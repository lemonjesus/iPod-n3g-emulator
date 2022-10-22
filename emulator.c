#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <unicorn/unicorn.h>

#include "arguments.h"
#include "debugger.h"
#include "disassembler.h"
#include "log.h"

#include "core/peripheral.h"
#include "core/aes.c"
#include "core/chipid.c"
#include "core/dma.c"
#include "core/gpio.c"
#include "core/i2c.c"
#include "core/interrupt_controllers.c"
#include "core/miu.c"
#include "core/ram.c"
#include "core/sha1.c"
#include "core/spi.c"
#include "core/system_controller.c"
#include "core/timer.c"
#include "core/unknown.c"
#include "core/usb.c"
#include "core/watchdog.c"

#include "paravirtualization/pv.h"
#include "paravirtualization/delay.c"
#include "paravirtualization/memcpy.c"
#include "paravirtualization/memzero.c"
#include "paravirtualization/nor_flash_loader.c"

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

int main(int argc, char **argv) {
    uc_engine* uc;
    uc_err err;

    Arguments arguments;
    arguments.log_level = LOG_INFO;

    static struct argp argp = {options, parse_opt, NULL, doc};
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    log_set_level(arguments.log_level);

    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    if (err) {
        log_fatal("Failed on uc_open() with error returned: %u (%s)", err, uc_strerror(err));
        return -1;
    }

     // allocate 2mb of memory for this emulation
    void* memory = calloc(1, 2 * 1024 * 1024);

    FILE *f = fopen("s5l8702-bootrom.bin", "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    fread(memory, fsize, 1, f);
    fclose(f);

    // PATCHES
    // 1. do not verify the image header, just assume it's good to go (immediately return 1 from verify_img_header)
    ((uint32_t*)memory)[0x5dc/4] = 0xE3A00001;
    ((uint32_t*)memory)[0x5e0/4] = 0xE12FFF1E;
    
    // 2. do the same for verify_decrypt_image (it's already decrypted off of NOR)
    ((uint32_t*)memory)[0x6dc/4] = 0xE3A00001;
    ((uint32_t*)memory)[0x6e0/4] = 0xE12FFF1E;

    // 3. ignore other issues in the header format
    ((uint32_t*)memory)[0x3098/4] = 0xE320F000;

    // map the memory at 0x0
    err = uc_mem_map_ptr(uc, 0x0, 2 * 1024 * 1024, UC_PROT_ALL, memory);
    if (err) {
        log_fatal("Failed on uc_mem_map_ptr() with error returned: %u (%s)", err, uc_strerror(err));
        return -1;
    }

    // map the memory at 0x20000000
    err = uc_mem_map_ptr(uc, 0x20000000, 2 * 1024 * 1024, UC_PROT_ALL, memory);
    if (err) {
        log_fatal("Failed on uc_mem_map_ptr() with error returned: %u (%s)", err, uc_strerror(err));
        return -1;
    }

    debugger_init(uc);

    Peripheral peripherals[] = {
        aes,
        chipid,
        dma0, dma1,
        dram,
        gpio,
        i2c0, i2c1,
        interrupt_controller,
        iram,
        miu,
        otgphy,
        sha1,
        spi0, spi1, spi2,
        system_controller,
        timer,
        unknown1, unknown2,
        usb,
        watchdog
    };

    // initialize peripherals
    for (int i = 0; i < sizeof(peripherals) / sizeof(peripherals[0]); i++) {
        peripherals[i].memory = calloc(1, peripherals[i].size);

        err = uc_mem_map_ptr(uc, peripherals[i].address, ROUND_UP(peripherals[i].size, 4 * 1024), UC_PROT_ALL, peripherals[i].memory);
        if (err) {
            log_fatal("Failed on uc_mem_map_ptr() in peripheral %s with error returned: %u (%s)", peripherals[i].name, err, uc_strerror(err));
            return -1;
        }

        int result = 0;
        if(peripherals[i].init) result = peripherals[i].init(uc, &peripherals[i]);
        if(result) {
            log_fatal("Failed on peripheral %s with error returned: %d", peripherals[i].name, result);
            return -1;
        }

        log_info("Loaded %s at 0x%x", peripherals[i].name, peripherals[i].address);
    }

    // initialize paravirtualization
    PV paravirtualizers[] = {
        delay,
        memcpy_stub0,
        memzero_stub0, memzero_stub1,
        nor_flash_loader
    };

    for(int i = 0; i < sizeof(paravirtualizers) / sizeof(paravirtualizers[0]); i++) {
        err = uc_hook_add(uc, &paravirtualizers[i].hook, UC_HOOK_CODE, paravirtualizers[i].execute, &paravirtualizers[i], paravirtualizers[i].hook_address, paravirtualizers[i].hook_address);
        log_info("Loaded %s", paravirtualizers[i].name);
    }

    // start emulation at 0x0
    printf("Starting emulation\n");
    err = uc_emu_start(uc, 0x0, 0x40000000, 0, 0);
  
    if (err) {
        char* inst_dump = malloc(128);
        log_fatal("Failed on uc_emu_start() with error returned: %u (%s)", err, uc_strerror(err));
        uint32_t pc, instruction;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        disassemble(uc, pc, 4, inst_dump);
        uc_mem_read(uc, pc, &instruction, 4);
        log_fatal("PC = 0x%x, inst = %s (0x%8X)", pc, inst_dump, instruction);

        // read all registers and print them
        uint32_t registers[16];
        for (int i = 0; i < 16; i++) {
            uc_reg_read(uc, UC_ARM_REG_R0 + i, &registers[i]);
        }
        log_fatal("R0 = 0x%x, R1 = 0x%x, R2 = 0x%x, R3 = 0x%x, R4 = 0x%x, R5 = 0x%x, R6 = 0x%x, R7 = 0x%x, R8 = 0x%x, R9 = 0x%x, R10 = 0x%x, R11 = 0x%x, R12 = 0x%x, R13 = 0x%x, R14 = 0x%x, R15 = 0x%x", registers[0], registers[1], registers[2], registers[3], registers[4], registers[5], registers[6], registers[7], registers[8], registers[9], registers[10], registers[11], registers[12], registers[13], registers[14], registers[15]);

        return -1;
    }
}
