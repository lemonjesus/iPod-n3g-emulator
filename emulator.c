#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unicorn/unicorn.h>

#include "disassembler.h"
#include "log.h"

#include "core/peripheral.h"
#include "core/aes.c"
#include "core/chipid.c"
#include "core/interrupt_controllers.c"
#include "core/gpio.c"
#include "core/ram.c"
#include "core/sha1.c"
#include "core/spi.c"
#include "core/system_controller.c"
#include "core/unknown.c"
#include "core/usb.c"
#include "core/watchdog.c"

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

char* disasm_buffer = NULL;

static void hook_code(uc_engine* uc, uint32_t address, uint32_t size, void* user_data) {
  // get the instruction at this location
  disassemble(uc, address, size, disasm_buffer);
  // log_trace(">>> Tracing instruction at 0x%x instruction = %s", address, disasm_buffer);
}

int main(int argc, char **argv) {
  uc_engine *uc;
  uc_err err;

  // log_set_level(LOG_INFO);
  disasm_buffer = malloc(128);

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

  // hook code
  uc_hook trace1;
  err = uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code, NULL, 0, 0x40000000);

  Peripheral peripherals[] = {
    aes,
    chipid,
    dram,
    gpio,
    interrupt_controller,
    iram,
    sha1,
    spi0, spi1, spi2,
    system_controller,
    unknown1,
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

  // start emulation at 0x0
  err = uc_emu_start(uc, 0x0, 0x40000000, 0, 0);
  
  if (err) {
    log_fatal("Failed on uc_emu_start() with error returned: %u (%s)", err, uc_strerror(err));
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    disassemble(uc, pc, 4, disasm_buffer);
    log_fatal("PC = 0x%x, inst = %s", pc, disasm_buffer);

    // read all registers and print them
    uint32_t registers[16];
    for (int i = 0; i < 16; i++) {
      uc_reg_read(uc, UC_ARM_REG_R0 + i, &registers[i]);
    }
    log_fatal("R0 = 0x%x, R1 = 0x%x, R2 = 0x%x, R3 = 0x%x, R4 = 0x%x, R5 = 0x%x, R6 = 0x%x, R7 = 0x%x, R8 = 0x%x, R9 = 0x%x, R10 = 0x%x, R11 = 0x%x, R12 = 0x%x, R13 = 0x%x, R14 = 0x%x, R15 = 0x%x", registers[0], registers[1], registers[2], registers[3], registers[4], registers[5], registers[6], registers[7], registers[8], registers[9], registers[10], registers[11], registers[12], registers[13], registers[14], registers[15]);

    return -1;
  }
}