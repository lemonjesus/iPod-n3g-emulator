#ifndef _NOR_FLASH_LOADER_C_
#define _NOR_FLASH_LOADER_C_

#include <stdint.h>

#include <unicorn/unicorn.h>

#include "pv.h"
#include "../devices/nor_flash.c"

int bootrom_nor_flash_loader_execute(uc_engine* uc, uint32_t _address, uint32_t _size, void* _user_data) {
    uint32_t size; // r1
    uint32_t dest; // r2
    uint32_t src; // r3
    uc_reg_read(uc, UC_ARM_REG_R1, &size);
    uc_reg_read(uc, UC_ARM_REG_R2, &dest);
    uc_reg_read(uc, UC_ARM_REG_R3, &src);

    log_debug("NOR Flash Loader reading 0x%x bytes from 0x%x to 0x%x", size, src, dest);
    uc_mem_write(uc, dest, ((norflash_meta_t*)norboot.meta)->content + src, size);

    //skip the function
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_LR, &pc);
    uc_reg_write(uc, UC_ARM_REG_PC, &pc);
}

// TODO: this one is a little suspect. It works... technically... but I'm not sure if it's correct. My guess is that when
//       it tries to start loading JPEGs it'll break. I'm not sure why it's broken. When loading the system configurations
//       it loads the first 0x18 bytes (which defines the signature and size) and then it knows to load size - 0x18 bytes
//       but it doesn't specify an offset of 0x18, so it starts from 0x0 and doesn't load the entire sysconfig.
int efi_nor_flash_loader_execute(uc_engine* uc, uint32_t _address, uint32_t _size, void* _user_data) {
    uint32_t src; // r1
    uint32_t dest; // r2
    uint32_t size; // r3
    uc_reg_read(uc, UC_ARM_REG_R1, &src);
    uc_reg_read(uc, UC_ARM_REG_R2, &dest);
    uc_reg_read(uc, UC_ARM_REG_R3, &size);

    log_debug("NOR Flash Loader reading 0x%x bytes from 0x%x to 0x%x", size, src, dest);
    uc_mem_write(uc, dest, ((norflash_meta_t*)norboot.meta)->content + src, size);

    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_LR, &pc);
    uc_reg_write(uc, UC_ARM_REG_PC, &pc);
}

PV bootrom_nor_flash_loader = {
    .name = "Bootrom NOR Flash Loader",
    .hook_address = 0x2000906c,
    .execute = bootrom_nor_flash_loader_execute
};

PV efi_nor_flash_loader = {
    .name = "EFI NOR Flash Loader",
    .hook_address = 0x9ef12b2,
    .execute = efi_nor_flash_loader_execute
};

#endif