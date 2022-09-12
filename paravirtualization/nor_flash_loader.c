#ifndef _NOR_FLASH_LOADER_C_
#define _NOR_FLASH_LOADER_C_

#include <stdint.h>

#include <unicorn/unicorn.h>

#include "pv.h"
#include "../devices/nor_flash.c"

int nor_flash_loader_execute(uc_engine* uc) {
    uint32_t size; // r1
    uint32_t dest; // r2
    uint32_t src; // r3
    uc_reg_read(uc, UC_ARM_REG_R1, &size);
    uc_reg_read(uc, UC_ARM_REG_R2, &dest);
    uc_reg_read(uc, UC_ARM_REG_R3, &src);
    log_debug("NOR Flash Loader reading 0x%x bytes from 0x%x to 0x%x", size, src, dest);
    uc_mem_write(uc, dest, ((norflash_meta_t*)norboot.meta)->content + src, size);

    // uint32_t r0 = 4;
    uint32_t pc = 0x200090b0; //skip the function
    // uc_reg_write(uc, UC_ARM_REG_R0, &r0);
    uc_reg_read(uc, UC_ARM_REG_LR, &pc);
    uc_reg_write(uc, UC_ARM_REG_PC, &pc);
}

PV nor_flash_loader = {
    .name = "NOR Flash Loader",
    .hook_address = 0x2000906c,
    .execute = nor_flash_loader_execute
};

#endif