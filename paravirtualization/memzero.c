#ifndef _MEMZERO_C_
#define _MEMZERO_C_

#include <stdint.h>

#include <unicorn/unicorn.h>

#include "pv.h"

int memzero_execute(uc_engine* uc, uint32_t address, uint32_t size, void* user_data) {
    PV *pv = (PV*)user_data;

    uint32_t zaddress; // r0
    uint32_t zsize; // r1
    uc_reg_read(uc, UC_ARM_REG_R0, &zaddress);
    uc_reg_read(uc, UC_ARM_REG_R1, &zsize);
    log_debug("%s called for 0x%x bytes at 0x%08x",pv->name, zsize, zaddress);

    void* memory = calloc(1, zsize);
    uc_mem_write(uc, zaddress, memory, zsize);
    free(memory);

    //skip the function
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_LR, &pc);
    uc_reg_write(uc, UC_ARM_REG_PC, &pc);
}

PV memzero_stub0 = {
    .name = "bootloader memzero",
    .hook_address = 0x2200fa8c,
    .execute = memzero_execute
};

PV memzero_stub1 = {
    .name = "efi dxemain memzero",
    .hook_address = 0x9fc55de,
    .execute = memzero_execute
};

#endif