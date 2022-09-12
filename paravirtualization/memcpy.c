#ifndef _MEMCPY_C_
#define _MEMCPY_C_

#include <stdint.h>

#include <unicorn/unicorn.h>

#include "pv.h"

int memcpy_execute(uc_engine* uc, uint32_t address, uint32_t size, void* user_data) {
    PV *pv = (PV*)user_data;

    uint32_t dest; // r0
    uint32_t src; // r1
    uint32_t zsize; // r2
    uc_reg_read(uc, UC_ARM_REG_R0, &dest);
    uc_reg_read(uc, UC_ARM_REG_R1, &src);
    uc_reg_read(uc, UC_ARM_REG_R2, &zsize);
    log_debug("%s called for 0x%x bytes from 0x%08x to 0x%08x",pv->name, zsize, dest, src);

    void* memory = malloc(zsize);
    uc_mem_read(uc, src, memory, zsize);
    uc_mem_write(uc, dest, memory, zsize);
    free(memory);

    //skip the function
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_LR, &pc);
    uc_reg_write(uc, UC_ARM_REG_PC, &pc);
}

PV memcpy_stub0 = {
    .name = "efi dxemain memcpy",
    .hook_address = 0x9fc559e,
    .execute = memcpy_execute
};

#endif