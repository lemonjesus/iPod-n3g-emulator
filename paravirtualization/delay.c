#ifndef _DELAY_C_
#define _DELAY_C_

#include <stdint.h>

#include <unicorn/unicorn.h>

#include "pv.h"

int delay_execute(uc_engine* uc, uint32_t address, uint32_t size, void* user_data) {
    uint32_t ticks; // r0
    uc_reg_read(uc, UC_ARM_REG_R0, &ticks);
    log_debug("Delay called for %d ticks", ticks);

    //skip the function
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_LR, &pc);
    uc_reg_write(uc, UC_ARM_REG_PC, &pc);
}

PV delay = {
    .name = "Delay",
    .hook_address = 0x2200eae6,
    .execute = delay_execute
};

#endif