#ifndef __SYSTEM_CONTROLLER_H__
#define __SYSTEM_CONTROLLER_H__

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

typedef struct  {
    uint32_t CLKCON0; // 0x00
    uint32_t CLKCON1; // 0x04
    uint32_t CLKCON2; // 0x08
    uint32_t CLKCON3; // 0x0C
    uint32_t CLKCON4; // 0x10
    uint32_t CLKCON5; // 0x14
    uint32_t CLKCON6; // 0x18 (unsure if this exists)
    uint32_t PLL0PMS; // 0x20
    uint32_t PLL1PMS; // 0x24
    uint32_t PLL2PMS; // 0x28
    uint32_t PLL3PMS; // 0x2C (unsure if this exists)
    uint32_t PLL0LCNT; // 0x30
    uint32_t PLL1LCNT; // 0x34
    uint32_t PLL2LCNT; // 0x38
    uint32_t PLL3LCNT; // 0x3C (unsure if this exists)
    uint32_t PLLLOCK; // 0x40
    uint32_t PLLMODE; // 0x44
    uint32_t PWRCON0; // 0x48
    uint32_t PWRCON1; // 0x4C
    uint32_t SWRCON; // 0x50
    uint32_t RSTSR; // 0x54
    uint32_t PWRCON2; // 0x58
    uint8_t _pad[0x68 - 0x5C];
    uint32_t PWRCON3; // 0x68
    uint32_t PWRCON4; // 0x6C
} system_controller_t;

static void pll_lock(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
    uint32_t pll_locked = 1;
    uc_mem_write(uc, 0x3C500040, &pll_locked, sizeof(uint32_t));
}

int system_controller_init(uc_engine* uc, void* self) {
    uc_hook trace1;
    uc_err err = uc_hook_add(uc, &trace1, UC_HOOK_MEM_WRITE, &pll_lock, self, 0x3C500020, 0x3C500024);
    if (err) {
        log_error("Failed on hook_code() with error returned: %u (%s)", err, uc_strerror(err));
        return -1;
    }
}

Peripheral system_controller = {
    .name = "System Controller",
    .address = 0x3C500000,
    .size = sizeof(system_controller_t),
    .init = system_controller_init
};

#endif