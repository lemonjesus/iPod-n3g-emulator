#ifndef _MIU_C_
#define _MIU_C_

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

typedef struct {
    uint32_t MIUCON; // 0x00
    uint32_t MIUCOM; // 0x04
    uint32_t MIUAREF; // 0x08
    uint32_t MIUMRS; // 0x0C
    uint32_t MIUSDPARA; // 0x10
} miu_t;

Peripheral miu = {
    .name = "Memory Interface Unit",
    .address = 0x38100000,
    .size = sizeof(miu_t),
};

#endif