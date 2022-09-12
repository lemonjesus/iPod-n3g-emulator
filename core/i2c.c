#ifndef _I2C_C_
#define _I2C_C_

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

typedef struct  {
    uint32_t IICCON; // 0x00
    uint32_t IICSTAT; // 0x04
    uint32_t IICADD; // 0x08
    uint32_t IICDS; // 0x0C
    uint32_t IICUNK10; // 0x10
    uint32_t IICUNK14; // 0x14
    uint32_t IICUNK18; // 0x18
    uint8_t _pad[0x20 - 0x1C];
    uint32_t IICSTA2; // 0x20
} i2c_t;

int i2c_init(uc_engine* uc, void* data) {
    Peripheral* self = (Peripheral*)data;
    i2c_t* i2c = (i2c_t*)self->memory;

    i2c->IICSTAT = -1;
    i2c->IICSTA2 = -1;

    return 0;
}

Peripheral i2c0 = {
    .name = "I2C 0",
    .address = 0x3C600000,
    .size = sizeof(i2c_t),
    .init = i2c_init
};

Peripheral i2c1 = {
    .name = "I2C 1",
    .address = 0x3C900000,
    .size = sizeof(i2c_t),
    .init = i2c_init
};

#endif