#ifndef _I2C_C_
#define _I2C_C_

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

#define IICCON(bus)     (*((uint32_t volatile*)(0x3C600000 + 0x300000 * (bus))))
#define IICSTAT(bus)    (*((uint32_t volatile*)(0x3C600004 + 0x300000 * (bus))))
#define IICADD(bus)     (*((uint32_t volatile*)(0x3C600008 + 0x300000 * (bus))))
#define IICDS(bus)      (*((uint32_t volatile*)(0x3C60000C + 0x300000 * (bus))))
#define IICUNK10(bus)   (*((uint32_t volatile*)(0x3C600010 + 0x300000 * (bus))))
#define IICUNK14(bus)   (*((uint32_t volatile*)(0x3C600014 + 0x300000 * (bus))))
#define IICUNK18(bus)   (*((uint32_t volatile*)(0x3C600018 + 0x300000 * (bus))))
#define IICSTA2(bus)    (*((uint32_t volatile*)(0x3C600020 + 0x300000 * (bus))))
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

Peripheral i2c0 = {
    .name = "I2C 0",
    .address = 0x3C600000,
    .size = sizeof(i2c_t),
};

Peripheral i2c1 = {
    .name = "I2C 1",
    .address = 0x3C900000,
    .size = sizeof(i2c_t),
};

#endif