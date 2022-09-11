#ifndef __GPIO_H__
#define __GPIO_H__

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

typedef struct  {
    uint32_t PCON0; // 0x00
    uint32_t PDAT0; // 0x04
    uint8_t _pad[0x20 - 0x8];
    uint32_t PCON1; // 0x20
    uint32_t PDAT1; // 0x24
    uint8_t _pad2[0x40 - 0x28];
    uint32_t PCON2; // 0x40
    uint32_t PDAT2; // 0x44
    uint8_t _pad3[0x60 - 0x48];
    uint32_t PCON3; // 0x60
    uint32_t PDAT3; // 0x64
    uint8_t _pad4[0x80 - 0x68];
    uint32_t PCON4; // 0x80
    uint32_t PDAT4; // 0x84
    uint8_t _pad5[0xA0 - 0x88];
    uint32_t PCON5; // 0xA0
    uint32_t PDAT5; // 0xA4
    uint8_t _pad6[0xC0 - 0xA8];
    uint32_t PCON6; // 0xC0
    uint32_t PDAT6; // 0xC4
    uint8_t _pad7[0xE0 - 0xC8];
    uint32_t PCON7; // 0xE0
    uint32_t PDAT7; // 0xE4
    uint8_t _pad8[0x100 - 0xE8];
    uint32_t PCON8; // 0x100
    uint32_t PDAT8; // 0x104
    uint8_t _pad9[0x120 - 0x108];
    uint32_t PCON9; // 0x120
    uint32_t PDAT9; // 0x124
    uint8_t _pad10[0x140 - 0x128];
    uint32_t PCONA; // 0x140
    uint32_t PDATA; // 0x144
    uint8_t _pad11[0x160 - 0x148];
    uint32_t PCONB; // 0x160
    uint32_t PDATB; // 0x164
    uint8_t _pad12[0x180 - 0x168];
    uint32_t PCONC; // 0x180
    uint32_t PDATC; // 0x184
    uint8_t _pad13[0x1A0 - 0x188];
    uint32_t PCOND; // 0x1A0
    uint32_t PDATD; // 0x1A4
    uint8_t _pad14[0x1C0 - 0x1A8];
    uint32_t PCONE; // 0x1C0
    uint32_t PDATE; // 0x1C4
    uint8_t _pad15[0x1E0 - 0x1C8];
    uint32_t PCONF; // 0x1E0
    uint32_t PDATF; // 0x1E4
    uint8_t _pad16[0x200 - 0x1E8];
    uint32_t GPIOCMD; // 0x200
} gpio_t;

Peripheral gpio = {
    .name = "GPIO",
    .address = 0x3CF00000,
    .size = sizeof(gpio_t),
};

#endif