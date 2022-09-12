#ifndef _TIMER_C_
#define _TIMER_C_

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

typedef struct  {
    uint32_t TACON; // 0x00
    uint32_t TACMD; // 0x04
    uint32_t TADATA0; // 0x08
    uint32_t TADATA1; // 0x0C
    uint32_t TAPRE; // 0x10
    uint32_t TACNT; // 0x14
    uint32_t TBCON; // 0x20
    uint32_t TBCMD; // 0x24
    uint32_t TBDATA0; // 0x28
    uint32_t TBDATA1; // 0x2C
    uint32_t TBPRE; // 0x30
    uint32_t TBCNT; // 0x34
    uint32_t TCCON; // 0x40
    uint32_t TCCMD; // 0x44
    uint32_t TCDATA0; // 0x48
    uint32_t TCDATA1; // 0x4C
    uint32_t TCPRE; // 0x50
    uint32_t TCCNT; // 0x54
    uint32_t TDCON; // 0x60
    uint32_t TDCMD; // 0x64
    uint32_t TDDATA0; // 0x68
    uint32_t TDDATA1; // 0x6C
    uint32_t TDPRE; // 0x70
    uint32_t TDCNT; // 0x74
    uint8_t _pad[0xA0 - 0x78];
    uint32_t TECON; // 0xA0
    uint32_t TECMD; // 0xA4
    uint32_t TEDATA0; // 0xA8
    uint32_t TEDATA1; // 0xAC
    uint32_t TEPRE; // 0xB0
    uint32_t TECNT; // 0xB4
    uint32_t TFCON; // 0xC0
    uint32_t TFCMD; // 0xC4
    uint32_t TFDATA0; // 0xC8
    uint32_t TFDATA1; // 0xCC
    uint32_t TFPRE; // 0xD0
    uint32_t TFCNT; // 0xD4
    uint32_t TGCON; // 0xE0
    uint32_t TGCMD; // 0xE4
    uint32_t TGDATA0; // 0xE8
    uint32_t TGDATA1; // 0xEC
    uint32_t TGPRE; // 0xF0
    uint32_t TGCNT; // 0xF4
    uint32_t THCON; // 0x100
    uint32_t THCMD; // 0x104
    uint32_t THDATA0; // 0x108
    uint32_t THDATA1; // 0x10C
    uint32_t THPRE; // 0x110
    uint32_t THCNT; // 0x114
    uint32_t TSTAT; // 0x118
} ipod_timer_t;

Peripheral timer = {
    .name = "Timers",
    .address = 0x3C700000,
    .size = sizeof(ipod_timer_t),
};

#endif