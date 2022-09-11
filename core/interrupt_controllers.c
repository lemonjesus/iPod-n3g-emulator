// Interupt controllers of the S5L8702

#ifndef __INTERRUPT_CONTROLLERS_H__
#define __INTERRUPT_CONTROLLERS_H__

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

typedef struct {
    uint32_t vicirqstatus; // 0x00
    uint32_t vicfiqstatus; // 0x04
    uint32_t vicrawintr; // 0x08
    uint32_t vicintselect; // 0x0C
    uint32_t vicintenable; // 0x10
    uint32_t vicintenclear; // 0x14
    uint32_t vicsoftint; // 0x18
    uint32_t vicsoftintclear; // 0x1C
    uint32_t vicprotection; // 0x20
    uint32_t vicswprioritymask; // 0x24
    uint32_t vicprioritydaisy; // 0x28

    uint8_t _pad[0x100 - 11 * 4];
    uint32_t vicvectaddr[32]; // 0x100

    uint8_t _pad2[0x200 - 32 * 4 - 0x100];
    uint32_t vicvecpriority[32]; // 0x200

    uint8_t _pad3[0xF00 - 32 * 4 - 0x200];
    uint32_t vicaddress; // 0xF00
} vic;

typedef struct {
    vic vic1;
    uint8_t _pad[0x1000 - sizeof(vic)];
    vic vic2;
    uint8_t _pad2[0x1000 - sizeof(vic)];
    uint32_t vic0edge0; // 0x2000
    uint32_t vic1edge0; // 0x2004
    uint32_t vic0edge1; // 0x2008
    uint32_t vic1edge1; // 0x200C
} interrupt_controller_t;

Peripheral interrupt_controller = {
    .name = "Interrupt Controller",
    .address = 0x38E00000,
    .size = sizeof(interrupt_controller_t),
};

#endif