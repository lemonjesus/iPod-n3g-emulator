#ifndef _WATCHDOG_C_
#define _WATCHDOG_C_

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

typedef struct  {
    uint32_t vicirqstatus; // 0x00
    uint32_t vicfiqstatus; // 0x04
} watchdog_t;

Peripheral watchdog = {
    .name = "Watchdog",
    .address = 0x3C800000,
    .size = sizeof(watchdog_t),
};

#endif