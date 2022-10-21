#ifndef _RAM_C_
#define _RAM_C_

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

Peripheral dram = {
    .name = "DRAM",
    .address = 0x08000000,
    .size = 0x100000 * 64,
};

Peripheral iram = {
    .name = "IRAM",
    .address = 0x22000000,
    .size = 0x200000 * 2,
};

#endif