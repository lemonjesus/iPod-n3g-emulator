#ifndef __RAM_H__
#define __RAM_H__

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

Peripheral dram = {
    .name = "DRAM",
    .address = 0x08000000,
    .size = 0x100000 * 32,
};

Peripheral iram = {
    .name = "IRAM",
    .address = 0x22000000,
    .size = 0x20000 * 2,
};

#endif