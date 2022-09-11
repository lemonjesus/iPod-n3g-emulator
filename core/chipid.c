#ifndef __CHIPID_H__
#define __CHIPID_H__

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

typedef struct  {
    uint32_t CHIPID_BASE; // 0x00
} chipid_t;

Peripheral chipid = {
    .name = "Chip ID",
    .address = 0x3d100000,
    .size = sizeof(chipid_t),
};

#endif