#ifndef __UNKNOWN_H__
#define __UNKNOWN_H__

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

Peripheral unknown1 = {
    .name = "Unknown Peripheral 1",
    .address = 0x39A00000,
    .size = 4*1024,
};

#endif