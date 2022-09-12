#ifndef _DMA_C_
#define _DMA_C_

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

Peripheral dma0 = {
    .name = "DMA0",
    .address = 0x38200000,
    .size = 0x1000,
};

Peripheral dma1 = {
    .name = "DMA1",
    .address = 0x39900000,
    .size = 0x1000,
};

#endif