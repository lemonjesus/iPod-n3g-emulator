#ifndef __SHA1_H__
#define __SHA1_H__

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

typedef struct  {
    uint32_t SHA1CONFIG; // 0x00
    uint32_t SHA1RESET; // 0x04
    uint8_t _pad[0x20 - 0x8];
    uint32_t SHA1RESULT; // 0x20
    uint8_t _pad2[0x40 - 0x24];
    uint32_t SHA1DATAIN; // 0x40
} sha1_t;

Peripheral sha1 = {
    .name = "SHA1",
    .address = 0x38000000,
    .size = sizeof(sha1_t),
};

#endif