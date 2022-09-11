#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

typedef struct  {
    uint32_t AESCONTROL; // 0x00
    uint32_t AESGO; // 0x04
    uint32_t AESUNKREG0; // 0x08
    uint32_t AESSTATUS; // 0x0C
    uint32_t AESUNKREG1; // 0x10
    uint32_t AESKEYLEN; // 0x14
    uint32_t AESOUTSIZE; // 0x18
    uint32_t _pad; // 0x1C
    uint32_t AESOUTADDR; // 0x20
    uint32_t AESINSIZE; // 0x24
    uint32_t AESINADDR; // 0x28
    uint32_t AESAUXSIZE; // 0x2C
    uint32_t AESAUXADDR; // 0x30
    uint32_t AESSIZE3; // 0x34
    uint8_t _pad1[0x4c - 0x38];
    uint8_t AESKEY[0x6c - 0x4c]; // 0x4c
    uint32_t AESTYPE; // 0x6c
    uint32_t _pad2;
    uint8_t AESIV[0x88 - 0x74]; // 0x74
    uint32_t AESTYPE2; // 0x88
    uint32_t AESUNKREG2; // 0x8C
} aes_t;

Peripheral aes = {
    .name = "AES",
    .address = 0x38c00000,
    .size = sizeof(aes_t),
};

#endif