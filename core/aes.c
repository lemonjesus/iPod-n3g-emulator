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

static void aes_go(uc_engine* uc, uc_mem_type type, uint32_t address, int size, uint32_t value, void* user_data) {
    Peripheral* self = (Peripheral*)user_data;
    aes_t* aes = (aes_t*)self->memory;

    if(aes->AESGO == 1) {
        uint32_t pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        log_debug("AES GO @ PC = 0x%x", pc);
        log_debug("AESCONTROL: 0x%X, AESGO: 0x%X, AESUNKREG0: 0x%X, AESSTATUS: 0x%X, AESUNKREG1: 0x%X, AESKEYLEN: 0x%X, AESOUTSIZE: 0x%X, AESOUTADDR: 0x%X, AESINSIZE: 0x%X, AESINADDR: 0x%X, AESAUXSIZE: 0x%X, AESAUXADDR: 0x%X, AESSIZE3: 0x%X, AESTYPE: 0x%X, AESUNKREG2: 0x%X", aes->AESCONTROL, aes->AESGO, aes->AESUNKREG0, aes->AESSTATUS, aes->AESUNKREG1, aes->AESKEYLEN, aes->AESOUTSIZE, aes->AESOUTADDR, aes->AESINSIZE, aes->AESINADDR, aes->AESAUXSIZE, aes->AESAUXADDR, aes->AESSIZE3, aes->AESTYPE, aes->AESUNKREG2);

        uint8_t* in = malloc(aes->AESINSIZE);
        uc_err err = uc_mem_read(uc, aes->AESINADDR, in, aes->AESINSIZE);
        if(err != UC_ERR_OK) {
            log_error("Failed to read AES input data: %s", uc_strerror(err));
            return;
        }

        err = uc_mem_write(uc, aes->AESOUTADDR, in, aes->AESOUTSIZE);
        if(err != UC_ERR_OK) {
            log_error("Failed to write AES output data: %s", uc_strerror(err));
            return;
        }

        free(in);
    }
}

int aes_init(uc_engine* uc, void* data) {
    Peripheral* self = (Peripheral*)data;
    aes_t* aes = (aes_t*)self->memory;

    uc_hook aes_go_write_trace;
    uc_err err = uc_hook_add(uc, &aes_go_write_trace, UC_HOOK_MEM_WRITE, &aes_go, self, ((Peripheral*)self)->address + 0x04, ((Peripheral*)self)->address + 0x04);
    if (err) {
        log_error("AES driver failed to hook into AESGO reg: %u (%s)", err, uc_strerror(err));
        return -1;
    }

    aes->AESSTATUS = 0xf;
    return 0;
}

Peripheral aes = {
    .name = "AES",
    .address = 0x38c00000,
    .size = sizeof(aes_t),
    .init = aes_init
};

#endif