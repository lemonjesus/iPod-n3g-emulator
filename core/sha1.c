#ifndef __SHA1_H__
#define __SHA1_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "peripheral.h"

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00)|(rol(block->l[i],8)&0x00FF00FF))
#elif BYTE_ORDER == BIG_ENDIAN
#define blk0(i) block->l[i]
#else
#error "Endianness not defined!"
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


void SHA1Transform(uint32_t state[5], const unsigned char buffer[64]) {
    uint32_t a, b, c, d, e;

    typedef union {
        unsigned char c[64];
        uint32_t l[16];
    } CHAR64LONG16;
    
    CHAR64LONG16 block[1];      /* use array to appear as a pointer */

    memcpy(block, buffer, 64);
    
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a, b, c, d, e, 0);
    R0(e, a, b, c, d, 1);
    R0(d, e, a, b, c, 2);
    R0(c, d, e, a, b, 3);
    R0(b, c, d, e, a, 4);
    R0(a, b, c, d, e, 5);
    R0(e, a, b, c, d, 6);
    R0(d, e, a, b, c, 7);
    R0(c, d, e, a, b, 8);
    R0(b, c, d, e, a, 9);
    R0(a, b, c, d, e, 10);
    R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12);
    R0(c, d, e, a, b, 13);
    R0(b, c, d, e, a, 14);
    R0(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);
    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);
    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);
    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
    memset(block, '\0', sizeof(block));
}

void SHA1Init(SHA1_CTX * context) {
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

void SHA1Update(SHA1_CTX * context, const unsigned char *data, uint32_t len) {
    uint32_t i, j;

    j = context->count[0];
    if ((context->count[0] += len << 3) < j) context->count[1]++;
    context->count[1] += (len >> 29);
    j = (j >> 3) & 63;
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    } else
        i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}

void SHA1Final(unsigned char digest[20], SHA1_CTX * context) {
    unsigned i;
    unsigned char finalcount[8];
    unsigned char c;

    for (i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char) ((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    }
    c = 0200;
    SHA1Update(context, &c, 1);
    while ((context->count[0] & 504) != 448) {
        c = 0000;
        SHA1Update(context, &c, 1);
    }
    SHA1Update(context, finalcount, 8); /* Should cause a SHA1Transform() */
    for (i = 0; i < 20; i++) {
        digest[i] = (unsigned char)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
    /* Wipe variables */
    memset(context, '\0', sizeof(*context));
    memset(&finalcount, '\0', sizeof(finalcount));
}

typedef struct  {
    uint32_t SHA1CONFIG; // 0x00
    uint32_t SHA1RESET; // 0x04
    uint8_t _pad[0x20 - 0x8];
    uint32_t SHA1RESULT[5]; // 0x20
    uint8_t _pad2[0x40 - 0x34];
    uint32_t SHA1DATAIN[16]; // 0x40
} sha1_t;

typedef struct {
    SHA1_CTX ctx;
} sha1_meta_t;

static void sha1_config(uc_engine* uc, uc_mem_type type, uint32_t address, int size, uint32_t value, void* user_data) {
    Peripheral* self = (Peripheral*)user_data;
    sha1_t* sha1 = (sha1_t*)self->memory;
    sha1_meta_t* meta = (sha1_meta_t*)self->meta;

    if (value & 2) {
        SHA1Update(&meta->ctx, sha1->SHA1DATAIN, 64);
        sha1->SHA1CONFIG = 0;
    }

    if (value & 8) {
        SHA1Final((uint8_t*)sha1->SHA1RESULT, &meta->ctx);
        sha1->SHA1CONFIG = 0;
    }
}

static void sha1_reset(uc_engine* uc, uc_mem_type type, uint32_t address, int size, uint32_t value, void* user_data) {
    Peripheral* self = (Peripheral*)user_data;
    sha1_t* sha1 = (sha1_t*)self->memory;
    sha1_meta_t* meta = (sha1_meta_t*)self->meta;
    
    if(value == 0x1) {
        log_debug("SHA1: Resetting");
        sha1->SHA1CONFIG = 0x0;
        sha1->SHA1RESET = 0x0;
        SHA1Init(&meta->ctx);
    }
}

int sha1_init(uc_engine* uc, void* data) {
    Peripheral* self = (Peripheral*)data;
    sha1_t* sha1 = (sha1_t*)self->memory;

    self->meta = malloc(sizeof(sha1_meta_t));

    uc_hook sha1_config_trace;
    uc_err err = uc_hook_add(uc, &sha1_config_trace, UC_HOOK_MEM_WRITE, &sha1_config, self, ((Peripheral*)self)->address, ((Peripheral*)self)->address);
    if (err) {
        log_error("SHA1 driver failed to hook into SHA1CONFIG reg: %u (%s)", err, uc_strerror(err));
        return -1;
    }
    
    uc_hook sha1_reset_trace;
    err = uc_hook_add(uc, &sha1_reset_trace, UC_HOOK_MEM_WRITE, &sha1_reset, self, ((Peripheral*)self)->address + 0x04, ((Peripheral*)self)->address + 0x04);
    if (err) {
        log_error("SHA1 driver failed to hook into SHA1RESET reg: %u (%s)", err, uc_strerror(err));
        return -1;
    }

    return 0;
}

Peripheral sha1 = {
    .name = "SHA1",
    .address = 0x38000000,
    .size = sizeof(sha1_t),
    .init = sha1_init
};

#endif