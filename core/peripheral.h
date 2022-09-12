#include <stdint.h>
#include <unicorn/unicorn.h>

#ifndef _PERIPHERAL_H_
#define _PERIPHERAL_H_

typedef struct {
    char* name;
    uint32_t address;
    uint32_t size;
    void* memory;
    void* meta;
    int (*init)(uc_engine* uc, void* self);
    int (*destroy)(uc_engine* uc, void* self);
} Peripheral;

#endif