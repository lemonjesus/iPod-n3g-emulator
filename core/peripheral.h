#include <stdint.h>
#include <unicorn/unicorn.h>

#ifndef __PERIPHERAL_H__
#define __PERIPHERAL_H__

typedef int (*InitCallback)(uc_engine* uc, void* self);
typedef int (*DestroyCallback)(uc_engine* uc, void* self);

typedef struct {
    char* name;
    uint32_t address;
    uint32_t size;
    void* memory;
    void* meta;
    InitCallback init;
    DestroyCallback destroy;
} Peripheral;

#endif