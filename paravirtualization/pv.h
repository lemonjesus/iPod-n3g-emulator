#ifndef _PV_H_
#define _PV_H_

#include <unicorn/unicorn.h>
#include <stdint.h>

typedef struct {
    char* name;
    uc_hook hook;
    uint32_t hook_address;
    void (*execute)(uc_engine* uc, uint32_t address, uint32_t size, void* user_data);
} PV;

#endif