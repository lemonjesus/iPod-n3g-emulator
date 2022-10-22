#ifndef _DEBUGGER_H_
#define _DEBUGGER_H_

#include <unicorn/unicorn.h>

#include "arguments.h"

int debugger_init(uc_engine* uc, Arguments* args);
void hook_code(uc_engine* uc, uint32_t address, uint32_t size, void* user_data);
void debug(uc_engine* uc, uint32_t address, uint32_t size, void* user_data);

// defined in emulator.c, but needs to be accessable from here
void start_emulation(uc_engine* uc, uint32_t start, uint32_t count);

#endif