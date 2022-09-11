#ifndef __DISASSEMBLER_H__
#define __DISASSEMBLER_H__

#include <stdint.h>
#include <unicorn/unicorn.h>

void disassemble(uc_engine* uc, uint32_t addr, uint32_t size, char* out);

#endif