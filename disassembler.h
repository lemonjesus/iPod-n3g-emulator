#ifndef _DISASSEMBLER_H_
#define _DISASSEMBLER_H_

#include <stdint.h>
#include <unicorn/unicorn.h>

void disassemble(uc_engine* uc, uint32_t addr, uint32_t size, char* out);

#endif