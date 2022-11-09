#ifndef _DEBUGGER_H_
#define _DEBUGGER_H_

#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include "arguments.h"

int debugger_init(uc_engine* uc, Arguments* args);
void hook_code(uc_engine* uc, uint32_t address, uint32_t size, void* user_data);
void debug(uc_engine* uc, uint32_t address, uint32_t size, void* user_data);

// defined in emulator.c, but needs to be accessable from here
int start_emulation(uc_engine* uc, uint32_t start, uint32_t count);

// debugger commands
int debug_help(uc_engine* uc, uint32_t address, uint32_t size, char** args, int argc);
int debug_quit(uc_engine* uc, uint32_t address, uint32_t size, char** args, int argc);
int debug_step(uc_engine* uc, uint32_t address, uint32_t size, char** args, int argc);
int debug_registers(uc_engine* uc, uint32_t address, uint32_t size, char** args, int argc);
int debug_disassemble(uc_engine* uc, uint32_t address, uint32_t size, char** args, int argc);
int debug_memory(uc_engine* uc, uint32_t address, uint32_t size, char** args, int argc);
int debug_break(uc_engine* uc, uint32_t address, uint32_t size, char** args, int argc);
int debug_rmbreak(uc_engine* uc, uint32_t address, uint32_t size, char** args, int argc);
int debug_log(uc_engine* uc, uint32_t address, uint32_t size, char** argv, int argc);

typedef struct debug_command {
    char* name;
    char* arguments;
    char abbreviation;
    int (*func)(uc_engine* uc, uint32_t address, uint32_t size, char** args, int argc);
    char* help;
} debug_command;

typedef struct name_map {
    unsigned int id;
    const char* name;
} name_map;

// mapping of arm registers to their names
static const name_map reg_name_maps2[] = {
	{ ARM_REG_APSR, "apsr"},
	{ ARM_REG_APSR_NZCV, "apsr_nzcv"},
	{ ARM_REG_CPSR, "cpsr"},
	{ ARM_REG_FPEXC, "fpexc"},
	{ ARM_REG_FPINST, "fpinst"},
	{ ARM_REG_FPSCR, "fpscr"},
	{ ARM_REG_FPSCR_NZCV, "fpscr_nzcv"},
	{ ARM_REG_FPSID, "fpsid"},
	{ ARM_REG_ITSTATE, "itstate"},
	{ ARM_REG_LR, "lr"},
	{ ARM_REG_PC, "pc"},
	{ ARM_REG_SP, "sp"},
	{ ARM_REG_SPSR, "spsr"},
	{ ARM_REG_D0, "d0"},
	{ ARM_REG_D1, "d1"},
	{ ARM_REG_D2, "d2"},
	{ ARM_REG_D3, "d3"},
	{ ARM_REG_D4, "d4"},
	{ ARM_REG_D5, "d5"},
	{ ARM_REG_D6, "d6"},
	{ ARM_REG_D7, "d7"},
	{ ARM_REG_D8, "d8"},
	{ ARM_REG_D9, "d9"},
	{ ARM_REG_D10, "d10"},
	{ ARM_REG_D11, "d11"},
	{ ARM_REG_D12, "d12"},
	{ ARM_REG_D13, "d13"},
	{ ARM_REG_D14, "d14"},
	{ ARM_REG_D15, "d15"},
	{ ARM_REG_D16, "d16"},
	{ ARM_REG_D17, "d17"},
	{ ARM_REG_D18, "d18"},
	{ ARM_REG_D19, "d19"},
	{ ARM_REG_D20, "d20"},
	{ ARM_REG_D21, "d21"},
	{ ARM_REG_D22, "d22"},
	{ ARM_REG_D23, "d23"},
	{ ARM_REG_D24, "d24"},
	{ ARM_REG_D25, "d25"},
	{ ARM_REG_D26, "d26"},
	{ ARM_REG_D27, "d27"},
	{ ARM_REG_D28, "d28"},
	{ ARM_REG_D29, "d29"},
	{ ARM_REG_D30, "d30"},
	{ ARM_REG_D31, "d31"},
	{ ARM_REG_FPINST2, "fpinst2"},
	{ ARM_REG_MVFR0, "mvfr0"},
	{ ARM_REG_MVFR1, "mvfr1"},
	{ ARM_REG_MVFR2, "mvfr2"},
	{ ARM_REG_Q0, "q0"},
	{ ARM_REG_Q1, "q1"},
	{ ARM_REG_Q2, "q2"},
	{ ARM_REG_Q3, "q3"},
	{ ARM_REG_Q4, "q4"},
	{ ARM_REG_Q5, "q5"},
	{ ARM_REG_Q6, "q6"},
	{ ARM_REG_Q7, "q7"},
	{ ARM_REG_Q8, "q8"},
	{ ARM_REG_Q9, "q9"},
	{ ARM_REG_Q10, "q10"},
	{ ARM_REG_Q11, "q11"},
	{ ARM_REG_Q12, "q12"},
	{ ARM_REG_Q13, "q13"},
	{ ARM_REG_Q14, "q14"},
	{ ARM_REG_Q15, "q15"},
	{ ARM_REG_R0, "r0"},
	{ ARM_REG_R1, "r1"},
	{ ARM_REG_R2, "r2"},
	{ ARM_REG_R3, "r3"},
	{ ARM_REG_R4, "r4"},
	{ ARM_REG_R5, "r5"},
	{ ARM_REG_R6, "r6"},
	{ ARM_REG_R7, "r7"},
	{ ARM_REG_R8, "r8"},
	{ ARM_REG_R9, "r9"},
	{ ARM_REG_R10, "r10"},
	{ ARM_REG_R11, "r11"},
	{ ARM_REG_R12, "r12"},
	{ ARM_REG_S0, "s0"},
	{ ARM_REG_S1, "s1"},
	{ ARM_REG_S2, "s2"},
	{ ARM_REG_S3, "s3"},
	{ ARM_REG_S4, "s4"},
	{ ARM_REG_S5, "s5"},
	{ ARM_REG_S6, "s6"},
	{ ARM_REG_S7, "s7"},
	{ ARM_REG_S8, "s8"},
	{ ARM_REG_S9, "s9"},
	{ ARM_REG_S10, "s10"},
	{ ARM_REG_S11, "s11"},
	{ ARM_REG_S12, "s12"},
	{ ARM_REG_S13, "s13"},
	{ ARM_REG_S14, "s14"},
	{ ARM_REG_S15, "s15"},
	{ ARM_REG_S16, "s16"},
	{ ARM_REG_S17, "s17"},
	{ ARM_REG_S18, "s18"},
	{ ARM_REG_S19, "s19"},
	{ ARM_REG_S20, "s20"},
	{ ARM_REG_S21, "s21"},
	{ ARM_REG_S22, "s22"},
	{ ARM_REG_S23, "s23"},
	{ ARM_REG_S24, "s24"},
	{ ARM_REG_S25, "s25"},
	{ ARM_REG_S26, "s26"},
	{ ARM_REG_S27, "s27"},
	{ ARM_REG_S28, "s28"},
	{ ARM_REG_S29, "s29"},
	{ ARM_REG_S30, "s30"},
	{ ARM_REG_S31, "s31"},
};

#endif