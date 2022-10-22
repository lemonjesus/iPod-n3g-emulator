#include <stdint.h>
#include <stdlib.h>

#include <unicorn/unicorn.h>

#include "arguments.h"
#include "debugger.h"
#include "disassembler.h"
#include "log.h"

char* disasm_buffer;
uc_hook instruction_trace;

uint32_t* breakpoints;
uint32_t breakpoint_count;

int debugger_init(uc_engine* uc, Arguments* args) {
    breakpoints = args->breakpoints;
    breakpoint_count = args->breakpoint_count;

    disasm_buffer = malloc(128);

    uc_err err = uc_hook_add(uc, &instruction_trace, UC_HOOK_CODE, hook_code, NULL, 0, 0x40000000);

    if (err) {
        log_error("Failed to init the debugger: on uc_hook_add() with error returned: %u (%s)", err, uc_strerror(err));
        return -1;
    }

    log_info("Loaded the Debugger");
}

void hook_code(uc_engine* uc, uint32_t address, uint32_t size, void* user_data) {
    disassemble(uc, address, size, disasm_buffer);
    uint32_t instruction = 0;
    uc_mem_read(uc, address, &instruction, size);
    log_trace(">>> Tracing instruction at 0x%x instruction = %s (0x%08X)", address, disasm_buffer, instruction);
    if(address == 0x200006d0) {
        log_error("verify_img_header has failed!");
        exit(1);
    }

    if(address == 0x20003758) {
        log_error("something has failed and the iPod is waiting in a USB DFU loop! Exiting.");
        exit(1);
    }

    if(address == 0x200034a0) {
        log_info("entering the EFI!");
    }

    if(address == 0x9ef133a) {
        uint32_t r1;
        uc_reg_read(uc, UC_ARM_REG_R1, &r1);
        log_trace("r1 = 0x%x", r1);
    }

    if(address == 0x9ee0306) {
        uint32_t sysconfig;
        log_set_level(LOG_TRACE);
        uc_reg_read(uc, UC_ARM_REG_R0, &sysconfig);
        log_trace("sysconfig = 0x%x", sysconfig);
    }

    if(address == 0x9ee025c) {
        uint32_t r0;
        uc_reg_read(uc, UC_ARM_REG_R0, &r0);
        log_info("system memory size returning r0 = 0x%x", r0);
    }

    if(address == 0x9ee0402) {
        uint32_t r0, r6;
        uc_reg_read(uc, UC_ARM_REG_R0, &r0);
        uc_reg_read(uc, UC_ARM_REG_R6, &r6);
        log_info("r0 = 0x%x r6 = 0x%x", r0, r6);
    }

    for(int i = 0; i < breakpoint_count; i++) {
        if(address == breakpoints[i]) {
            uc_emu_stop(uc);
            log_debug("Hit Breakpoint %d", i);
        }
    }
}