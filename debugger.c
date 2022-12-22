#include <stdint.h>
#include <stdlib.h>

#include <readline/readline.h>
#include <readline/history.h>
#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include "arguments.h"
#include "debugger.h"
#include "disassembler.h"
#include "log.h"

char* disasm_buffer;
uc_hook instruction_trace;

Arguments* args;
int orig_log_level;

uint32_t call_stack[512];
uint16_t call_depth = 0;

extern int keepRunning;

int debugger_init(uc_engine* uc, Arguments* a) {
    args = a;
    disasm_buffer = malloc(128);

    uc_err err = uc_hook_add(uc, &instruction_trace, UC_HOOK_CODE, hook_code, NULL, 0, 0x40000000);

    if (err) {
        log_error("Failed to init the debugger: on uc_hook_add() with error returned: %u (%s)", err, uc_strerror(err));
        return -1;
    }

    log_info("Loaded the Debugger");
}

marker known_markers[] = {
    {0x200006d0, LOG_FATAL, "verify_img_failer has failed!"},
    {0x20003758, LOG_FATAL, "something has failed and the iPod is waiting in a USB DFU loop! Exiting."},
    {0x200034a0, LOG_INFO, "entering the EFI!"}
};

void hook_code(uc_engine* uc, uint32_t address, uint32_t size, void* user_data) {
    disasm_buffer[0] = '\0';
    disassemble(uc, address, size, disasm_buffer);
    uint32_t cpsr, instruction = 0;
    uc_mem_read(uc, address, &instruction, size);
    uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr);
    log_trace(">>> Tracing %s instruction at 0x%x instruction = %s (0x%08X)",(cpsr & 0x20) ? "THUMB" : "ARM", address, disasm_buffer, instruction);
    
    // check markers
    for(int i = 0; i < sizeof(known_markers)/sizeof(marker); i++) {
        if(known_markers[i].address == address) {
            log_log(known_markers[i].level, __FILE__, __LINE__, known_markers[i].message);
            if(known_markers[i].level == LOG_FATAL) exit(1);
            break;
        }
    }

    if(address == 0x9ef133a) {
        uint32_t r1;
        uc_reg_read(uc, UC_ARM_REG_R1, &r1);
        log_trace("r1 = 0x%x", r1);
    }

    if(address == 0x9fc34d8) {
        log_set_level(LOG_TRACE);
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

    if(keepRunning == 0) {
        uc_emu_stop(uc);
        log_info("Stopping the emulation");
        debug(uc, address, size, user_data);
    }

    if(address == args->trace_from) {
        orig_log_level = log_get_level();
        log_set_level(LOG_TRACE);
    }

    if(address == args->trace_to) {
        log_set_level(orig_log_level);
    }

    for(int i = 0; i < args->breakpoint_count; i++) {
        if(address == args->breakpoints[i]) {
            uc_emu_stop(uc);
            log_debug("Hit Breakpoint %d", i);
            debug(uc, address, size, user_data);
            break;
        }
    }
}

uint8_t debugging = 0;

debug_command commands[] = {
    {"help", "", 'h', debug_help, "Prints this help message"},
    {"quit", "", 'q', debug_quit, "Quits the debugger"},
    {"continue", "", 'c', debug_quit, "Continues execution"},
    {"step", "", 's', debug_step, "Steps to the next instruction"},
    {"break", "<address>", 'b', debug_break, "Sets a breakpoint at the specified address"},
    {"rmbreak", "<address>", 'x', debug_rmbreak, "Removes a breakpoint at the specified address"},
    {"disassemble", "<address> [count=16]", 'd', debug_disassemble, "Disassembles <count> instructions starting at <address>"},
    {"registers", "", 'r', debug_registers, "Dumps the current register values"},
    {"memory", "<address|register> [count=128]", 'm', debug_memory, "Prints <count> bytes of memory starting at <address> (or the pointer in <register>)"},
    // {"write", "<address> <value>", 'w', debug_write, "Writes <value> to <address>"},
    // {"read", "<address>", 'r', debug_read, "Reads the value at <address>"},
    // {"trace", "", 't', debug_trace, "Toggles instruction tracing"},
    {"log", "<level>", 'l', debug_log, "Sets the log level to <level>"},
};

uc_arm_reg reg_name_to_id(char* regname) {
    // loop through reg_names_maps2 and find the regname (and return the id because it's the same in Unicorn)
    for(int i = 0; i < sizeof(reg_name_maps2) / sizeof(reg_name_maps2[0]); i++) {
        if(strcmp(regname, reg_name_maps2[i].name) == 0) {
            return reg_name_maps2[i].id;
        }
    }
}

char* printable_memdump(uint8_t* buffer, int offset, char* out) {
    for(int i = 0; i < 16; i++) {
        out[i] = isprint(buffer[i + offset]) ? buffer[i + offset] : '.';
    }
    out[16] = 0;
    return out;
}

int debug_help(uc_engine* uc, uint32_t address, uint32_t size, char** args, int argc) {
    printf("Commands:\n");
    for(int i = 0; i < sizeof(commands) / sizeof(debug_command); i++) {
        printf("\t(%c) %s %s - %s\n", commands[i].abbreviation, commands[i].name, commands[i].arguments, commands[i].help);
    }
    return 0;
}

int debug_quit(uc_engine* uc, uint32_t address, uint32_t size, char** args, int argc) {
    return -1;
}

int debug_step(uc_engine* uc, uint32_t address, uint32_t size, char** args, int argc) {
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    start_emulation(uc, pc + size, 1);
    return 0;
}

int debug_memory(uc_engine* uc, uint32_t address, uint32_t size, char** args, int argc) {
    if(argc < 1) {
        printf("Usage: memory <address|register> [count=128]\n");
        return 0;
    }

    uint32_t addr = 0;
    if(args[0][0] == '0' && args[0][1] == 'x') {
        addr = strtol(args[0], NULL, 16);
    } else {
        uc_arm_reg reg = reg_name_to_id(args[0]);
        if(reg != UC_ARM_REG_INVALID) {
            uc_reg_read(uc, reg, &addr);
        } else {
            printf("Invalid address or register: %s\n", args[1]);
            return 0;
        }
    }

    int count = 128;
    if(argc > 1) {
        count = strtol(args[1], NULL, 10);
        count = ((count + 15) / 16) * 16;
    }

    uint8_t* buffer = calloc(1, count);

    uc_err err = uc_mem_read(uc, addr, buffer, count);
    char out[17];
    for(int i = 0; i < count/16; i++) {
        printf("0x%08X | %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X | %s\n", addr + i*16,
            buffer[0+i*16], buffer[1+i*16], buffer[2+i*16], buffer[3+i*16], buffer[4+i*16], buffer[5+i*16], buffer[6+i*16], buffer[7+i*16],
            buffer[8+i*16], buffer[9+i*16], buffer[10+i*16], buffer[11+i*16], buffer[12+i*16], buffer[13+i*16], buffer[14+i*16], buffer[15+i*16],
            printable_memdump(buffer, i*16, out));
    }

    free(buffer);
    return 0;
}

int debug_registers(uc_engine* uc, uint32_t address, uint32_t size, char** args, int argc) {
    uint32_t pc, instruction, cpsr;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr);
    disassemble(uc, pc, size, disasm_buffer);
    uc_mem_read(uc, pc, &instruction, size);
    printf("PC = 0x%x, inst = %s (0x%8X)\n", pc, disasm_buffer, instruction);
    printf("CSPR = 0x%08X\n", cpsr);

    // read all registers and print them
    uint32_t registers[16];
    for (int i = 0; i < 16; i++) {
        uc_reg_read(uc, UC_ARM_REG_R0 + i, &registers[i]);
    }

    uint32_t SB, SL, FP, IP, SP, LR;
    uc_reg_read(uc, UC_ARM_REG_SB, &SB);
    uc_reg_read(uc, UC_ARM_REG_SL, &SL);
    uc_reg_read(uc, UC_ARM_REG_FP, &FP);
    uc_reg_read(uc, UC_ARM_REG_IP, &IP);
    uc_reg_read(uc, UC_ARM_REG_SP, &SP);
    uc_reg_read(uc, UC_ARM_REG_LR, &LR);

    printf("R0 = 0x%x\tR1 = 0x%x\tR2 = 0x%x\tR3 = 0x%x\tR4 = 0x%x\tR5 = 0x%x\tR6 = 0x%x\tR7 = 0x%x\n", registers[0], registers[1], registers[2], registers[3], registers[4], registers[5], registers[6], registers[7]);
    printf("R8 = 0x%x\tR9 = 0x%x\tR10 = 0x%x\tR11 = 0x%x\tR12 = 0x%x\tR13 = 0x%x\tR14 = 0x%x\tR15 = 0x%x\n", registers[8], registers[9], registers[10], registers[11], registers[12], registers[13], registers[14], registers[15]);
    printf("SB = 0x%x\tSL = 0x%x\tFP = 0x%x\tIP = 0x%x\tSP = 0x%x\tLR = 0x%x\tPC = 0x%x\n", registers[8], SB, SL, FP, IP, SP, LR, pc);
    return 0;
}

int debug_disassemble(uc_engine* uc, uint32_t address, uint32_t size, char** argv, int argc) {
    uint32_t addr = 0;
    if(argc < 1) {
        uc_reg_read(uc, UC_ARM_REG_PC, &addr);
    } else {
        if(argv[0][0] == '0' && argv[0][1] == 'x') {
            addr = strtol(argv[0], NULL, 16);
        } else {
            uc_arm_reg reg = reg_name_to_id(argv[0]);
            if(reg != UC_ARM_REG_INVALID) {
                uc_reg_read(uc, reg, &addr);
            } else {
                printf("Invalid address or register: %s\n", argv[1]);
                return 0;
            }
        }
    }

    uint32_t cpsr;
    uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr);

    int count = 16;
    if(argc > 1) count = strtol(argv[1], NULL, 10);
    count *= (cpsr & 0x20) ? 2 : 4;

    char* buffer = calloc(1, 128 * count);
    printf("Disassembly of %d bytes starting at 0x%08X:\n", count, addr);
    disassemble(uc, addr, count, buffer);

    printf("%s\n", buffer);
    free(buffer);
    return 0;
}

int debug_break(uc_engine* uc, uint32_t address, uint32_t size, char** argv, int argc) {
    if(argc < 1) {
        printf("Usage: break <address>\n");
        return 0;
    }

    uint32_t addr = strtol(argv[0], NULL, 16);
    args->breakpoints[args->breakpoint_count++] = addr;
    return 0;
}

int debug_rmbreak(uc_engine* uc, uint32_t address, uint32_t size, char** argv, int argc) {
    if(argc < 1) {
        printf("Usage: rmbreak <address>\n");
        return 0;
    }

    uint32_t addr = strtol(argv[0], NULL, 16);
    for(int i = 0; i < args->breakpoint_count; i++) {
        if(args->breakpoints[i] == addr) {
            for(int j = i; j < args->breakpoint_count - 1; j++) {
                args->breakpoints[j] = args->breakpoints[j + 1];
            }
            args->breakpoint_count--;
            break;
        }
    }
    return 0;
}

int debug_log(uc_engine* uc, uint32_t address, uint32_t size, char** argv, int argc) {
    if(argc < 1) {
        printf("Usage: log <log level f,e,w,i,d,t>\n");
        return 0;
    }

    int log_level;

    switch(argv[0][0]) {
        case 'f':
            log_level = LOG_FATAL;
            break;
        case 'e':
            log_level = LOG_ERROR;
            break;
        case 'w':
            log_level = LOG_WARN;
            break;
        case 'i':
            log_level = LOG_INFO;
            break;
        case 'd':
            log_level = LOG_DEBUG;
            break;
        case 't':
            log_level = LOG_TRACE;
            break;
        default:
            printf("Invalid log level: %s\n", argv[0]);
            return 0;
    }

    log_set_level(log_level);
}

void debug(uc_engine* uc, uint32_t address, uint32_t size, void* user_data) {
    if(debugging) return;
    debugging = 1;

    rl_bind_key('\t', rl_insert);

    char* input;
    uint32_t addr_arg_buf;
    uint8_t* buffer = (uint8_t*)malloc(128);

    printf("DEBUGGER!\n");

    debug_registers(uc, address, size, NULL, 0);

    uint32_t pc, cpsr;
    uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr);

    printf("PROCESSOR IS IN %s MODE\n", (cpsr & 0x20) ? "THUMB" : "ARM");

    while(true) {
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);

        input = readline("> ");
        if(input == NULL) goto cleanup;

        if (strlen(input) == 0) continue;
        
        add_history(input);

        char* p = input;
        for( ; *p; ++p) *p = tolower(*p);

        // parse the output into args
        char* args[16];
        int argc = 0;
        char* arg = strtok(input, " ");
        while(arg != NULL) {
            args[argc++] = arg;
            arg = strtok(NULL, " ");
        }

        int command_count = sizeof(commands) / sizeof(debug_command);
        int result = -2;

        for(int i = 0; i < command_count; i++) {
            if(strcmp(args[0], commands[i].name) == 0 || args[0][0] == commands[i].abbreviation) {
                result = commands[i].func(uc, address, size, args + 1, argc - 1);
                break;
            }
        }

        if(result == -1) goto cleanup;
        if(result == -2) {
            printf("Unknown command: %s\n", args[0]);
            continue;
        }
    }

    cleanup:
    debugging = 0;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("Resuming emulation\n");

    start_emulation(uc, pc, 0);
}