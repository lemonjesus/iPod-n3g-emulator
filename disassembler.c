#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include "disassembler.h"
#include "log.h"

void disassemble(uc_engine* uc, uint32_t addr, uint32_t size, char* out) {
    csh handle;
    cs_insn *insn;
    size_t count;

    uint32_t cpsr;
    uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr);

    if (cs_open(CS_ARCH_ARM, (cpsr & 0x20 ? CS_MODE_THUMB : CS_MODE_ARM), &handle) != CS_ERR_OK) {
        log_error("failed on cs_open(), quit");
    }

    uint8_t* bytes = calloc(1, size);
    uc_mem_read(uc, addr, bytes, size);

    count = cs_disasm(handle, bytes, size, addr, 0, &insn);
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            sprintf(out + strlen(out), "%s %s\n", insn[j].mnemonic, insn[j].op_str);
        }
        cs_free(insn, count);
        out[strlen(out) - 1] = '\0';
    } else {
        log_error("Failed to disassemble given %s code! 0x%08X: 0x%08X (size: %d)", (cpsr & 0x20) ? "THUMB" : "ARM", addr, *(uint32_t*)bytes, size);
    }

    free(bytes);
    cs_close(&handle);
}