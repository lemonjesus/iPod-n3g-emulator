#ifndef _LCD_C_
#define _LCD_C_

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

typedef struct  {
    uint32_t config; // 0x00
    uint32_t wcmd; // 0x04
    uint32_t _pad;
    uint32_t rcmd; // 0x0C
    uint32_t rdata; // 0x10
    uint32_t dbuff; // 0x14
    uint32_t intcon; // 0x18
    uint32_t status; // 0x1C
    uint32_t phtime; // 0x20
    uint32_t _pad2[7];
    uint32_t wdata; // 0x40
} lcd_t;

static void lcd_reigon_read(uc_engine* uc, uc_mem_type type, uint32_t address, int size, int64_t value, void* user_data) {
    Peripheral* self = (Peripheral*)user_data;
    lcd_t* lcd = (lcd_t*)self->memory;

    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    log_debug("LCD Reigon Read 0x%x = 0x%08X @ PC = 0x%x", address, lcd->status, pc);
    log_trace("LCD STATE CONFIG=0x%x, WCMD=0x%x, RDATA=0x%x, DBUFF=0x%x, INTCON=0x%x, STATUS=0x%x, PHTIME=0x%x, WDATA=0x%x", lcd->config, lcd->wcmd, lcd->rdata, lcd->dbuff, lcd->intcon, lcd->status, lcd->phtime, lcd->wdata);
}

static void lcd_reigon_write(uc_engine* uc, uc_mem_type type, uint32_t address, int size, uint32_t value, void* user_data) {
    Peripheral* self = (Peripheral*)user_data;
    lcd_t* lcd = (lcd_t*)self->memory;

    // perform the write for the vm so we can write reasonable code about it below
    ((uint8_t*)self->memory)[address - self->address] = value;

    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    log_debug("LCD Reigon Write 0x%x = 0x%x @ PC = 0x%x", address, value, pc);

    if(address == self->address && value == 0x81100db8) {
        lcd->status = 0x00000002;
        log_trace("LCD INIT CONFIG=0x%x, WCMD=0x%x, RDATA=0x%x, DBUFF=0x%x, INTCON=0x%x, STATUS=0x%x, PHTIME=0x%x, WDATA=0x%x", lcd->config, lcd->wcmd, lcd->rdata, lcd->dbuff, lcd->intcon, lcd->status, lcd->phtime, lcd->wdata);
    }
}

int lcd_init(uc_engine* uc, void* data) {
    Peripheral* self = (Peripheral*)data;
    lcd_t* lcd = (lcd_t*)self->memory;

    uc_hook lcd_status_read_trace;
    uc_err err = uc_hook_add(uc, &lcd_status_read_trace, UC_HOOK_MEM_READ, &lcd_reigon_read, self, ((Peripheral*)self)->address, ((Peripheral*)self)->address + sizeof(lcd_t));
    if (err) {
        log_error("lcd driver failed to hook into lcdSETUP reg: %u (%s)", err, uc_strerror(err));
        return -1;
    }

    uc_hook lcd_status_write_trace;
    err = uc_hook_add(uc, &lcd_status_write_trace, UC_HOOK_MEM_WRITE, &lcd_reigon_write, self, ((Peripheral*)self)->address, ((Peripheral*)self)->address + sizeof(lcd_t));
    if (err) {
        log_error("lcd driver failed to hook into lcdSETUP reg: %u (%s)", err, uc_strerror(err));
        return -1;
    }
}


Peripheral lcd = {
    .name = "LCD",
    .address = 0x38300000,
    .size = sizeof(lcd_t),
    .init = lcd_init
};

#endif