#ifndef __SPI_H__
#define __SPI_H__

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

typedef struct  {
    uint32_t SPICTRL; // 0x00
    uint32_t SPISETUP; // 0x04
    uint32_t SPISTATUS; // 0x08
    uint32_t SPIPIN; // 0x0C
    uint32_t SPITXDATA; // 0x10
    uint8_t _pad[0x20 - 0x14];
    uint32_t SPIRXDATA; // 0x20
    uint8_t _pad2[0x30 - 0x24];
    uint32_t SPICLKDIV; // 0x30
    uint32_t SPIRXLIMIT; // 0x34
    uint32_t SPIDD; // 0x38
} spi_t;

static void spi_status_read(uc_engine* uc, uc_mem_type type, uint32_t address, int size, int64_t value, void* user_data) {
    Peripheral* self = (Peripheral*)user_data;
    spi_t* spi = (spi_t*)self->memory;

    if(spi->SPISETUP & 0x1) {
        // a read is being attempted
        spi->SPIRXDATA++;
        spi->SPISTATUS = 0x3e00;
    }

    printf("SPI Status Read\n");
    uint32_t pc;
    uint32_t inst;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    uc_mem_read(uc, pc, &inst, sizeof(inst));
    printf("PC = 0x%x, inst = 0x%x\n", pc, inst);
    printf("SPICTRL: 0x%X, SPISETUP: 0x%X, SPISTATUS: 0x%X, SPIPIN: 0x%X, SPITXDATA: 0x%X, SPIRXDATA: 0x%X, SPICLKDIV: 0x%X, SPIRXLIMIT: 0x%X, SPIDD: 0x%X\n", spi->SPICTRL, spi->SPISETUP, spi->SPISTATUS, spi->SPIPIN, spi->SPITXDATA, spi->SPIRXDATA, spi->SPICLKDIV, spi->SPIRXLIMIT, spi->SPIDD);
}

static void spi_status_write(uc_engine* uc, uc_mem_type type, uint32_t address, int size, int64_t value, void* user_data) {
    Peripheral* self = (Peripheral*)user_data;
    spi_t* spi = (spi_t*)self->memory;

    if(spi->SPISETUP & 0x1) {
        // a write is being attempted
        spi->SPISTATUS = 0x3e00;
    }
    
    printf("SPI Status Write 0x%x = 0x%x\n", address, value);
    uint32_t pc;
    uint32_t inst;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    uc_mem_read(uc, pc, &inst, sizeof(inst));
    printf("PC = 0x%x, inst = 0x%x\n", pc, inst);
    printf("SPICTRL: 0x%X, SPISETUP: 0x%X, SPISTATUS: 0x%X, SPIPIN: 0x%X, SPITXDATA: 0x%X, SPIRXDATA: 0x%X, SPICLKDIV: 0x%X, SPIRXLIMIT: 0x%X, SPIDD: 0x%X\n", spi->SPICTRL, spi->SPISETUP, spi->SPISTATUS, spi->SPIPIN, spi->SPITXDATA, spi->SPIRXDATA, spi->SPICLKDIV, spi->SPIRXLIMIT, spi->SPIDD);
}

// void spi_prepare(int port)
// {
//     clockgate_enable(SPICLKGATE(port), true);
//     SPISTATUS(port) = 0xf;
//     SPICTRL(port) |= 0xc;
//     SPICLKDIV(port) = clkdiv[port];
//     SPIPIN(port) = 6;
//     SPISETUP(port) = 0x10618;
//     SPICTRL(port) |= 0xc;
//     SPICTRL(port) = 1;
// }
// void spi_read(int port, uint32_t size, void* buf)
// {
//     uint8_t* buffer = (uint8_t*)buf;

//     SPIRXLIMIT(port) = size;
//     SPISETUP(port) |= 1;
//     while (size--)
//     {
//         while (!(SPISTATUS(port) & 0x3e00));
//         *buffer++ = SPIRXDATA(port);
//     }
//     SPISETUP(port) &= ~1;
// }


int spi_init(uc_engine* uc, void* self) {
    uc_hook spi_status_read_trace;
    uc_err err = uc_hook_add(uc, &spi_status_read_trace, UC_HOOK_MEM_READ, &spi_status_read, self, ((Peripheral*)self)->address + 8, ((Peripheral*)self)->address + 8);
    if (err) {
        printf("SPI driver failed to hook into SPISETUP reg: %u (%s)", err, uc_strerror(err));
        return -1;
    }

    uc_hook spi_status_write_trace;
    err = uc_hook_add(uc, &spi_status_write_trace, UC_HOOK_MEM_WRITE, &spi_status_write, self, ((Peripheral*)self)->address, ((Peripheral*)self)->address + sizeof(spi_t));
    if (err) {
        printf("SPI driver failed to hook into SPISETUP reg: %u (%s)", err, uc_strerror(err));
        return -1;
    }
}

Peripheral spi0 = {
    .name = "SPI 0",
    .address = 0x3c300000,
    .size = sizeof(spi_t),
    .init = spi_init
};

Peripheral spi1 = {
    .name = "SPI 1",
    .address = 0x3ce00000,
    .size = sizeof(spi_t),
    .init = spi_init
};

Peripheral spi2 = {
    .name = "SPI 2",
    .address = 0x3d200000,
    .size = sizeof(spi_t),
    .init = spi_init
};

#endif