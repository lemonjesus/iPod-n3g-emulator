#ifndef _LCD_C_
#define _LCD_C_

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

typedef struct  {
    uint32_t config; // 0x00
    uint32_t wcmd; // 0x04
    uint32_t _pad[2];
    uint32_t rcmd; // 0x0C
    uint32_t rdata; // 0x10
    uint32_t dbuff; // 0x14
    uint32_t intcon; // 0x18
    uint32_t status; // 0x1C
    uint32_t phtime; // 0x20
    uint32_t _pad2[7];
    uint32_t wdata; // 0x40
} lcd_t;

Peripheral lcd = {
    .name = "LCD",
    .address = 0x38300000,
    .size = sizeof(lcd_t),
};

#endif