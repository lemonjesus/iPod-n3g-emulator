#ifndef __NORFLASH_H__
#define __NORFLASH_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../log.h"

#include "spi_device.h"

typedef struct {
    uint8_t* cmd_buffer;
    uint8_t cmd_buffer_index;
    uint8_t* data_buffer;
} norflash_meta_t;

int norboot_init(void* dev) {
    spidev_t* self = (spidev_t*)dev;
    self->meta = malloc(sizeof(norflash_meta_t));
    norflash_meta_t* meta = (norflash_meta_t*)self->meta;

    meta->cmd_buffer = calloc(1, 4);
    meta->cmd_buffer_index = 0;
    meta->data_buffer = calloc(1, 0x1000);

    log_info("NORBOOT device initialized");
}

int norboot_write(void* self, uint32_t cmd) {
    norflash_meta_t* meta = ((spidev_t*)self)->meta;

    meta->cmd_buffer[meta->cmd_buffer_index++] = cmd;

    log_trace("NORBOOT: Recv Command 0x%x (full buffer: 0x%02x%02x%02x%02x)", cmd, meta->cmd_buffer[0], meta->cmd_buffer[1], meta->cmd_buffer[2], meta->cmd_buffer[3]);

    if(cmd == 0xFF) {
        log_info("NORBOOT: Resetting");
        meta->cmd_buffer_index = 0;
        memset(meta->cmd_buffer, 0, 4);
        return 100;
    }

    if(meta->cmd_buffer[0] == 0x05) {
        log_trace("NORBOOT: Read Status?");
        meta->cmd_buffer_index = 0;
        return 1;
    }

    if(meta->cmd_buffer[0] == 0x03 && meta->cmd_buffer_index == 4) {
        log_trace("NORBOOT: Read Data from 0x00%02x%02x%02x", meta->cmd_buffer[1], meta->cmd_buffer[2], meta->cmd_buffer[3]);
        meta->cmd_buffer_index = 0;
        return 1;
    }

    return 100;
}

spidev_t norboot = {
    .init = norboot_init,
    .write = norboot_write,
    .meta = NULL
};

#endif