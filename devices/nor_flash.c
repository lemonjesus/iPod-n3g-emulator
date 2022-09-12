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
    uint8_t* content;
    uint32_t content_buffer_index;
} norflash_meta_t;

int norboot_init(void* dev) {
    spidev_t* self = (spidev_t*)dev;
    self->meta = malloc(sizeof(norflash_meta_t));
    norflash_meta_t* meta = (norflash_meta_t*)self->meta;

    meta->cmd_buffer = calloc(1, 4);
    meta->cmd_buffer_index = 0;
    meta->content = calloc(1, 0x100000);
    meta->content_buffer_index = 0;

    // load efi.bin into norflash at 0x8000
    FILE* efi = fopen("efi.bin", "rb");
    if(efi == NULL) {
        log_error("Failed to open efi.bin");
        return -1;
    }
    fseek(efi, 0, SEEK_END);
    long fsize = ftell(efi);
    fseek(efi, 0, SEEK_SET);
    fread(meta->content + 0x8000, fsize, 1, efi);
    fclose(efi);

    log_info("NORBOOT device initialized");
}

uint8_t norboot_read(void* self) {
    norflash_meta_t* meta = ((spidev_t*)self)->meta;
    return meta->content[meta->content_buffer_index++];
}

int norboot_write(void* self, uint32_t cmd) {
    norflash_meta_t* meta = ((spidev_t*)self)->meta;

    meta->cmd_buffer[meta->cmd_buffer_index++] = cmd;

    log_trace("NORBOOT: Recv Command 0x%x (full buffer: 0x%02x%02x%02x%02x)", cmd, meta->cmd_buffer[0], meta->cmd_buffer[1], meta->cmd_buffer[2], meta->cmd_buffer[3]);

    if(cmd == 0xFF) {
        log_info("NORBOOT: Resetting");
        meta->cmd_buffer_index = 0;
        meta->content_buffer_index = 0;
        memset(meta->cmd_buffer, 0, 4);
        return 100;
    }

    if(meta->cmd_buffer[0] == 0x05) {
        log_trace("NORBOOT: Read Status?");
        meta->cmd_buffer_index = 0;
        return 1;
    }

    if(meta->cmd_buffer[0] == 0x03 && meta->cmd_buffer_index == 4) {
        meta->cmd_buffer_index = 0;
        meta->content_buffer_index = ((uint32_t)meta->cmd_buffer[1] << 16) | ((uint32_t)meta->cmd_buffer[2] << 8) | (uint32_t)meta->cmd_buffer[3];
        log_trace("NORBOOT: Read Data from 0x%x", meta->content_buffer_index);
        return 1;
    }

    return 100;
}

spidev_t norboot = {
    .init = norboot_init,
    .read = norboot_read,
    .write = norboot_write,
    .meta = NULL
};

#endif