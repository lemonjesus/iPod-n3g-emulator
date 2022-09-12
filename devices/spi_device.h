#ifndef _SPI_DEVICE_H_
#define _SPI_DEVICE_H_

typedef struct {
    int (*init)(void* self);
    uint8_t (*read)(void* self);
    int (*write)(void* self, uint32_t cmd);
    void* meta;
} spidev_t;

#endif