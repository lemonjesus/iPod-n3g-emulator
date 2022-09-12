#ifndef __SPI_DEVICE_H__
#define __SPI_DEVICE_H__

typedef struct {
    int (*init)(void* self);
    uint8_t (*read)(void* self);
    int (*write)(void* self, uint32_t cmd);
    void* meta;
} spidev_t;

#endif