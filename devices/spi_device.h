#ifndef __SPI_DEVICE_H__
#define __SPI_DEVICE_H__

typedef int (*SpiInitCallback)(void* self);
typedef int (*SpiWriteCallback)(void* self, uint32_t cmd);

typedef struct {
    SpiInitCallback init;
    SpiWriteCallback write;
    void* meta;
} spidev_t;

#endif