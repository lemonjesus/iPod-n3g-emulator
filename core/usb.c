#ifndef __USB_H__
#define __USB_H__

#include <stdint.h>
#include <stdlib.h>
#include "peripheral.h"

typedef struct  {
    uint32_t OPHYPWR; // 0x00
    uint32_t OPYCLK; // 0x04
    uint32_t ORSTCON; // 0x08
    uint8_t _pad[0x18 - 0x0C];
    uint32_t OPHYUNK3; // 0x18
    uint32_t OPHYUNK1; // 0x1C
    uint8_t _pad2[0x44 - 0x20];
    uint32_t OPHYUNK2; // 0x44

} otgphy_t;

int usb_init(uc_engine* uc, void* data) {
    Peripheral* self = (Peripheral*)data;
    uint8_t* usb = (uint8_t*)self->memory;

    usb[14] = 0x1;
    return 0;
}

Peripheral otgphy = {
    .name = "OTG PHY",
    .address = 0x3C400000,
    .size = sizeof(otgphy_t),
};

Peripheral usb = {
    .name = "USB",
    .address = 0x38400000,
    .size = 0x1000,
    .init = usb_init,
};

#endif