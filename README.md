# iPod Nano 3rd Generation Emulator

This is a work in progress emulator for the iPod Nano 3rd Generation. It is written in C using the Unicorn Engine for execution.

## Building

Install Capstone and the Unicorn Engine, and then run `make`.

**This does not include the actual code to run in the emulator.** You will need to provide your own firmware image. This consists of:
 - A bootrom from the S5L8702
 - An EFI image with the IM3 header intact (theoretically this can be skipped with one of the patches I have in place)
 - A decrypted EFI image (at 0x8800 on NOR)

## Progress
The iPod currently makes it through the bootrom (skipping verification steps, of course) and into the EFI image. I don't think it successfully loads any modules (decompressing them takes forever). I think my NOR is missing the sysconfig partition which is why it's getting stuck.

### Currently Working
 - Executing ARM and THUMB code (thanks Unicorn!)
 - Logging of ARM and THUMB instructions at TRACE level
 - Flexible Peripheral and Paravirtualization Interface
 - Enough of the SPI peripheral to make it through the bootloader
 - Enough of the NOR Flash to make it through the bootloader
 - The barest of definitions of other peripherals (in most cases, just acknowledging that they exist)
 - SHA1 peripheral might work
 - Some paravirtualization of NOR Flash (speeds up certain big reads) and slow (for some reason) memory routines like `memzero`

### Not Working (yet)
 - The other peripherals (I2C and Timers are about to become important)
 - Speed - (it takes so long to decompress the EFI drivers that it's not even funny)
 - Getting past the DXEMain module (which is the first EFI driver)
 - Everything else.

## License
GPLv3