# iPod Nano 3rd Generation Emulator

This is a work in progress emulator for the iPod Nano 3rd Generation. It is written in C using the Unicorn Engine for execution.

## Building

Install the Unicorn Engine, and then run `make`.

## Progress

Currently I'm making my way through the S5L8702's bootrom. I believe I'm currently at the point where it's trying to read from SPI flash and AES decrypt it. Those peripherals don't do anything currently, so I'm working on that now.

## License
GPLv3