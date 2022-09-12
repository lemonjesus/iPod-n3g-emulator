# iPod Nano 3rd Generation Emulator

This is a work in progress emulator for the iPod Nano 3rd Generation. It is written in C using the Unicorn Engine for execution.

## Building

Install Capstone and the Unicorn Engine, and then run `make`.

## Progress

Currently I'm making my way through the S5L8702's bootrom. It's able to read from NOR Flash over SPI, and it tries to verify the image header, but it fails because I have the wrong file for it. See commit history for more details.

## License
GPLv3