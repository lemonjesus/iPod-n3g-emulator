all: emulator

emulator: emulator.c core/*.c
	gcc -o emulator emulator.c  -lunicorn -lpthread -lm
