all: disassembler.o emulator.o log.o
	gcc -o emulator disassembler.o emulator.o log.o -lunicorn -lcapstone

disassembler.o: disassembler.c
	gcc -c -o disassembler.o disassembler.c -lcapstone

emulator.o: emulator.c core/*.c
	gcc -c -o emulator.o emulator.c -lunicorn -c

log.o: log.c log.h
	gcc -o log.o log.c -c

clean:
	rm -f *.o emulator