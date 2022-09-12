all: disassembler.o emulator.o log.o
	gcc -g -o emulator disassembler.o emulator.o log.o -lunicorn -lcapstone

disassembler.o: disassembler.c
	gcc -g -c -o disassembler.o disassembler.c -lcapstone

emulator.o: emulator.c core/* devices/* paravirtualization/*
	gcc -g -c -o emulator.o emulator.c -lunicorn

log.o: log.c log.h
	gcc -g -c -DLOG_USE_COLOR -o log.o log.c

clean:
	rm -f *.o emulator
