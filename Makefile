all: arguments.o debugger.o disassembler.o emulator.o log.o
	gcc -g -o emulator *.o -lunicorn -lcapstone

arguments.o: arguments.c arguments.h
	gcc -g -c -o arguments.o arguments.c

debugger.o: debugger.c debugger.h
	gcc -g -c -o debugger.o debugger.c -lcapstone -lunicorn

disassembler.o: disassembler.c disassembler.h
	gcc -g -c -o disassembler.o disassembler.c -lcapstone

emulator.o: emulator.c core/* devices/* paravirtualization/*
	gcc -g -c -o emulator.o emulator.c -lunicorn

log.o: log.c log.h
	gcc -g -c -DLOG_USE_COLOR -o log.o log.c

clean:
	rm -f *.o emulator
