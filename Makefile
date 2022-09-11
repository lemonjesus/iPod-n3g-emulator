all: emulator.o log.o
	gcc -o emulator emulator.o log.o -lunicorn

emulator.o: emulator.c core/*.c
	gcc -o emulator.o emulator.c -lunicorn -c

log.o: log.c log.h
	gcc -o log.o log.c -c

clean:
	rm -f *.o emulator