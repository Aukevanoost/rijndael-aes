CC ?= cc

.PHONY: all
all: main rijndael.so

main: rijndael.o src/main.c
	gcc -o dist/main src/main.c dist/rijndael.o

rijndael.o: lookup_table.o src/rijndael.c src/rijndael.h
	gcc -o dist/rijndael.o -fPIC -c src/rijndael.c

rijndael.so: rijndael.o
	gcc -o dist/rijndael.so -shared dist/rijndael.o

lookup_table.o: src/lookup_table.c
	gcc -o dist/lookup_table.o -fPIC -c src/lookup_table.c

clean:
	rm -rf dist/*
