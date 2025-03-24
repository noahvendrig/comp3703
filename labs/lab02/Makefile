EXE=got magic

.PHONY: clean

all: $(EXE)

got: got.c 
	gcc -O0 -g got.c -o got -no-pie -fno-pic -fcf-protection=none -fno-asynchronous-unwind-tables

magic: magic.c 
	gcc -O0 magic.c -o magic -no-pie -fno-pic -fcf-protection=none -fno-asynchronous-unwind-tables
	

clean: 
	rm -f $(EXE)
