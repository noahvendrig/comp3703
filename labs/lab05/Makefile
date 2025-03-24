CC=gcc
OBJ=hexit hexits 

.PHONY: all clean

all: $(OBJ)

hexit: hexit.c
	$(CC) -o hexit hexit.c -g -O0 -fno-stack-protector -z execstack -no-pie -fcf-protection=none

hexits: hexit.c
	$(CC) -o hexits hexit.c -O3 -fno-stack-protector -D_FORTIFY_SOURCE=0 -z execstack -no-pie -fcf-protection=none 
	strip hexits 

clean:
	rm -f $(OBJ)
	rm -f *.o

