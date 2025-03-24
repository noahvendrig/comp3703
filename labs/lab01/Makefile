ALL=hello count_down off_by_one compilation_example div_zero crash_me unreachable

.PHONY: clean

all: $(ALL)

hello.s: hello.c 
	gcc -masm=intel -S hello.c -O0 -fno-stack-protector -fcf-protection=none -fno-asynchronous-unwind-tables -fno-pic 

hello: hello.s 
	gcc hello.s -o hello -no-pie

count_down: count_down.s  
	gcc count_down.s -o count_down -no-pie

off_by_one.s: off_by_one.c 
	gcc -masm=intel -S off_by_one.c -O0 -fno-stack-protector -fcf-protection=none -fno-asynchronous-unwind-tables -fno-pic 

off_by_one: off_by_one.s 
	gcc off_by_one.s -o off_by_one -no-pie

compilation_example: compilation_example.c 
	gcc -O0 -g compilation_example.c -o compilation_example -no-pie 

div_zero: div_zero.c 
	gcc -O0 -g div_zero.c -o div_zero -no-pie 

crash_me: crash_me.c 
	gcc -O0 -g crash_me.c -o crash_me -no-pie 

unreachable: unreachable.c 
	gcc -O0 -g unreachable.c -o unreachable -no-pie 

clean:
	rm -f $(ALL) hello.s 

