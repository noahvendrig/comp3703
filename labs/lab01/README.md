# ANU COMP3703 Lab 01 -- Introduction to Assembly, Compilation and Debugging
_Author: Alwen Tiu, 2025_

In this lab, we will go over some basics of x86 assembly language, compilation, and debugging tool GDB. Some of the exercises, especially towards the end, may require more time to solve than the allocated lab hours, so it is not expected that all students complete all of them during the 2-hour lab session on their own. Sample solutions to these exercises will be released after the lab, but the students are encouraged to attempt them, and work in groups to tackle selected problems. 

# Lab Setup

For the labs in this course, we will use a virtual machine (VM) running Ubuntu Server 22.04 LTS. 

In the following, we assume that you are logged in to a lab computer -- this is the recommended option to get you quickly set up for the lab exercises. The instructions to setup the VM in your own personal computer can be found [here](./vm_setup.md) (but do this outside the lab session). 

## Setting up the lab VM in a lab computer

Log in to your account in a lab computer and open a terminal, then run:

```bash
export PATH=/courses/comp3703/bin:$PATH
install_vm comp3703
```

This will install an instance of VirtualBox VM called `comp3703`in the folder `"VirtualBox VMs"` in your home directory. If you launch the VirtualBox application, you will see `comp3703` listed in the list of virtual machines.
**You only need to run the install_vm script once. Running the install_vm script repeatedly will create multiple instances of the VM and will cause you to run out of storage (and unable to login to your account).**

Note that you need to ensure that `/courses/comp3703/bin` is in your path environment to run the install_vm and other scripts below. One way to make this path permanent is to add the line `export PATH=/courses/comp3703/bin:$PATH` to the `.profile` file in your home directory. 

To run the `comp3703` VM you have just installed, run the following in a terminal: 

```bash 
start_vm comp3703
```

This starts the VM in a "headless" mode -- which means that you will not see the console of the VM launching. We will be primarily interacting with the VM through `ssh`. 

Alternatively, you could also use the GUI of VirtualBox app to start the VM manually, in which case you will be presented with the console. It is **not** recommended for you to login to the VM via the console directly, as the console has limited functionalities and does not interact well with the host operating system (e.g., you can't copy-paste texts etc). Use `ssh` instead. 

If everything goes well, the VM should finish the boot process in 1-2 minutes, after which you can connect to it (see below). 

## Connecting to the lab VM

Once the VM has completed the boot process, connect to it using ssh by running the following command:

```bash
ssh -p 5555 user1@localhost
```

Note that by default, the VM is configured to forward the ssh port (port 22) to port 5555 in the host OS. You can change this port through the `start_vm` command using the `--port` option.

**Username and password:** The username for the VM is `user1` and the password is `ANU_comp3703`. 

**IMPORTANT NOTE: Make sure you change the default password to a secure one!**

## IMPORTANT: Stopping the VM before you log out

When you are done with the lab, or every time you log out of the lab computer, make sure you stop the VM first. Failing to do so might corrupt your instance of the VM and you may lose all your data stored in the VM!

To stop the VM simply run:

```bash
stop_vm comp3703
```

## Troubleshooting
If something goes wrong with your installation, [read these notes first](./troubleshooting.md) to see if that helps. If not, approach the teaching team for help. 

## Transferring files to and from the VM

For most labs, you will likely use `git` to clone a repository from `gitlab.cecs.anu.edu.au` directly to the VM. But in case you need to to transfer files to and from the VM from the host OS, you can use the Secure FTP protocol. This file transfer protocol is supported natively in many operating systems, such as Windows, Linux and Mac OS. The command you need is "sftp". The command to connect to the lab VM using sftp is very similar to ssh; run the following command **from the host OS** (so not from inside the VM):  

```
sftp -P 5555 user1@localhost
```

(Notice the upper case 'P' in the option for port number)

Once you are connected to the lab VM, you will be presented with a `sftp>` prompt, in which you can type commands. Two basic useful commands are get (to download files from the VM) and put (to upload files to the VM). Here are the two commands you need to upload and download files to the VM (assuming the file you want to download/upload is called `myfile.txt`): 

```
sftp> get myfile.txt 
```

This command will retrieve the file `myfile.txt` from the current directory on the VM (by default it is the home directory of the logged in user).  

```
sftp> put myfile.txt
```

This command  will upload the file `myfile.txt` in the current directory on the VM. 


# Exercises

Log in to your VM and clone this repository and change to `lab01` directory and compile all the programs there: 

```bash
cd ~/
git clone https://gitlab.cecs.anu.edu.au/comp3703/2025/labs/lab01
cd lab01/
```

The compiler commands needed to produce the binaries for lab01 are contained in the `Makefile`. To compile all source files, simply type: 

```
make all
```

## Exercise 1 -- x86_64 assembly

For this exercise, we will try to identify some patterns of assembly generated by the gcc compiler, and perform minor modifications to some assembly files. 

Some of the exercises below would require you to disassemble parts of an executable file. The following commands will be useful for these exercises (we will cover more details of the structure of linux executable binaries in Lab 2):

```bash
objdump -M intel -dj .text compilation_example
```

This command disassembles the `.text` section in the executable file compilation_example that contains the instructions of the program that will be executed when the program is run. Here is an example output of a fragment of the disassembled binary: 

```
Disassembly of section .text:

0000000000401050 <_start>:
  401050:	f3 0f 1e fa          	endbr64 
  401054:	31 ed                	xor    ebp,ebp
  401056:	49 89 d1             	mov    r9,rdx
  401059:	5e                   	pop    rsi
  40105a:	48 89 e2             	mov    rdx,rsp
  40105d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  401061:	50                   	push   rax
  401062:	54                   	push   rsp
  401063:	45 31 c0             	xor    r8d,r8d
  401066:	31 c9                	xor    ecx,ecx
  401068:	48 c7 c7 36 11 40 00 	mov    rdi,0x401136
  40106f:	ff 15 7b 2f 00 00    	call   QWORD PTR [rip+0x2f7b]        # 403ff0 <__libc_start_main@GLIBC_2.34>
  401075:	f4                   	hlt    
  401076:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40107d:	00 00 00 

...
```

The left column shows the memory addresses where the instructions will be loaded in memory, the middle column shows the machine code of the instructions, and the right column shows the corresponding assembly. 

```
objdump -sj .rodata crash_me
```

This command shows the content of static data (e.g., pre-defined strings, integers, etc) that the binary crash_me uses.  Here is an example output of the `.rodata` section of the binary: 

```
crash_me:     file format elf64-x86-64

Contents of section .rodata:
 402000 01000200 55736167 653a2025 73203c6e  ....Usage: %s <n
 402010 756d3e0a 00526573 756c743a 2025640a  um>..Result: %d.
 402020 00                                   .               
```

As with the previous command, the left column shows the memory addresses where the data will be located when the program is run. Each row starts with a memory address, followed 16 bytes of the actual data located in that address, in HEX and in ASCII notation (where non-printable characters are replaced by a dot `.`). For example, the string `Usage: %s` starts at memory address 0x402004 (i.e., fifth byte from the address 0x402000).

---

### Exercise 1A
> Compile the program `hello.c` into its assembly version (`hello.s`) and its executable (`hello`) by running `make hello`. Use `objdump` to disassemble the `.text` section of the executable `hello`. Compare the main function in `hello.s` and the disassembled version, and identify which memory address is reserved for the "Hello, world!" string in the executable.

---

### Exercise 1B

> The binary `count_me.o` is an object file that was compiled and stripped (so all debugging symbols, including function names, have been removed). Try to identify how many functions were declared in the file using what you know about the prologue/epilogue patterns of functions compiled with gcc.

---

### Exercise 1C

> For this exercise you are given two files: `off_by_one.c` and its assembly version `off_by_one.s`. The program has a bug that causes it to miss an array index by one. Can you identify where the reference to the array entry is made in the assembly file? Once you identify it, fix the assembly file `off_by_one.s` (do not modify the C program `off_by_one.c`) by modifying only the memory addressing used to access the correct array entry. Compile it with `make off_by_one` to produce the executable and test to see if it runs correctly. Hint: it may be helpful if you can first identify the locations of the local variables (`i` and `arr`) relative to `rbp`.

---

### Exercise 1D (Extension)

> The assembly file `count_down.s` is supposed to start a count down from 10. But the programmer forgot to decrement a counter. Can you spot where the bug is and fix it (by decrementing the counter)? Use `make count_down` to produce the executable `count_down` to test your solution. 

## Exercise 2 -- Introduction to GDB

This exercise is mostly about getting familiar with basic gdb commands. A couple of useful tips on using GDB:

-	You do not need to type the full command if it is unambiguous, e.g., instead of fully typing `continue` we can just type `c` instead.

-	You can hit enter to re-execute the last command. This is useful for commands that need repeated applications.

_Note: the lab VM has a gdb extension, called GEF, installed. For this exercise, we will be looking at the vanilla GDB, so make sure you disable the extension by calling gdb with the option `-nx`._ 

### Starting gdb and stepping through instructions 

For this exercise, we will use the source file `compilation_example.c`. We first compile the program `compilation_example.c` using the command:

```
make compilation_example
```

Then run the program and attach GDB to it.  You might want to incorporate `-q` (quiet) to suppress some verbose output. The option `-nx` disables the GEF plugin, as for this exercise, we want to look at how vanilla gdb works. 

_Note: in the following, we often show the bash commands with a prefix `$`. That `$` sign is not part of the commands; it is there to indicate that the commands are supposed to run in the shell._

```bash
$ make compilation_example
gcc -O0 -g compilation_example.c -o compilation_example -no-pie 
$ gdb -nx -q compilation_example
Reading symbols from compilation_example...
(gdb) 
```

**Getting help.** GDB has a lot of commands, and it may be hard to remember each command and what it can be used for. We can use the `help` command to see the list of instructions and what they are used for. We can further use `help <command>` to see the help for subcommands. Here is an example output of the help command. 

```
(gdb) help
List of classes of commands:

aliases -- User-defined aliases of other commands.
breakpoints -- Making program stop at certain points.
data -- Examining data.
files -- Specifying and examining files.
internals -- Maintenance commands.
obscure -- Obscure features.
running -- Running the program.
stack -- Examining the stack.
status -- Status inquiries.
support -- Support facilities.
text-user-interface -- TUI is the GDB text based interface.
tracepoints -- Tracing of program execution without stopping the program.
user-defined -- User-defined commands.

Type "help" followed by a class name for a list of commands in that class.
Type "help all" for the list of all commands.
Type "help" followed by command name for full documentation.
Type "apropos word" to search for commands related to "word".
Type "apropos -v word" for full documentation of commands related to "word".
Command name abbreviations are allowed if unambiguous.
(gdb) help run
run, r
Start debugged program.
You may specify arguments to give it.
Args may include "*", or "[...]"; they are expanded using the
shell that will start the program (specified by the "$SHELL" environment
variable).  Input and output redirection with ">", "<", or ">>"
are also allowed.

With no arguments, uses arguments last specified (with "run" or 
"set args").  To cancel previous arguments and run with no arguments,
use "set args" without arguments.

To start the inferior without using a shell, use "set startup-with-shell off".
(gdb) 
```


**Running the binary.** We run the binary with the command run. GDB will continue the execution until an input is required, a breakpoint is hit, the program is finished, or the program crashed.

```
(gdb) run
Starting program: /home/user1/lab01/compilation_example 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Hello, world!
[Inferior 1 (process 43126) exited normally]
(gdb) 
```

**Breakpoints.** The `break` command can be used to set breakpoints in a program, so that GDB will pause the execution when it reaches one of these breakpoints. We can add breakpoints using a function name (if the binary is not stripped) and the line number in the source code (if debugging symbol exists). If we can find the memory address of an instruction of interest, we can also add a breakpoint on that memory address; so GDB will pause execution when the current instruction pointer reaches that memory address. Notice that to set a breakpoint at a memory address, you need to prefix the address with an asterisk `*`. 
For example, the following three breakpoints point to the same location:

```
Reading symbols from ./compilation_example...
(gdb) break main
Breakpoint 1 at 0x401149: file compilation_example.c, line 8.
(gdb) break compilation_example.c:8
Note: breakpoint 1 also set at pc 0x401149.
Breakpoint 2 at 0x401149: file compilation_example.c, line 8.
(gdb) break *0x401149
Note: breakpoints 1 and 2 also set at pc 0x401149.
Breakpoint 3 at 0x401149: file compilation_example.c, line 8.
(gdb) 
```

Try different breakpoint related commands, such as  `delete break`, `enable break`, `disable break`, and `clear` (use the `help` command to find out what each of these commands does). You can use the command `info break` to see the status of breakpoints you have set.

When the program execution is halted at a breakpoint, we can investigate the context of the running program at that point. We may even change some values in the registers and memories to see how it will affect subsequent executions (we'll come back to this later).  


**One Step Execution.** When the execution is halted at a breakpoint, it is often useful to continue execution one step at a time. GDB supports several options to step through the program, depending on the granularity of the step we want, e.g., whether we step over a function, a line in the source or an assembly instruction. Note that one line in the source code may be compiled into several assembly instructions.


|                      | Step into the function body | Skip the body of the function |
|----------------------|-----------------------------|-------------------------------|
| Source line          | step                        | next                          |
| Assembly instruction | stepi                       | nexti                         |

In the case where you accidentally step into a function body, you can issue finish to execute until the current function body returns. For example:

```
(gdb) # delete all breakpoints
(gdb) del
Delete all breakpoints? (y or n) y
(gdb) # set a breakpoint at main()
(gdb) break main
Breakpoint 5 at 0x401149: file compilation_example.c, line 8.
(gdb) run
Starting program: /home/user1/lab01/compilation_example 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 5, main (argc=1, argv=0x7fffffffe4a8) at compilation_example.c:8
8	  printf(FORMAT_STRING, MESSAGE);
(gdb) stepi
0x0000000000401150	8	  printf(FORMAT_STRING, MESSAGE);
(gdb) stepi
0x0000000000401153	8	  printf(FORMAT_STRING, MESSAGE);
(gdb) stepi
0x0000000000401040 in puts@plt ()
(gdb) finish
Run till exit from #0  0x0000000000401040 in puts@plt ()
Hello, world!
main (argc=1, argv=0x7fffffffe4a8) at compilation_example.c:9
9	  return 0;
(gdb) 
```

Note that the character `#` is used to mark the beginning of a comment in gdb so the line that starts with this character is ignored by `gdb`. Note also that the memory addresses you see in your terminal may differ from the above output. 

Try replacing the command `stepi` with the command `nexti` and observe the difference. 

**Continuing Execution.** The command `continue` can be used to continue the program execution, unless the program has terminated. 

### Examining stack frames 

For this part, we use the program `div_zero.c`. Compile it with `make div_zero` to produce the executable file `div_zero`. 

When a program crashes, it can be useful to examine the sequence of function calls leading to the crash, and analyse the values of local variables, arguments and registers at various points in the stack frames of the functions in that sequence of calls. The gdb command backtrace (or where) shows the accumulated stack frames in the current execution context, and the info frame command to see relevant information for the current frame. We can also navigate the frames, using up, down, and frame <frame index>.  Here is an example run using the "div_zero" binary we just compiled. Notice that the div_zero program expects two arguments (two numbers), so we use the "run" command followed by the arguments (-1 and 2). 

```bash
user1@comp3703:~/lab01$ gdb -nx -q div_zero
Reading symbols from div_zero...
(gdb) run -1 2
Starting program: /home/user1/lab01/div_zero -1 2
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Program received signal SIGFPE, Arithmetic exception.
0x000000000040117f in f2 (x=0, y=1) at div_zero.c:10
10	        return y/x; 
(gdb) 
```


At this point, gdb says there is an exception (SIGFPE -- floating-point exception), which is caused by a division by zero. The output of gdb above indicates the exception was triggered in function `f2` at line 10 in the source code, where the first argument `(x=0)` is used as a divisor for `y`. In this example, we are already provided with the crashing input (-1 and 2), but in it is not clear at this stage which input is responsible for the crash. For this, running a `backtrace` may help tracing the source of error. 

```
(gdb) backtrace
#0  0x000000000040117f in f2 (x=0, y=1) at div_zero.c:10
#1  0x00000000004011c5 in f1 (a=-1, b=2) at div_zero.c:19
#2  0x0000000000401241 in main (argc=3, argv=0x7fffffffe4a8) at div_zero.c:33
(gdb) 
```

We can use info frame to examine the arguments to the current function (`f2`), the frame pointer (`rbp`) and the instruction pointer (`rip`). 

```
(gdb) info frame
Stack level 0, frame at 0x7fffffffe348:
 rip = 0x40117f in f2 (div_zero.c:10); saved rip = 0x4011c5
 called by frame at 0x7fffffffe370
 source language c.
 Arglist at 0x7fffffffe338, args: x=0, y=1
 Locals at 0x7fffffffe338, Previous frame's sp is 0x7fffffffe348
 Saved registers:
  rbp at 0x7fffffffe338, rip at 0x7fffffffe340
(gdb) 
```

We can navigate to the parent frame (frame #1) that called the current frame, and examining its arguments and local variables (using `info locals`). 

```
(gdb) frame 1
#1  0x00000000004011c5 in f1 (a=-1, b=2) at div_zero.c:19
19	    f2(x,y);
(gdb) info locals
x = 0
y = 1
(gdb) 
```

To help the tracing the source of the crash (assuming we don't have the source code, but debugging symbols are present), we could try to disassemble the instructions in the current frame using the command disassemble. But first we may want to set the "flavor" of the assembly language to use with the set command (we choose 'intel' here, by default it uses the AT&T syntax): 

```
(gdb) set disassembly-flavor intel
(gdb) disassemble
Dump of assembler code for function f1:
   0x0000000000401192 <+0>:	endbr64 
   0x0000000000401196 <+4>:	push   rbp
   0x0000000000401197 <+5>:	mov    rbp,rsp
   0x000000000040119a <+8>:	sub    rsp,0x18
   0x000000000040119e <+12>:	mov    DWORD PTR [rbp-0x14],edi
   0x00000000004011a1 <+15>:	mov    DWORD PTR [rbp-0x18],esi
   0x00000000004011a4 <+18>:	mov    eax,DWORD PTR [rbp-0x14]
   0x00000000004011a7 <+21>:	add    eax,0x1
   0x00000000004011aa <+24>:	mov    DWORD PTR [rbp-0x8],eax
   0x00000000004011ad <+27>:	mov    eax,DWORD PTR [rbp-0x18]
   0x00000000004011b0 <+30>:	sub    eax,0x1
   0x00000000004011b3 <+33>:	mov    DWORD PTR [rbp-0x4],eax
   0x00000000004011b6 <+36>:	mov    edx,DWORD PTR [rbp-0x4]
   0x00000000004011b9 <+39>:	mov    eax,DWORD PTR [rbp-0x8]
   0x00000000004011bc <+42>:	mov    esi,edx
   0x00000000004011be <+44>:	mov    edi,eax
   0x00000000004011c0 <+46>:	call   0x401156 <f2>
=> 0x00000000004011c5 <+51>:	nop
   0x00000000004011c6 <+52>:	leave  
   0x00000000004011c7 <+53>:	ret    
End of assembler dump.
(gdb) 
```

Feel free to make 'intel' the default by running the following command to add the `set` command to the `~/.gdbinit` file.
```
user1@comp3703:~/lab01$ echo "set disassembly-flavor intel" >> ~/.gdbinit
```

We are interested to see how the first argument to the function `f2` (which is the content of the `edi` register prior to `call 0x401156 <f2>`) is derived, as it is that argument that ends up being the divisor. We leave it as an exercise to the reader to figure out that it is the first argument of `f1` that is responsible in for the value of `edi`. 

A further analysis of the parent frame of `f1` (the main function) would reveal that the culprit is the first argument of the program (i.e., `argv[1]`). We omit here the analysis of the assembly code of the main function leading to that conclusion. We can use the `print` command to inspect the array `argv` to see the actual input leading to the crash. 

```
(gdb) frame 2
#2  0x0000000000401241 in main (argc=3, argv=0x7fffffffe4a8) at div_zero.c:33
33	    printf("Result: %d\n", f1(a,b)); 
(gdb) print argv[1]
$1 = 0x7fffffffe736 "-1"
(gdb) 
```

---

### Exercise 2A. 

> The program `crash_me` may occasionally crash (with a floating point exception) when provided with an input value 0 as its argument. Your task is to figure out what input value that would trigger a crash consistently, by analysing its crashing runs in gdb. Use the stack trace analysis you have learned above. You may consult the source code to help you solve this task. Make sure you compile the program first using `make crash_me`. You may need to run it more than once to trigger the crash.

### Inspecting values and modifying values (Local Variables, Registers, Memory, and Instructions). 

In the example of stack frames above, we use some commands (`info` and `print`) to inspect the values of local variables and frames. They can also be applied to registers and memory addresses. To show the values of local variables and all registers in the current frame, respectively, use info locals and info registers. If we are just interested in a particular value we can use print. Inspecting memory can be done using `x`; use `help x` to find more information on how to use it.

We can change the value held by a register or memory location by using set, we can even modify the instruction pointer to modify program executions. We will now see some typical usage of the set command to change the control flow of programs in a debugger, e.g., to by-pass certain a certain check that guards interesting parts of the program. We illustrate here with a simple example using the program `unreachable.c`. First compile the program with `make unreachable`, and run it with `gdb`. 

From the source code, we see that the check at line 34 cannot be true in a normal run of the program, since `x` is set to 0 just prior to this check. We will override the value of `x` at this point so that we can trigger the function `unreachable()`. 

```
user1@comp3703:~/lab01$ gdb -nx -q unreachable
Reading symbols from unreachable...
(gdb) break unreachable.c:34
Breakpoint 1 at 0x4012b7: file unreachable.c, line 34.
(gdb) run
Starting program: /home/user1/lab01/unreachable 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, main (argc=1, argv=0x7fffffffe4b8) at unreachable.c:34
34	    if(x == 1) {
(gdb) set x=1
(gdb) info locals
x = 1
(gdb) continue
Continuing.
You have reached the unreachable, well done!
[Inferior 1 (process 43875) exited with code 01]
(gdb) 
```

Alternatively, we could also change the instruction pointer (register `rip`) to skip the check. But we need to first find out the address of the target instruction we want to jump to. A little disassembly is in order. 

```
(gdb) run
Starting program: /home/user1/lab01/unreachable 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, main (argc=1, argv=0x7fffffffe4b8) at unreachable.c:34
34	    if(x == 1) {
(gdb) set disassembly-flavor intel
(gdb) disass
Dump of assembler code for function main:
   0x000000000040129d <+0>:	endbr64 
   0x00000000004012a1 <+4>:	push   rbp
   0x00000000004012a2 <+5>:	mov    rbp,rsp
   0x00000000004012a5 <+8>:	sub    rsp,0x20
   0x00000000004012a9 <+12>:	mov    DWORD PTR [rbp-0x14],edi
   0x00000000004012ac <+15>:	mov    QWORD PTR [rbp-0x20],rsi
   0x00000000004012b0 <+19>:	mov    DWORD PTR [rbp-0x4],0x0
=> 0x00000000004012b7 <+26>:	cmp    DWORD PTR [rbp-0x4],0x1
   0x00000000004012bb <+30>:	jne    0x4012c9 <main+44>
   0x00000000004012bd <+32>:	mov    eax,0x0
   0x00000000004012c2 <+37>:	call   0x40127c <unreachable>
   0x00000000004012c7 <+42>:	jmp    0x4012d8 <main+59>
   0x00000000004012c9 <+44>:	lea    rax,[rip+0xdc8]        # 0x402098
   0x00000000004012d0 <+51>:	mov    rdi,rax
   0x00000000004012d3 <+54>:	call   0x401070 <puts@plt>
   0x00000000004012d8 <+59>:	mov    eax,0x0
   0x00000000004012dd <+64>:	leave  
   0x00000000004012de <+65>:	ret    
End of assembler dump.
(gdb) 
```

The `cmp/jne` instructions correspond to the "`if (x==1)`" part of the code, so we'll skip them, by setting the register rip (the variable `$rip` in gdb, or alternatively, `$pc`)  to the instruction that comes after them, at address 0x4012bd. 

```
(gdb) set $rip = 0x4012bd
(gdb) c
Continuing.
You have reached the unreachable, well done!
[Inferior 1 (process 43878) exited with code 01]
(gdb) 
```

You could also use the `jump` command to achieve the same effect.


### Exercise 2B. 

> Run the `unreachable` program in gdb again and try to change its control flow so that the unreachable() function gets executed, by calling that function directly using the `call` command from `gdb`. Use `help call` to find out how to use this command. 

_Note that although you can use `jump` or set the `rip` to the target function, this is in general not a good approach (unless you know exactly what you are doing), as a function may expect certain arguments to be in place, or that the stack pointer (`rsp`) is aligned (to 16 bytes boundary), and may crash if these conditions are not met. The `call` command does some of these steps for you._

### Exercise 2C.

> Run the `unreachable` program in gdb again and try to change its control flow so that the notexist() function gets executed, by calling that function directly. Note that the function expects an argument, so make sure you supply the correct value. 

### Exercise 2D (Extension)

> Run the `unreachable` program in gdb again and try to change its control flow so that the `surreal()` function gets executed and the check `(x == 1234)` evaluates to true. Your exploit must not trigger a segmentation fault (SIGSEV). 

## A (very quick) introduction to GEF

Try running GDB again, but without the -nx option. This will enable the GEF plugin. Since GEF is a plugin built on top of GDB, all GDB commands still work, but GEF provides much more information about the binary, including the disassembly of the machine code, values of registers, information on the stack, etc. There are also commands specific to GEF that will simplify some of the debugging tasks. You can try to repeat the exercises above using GEF and see if some exercises become easier to solve. 

We will come back to GEF again in a later part of this course. More information about GEF can be found here: https://hugsy.github.io/gef/

