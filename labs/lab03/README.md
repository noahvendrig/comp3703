# COMP3703 Lab 03 -- Simple code injection

_Alwen Tiu, 2025_

In this lab, we will look at some simple code injection techniques covered in Chapter 7 of D. Andriesse's "Practical Binary Analysis", in particular, direct hex-editing for in-place instruction modification, code injection, entry point hijacking, GOT hijacking and PLT hijacking. 

Some of the exercises ask you to disassemble a binary, encoding one or more assembly instructions into machine code and patch some instructions in the binary. For a quick reference on the Intel x86-64 instruction set, see

[https://www.felixcloutier.com/x86/](https://www.felixcloutier.com/x86/)

You are welcome (and encouraged) to try to encode/decode simple assembly commands into/from their corresponding bytes manually when solving exercises that require instruction modification, to build a better understanding of subtleties of x86-64 assembly. Or you can use the `asm` and `disasm` functions from the `pwnlib` library (that is part of `pwntools`, a versatile tool for binary analysis and exploitation, that we will use extensively in later parts of the course). A quick tutorial of `pwnlib` `asm`/`disasm` can be found [here](./pwnlib_asm.md). 

Some exercises use the `nasm` assembler to compile assembly code into raw binary. Although `nasm` uses the Intel syntax, it is slightly different from the syntax used by, .e.g., objdump. For this lab you are given template assembly files that require only minor modifications, so a full understanding of `nasm` syntax is not needed. But if you want to learn more, see the [official `nasm` website](https://www.nasm.us) for details.
# Lab setup

Clone the repository for this lab to your lab VM: 

```bash
$ cd ~/
$ git clone https://gitlab.cecs.anu.edu.au/comp3703/2025/labs/lab03.git
$ cd ~/lab03
```

The repository contains a python script `elfins.py`, which is a simple tool for injecting a code section, and for performing a number of simple binary modifications (patching entry address, GOT, arbitrary address). Run `python3 elfins.py --help` to see the available options for this tool. 


# Exercise 1 -- Bare-metal binary modification 


The executable binary `passcheck` checks asks the user to enter a password and checks whether its hash matches a hash value stored in the binary. The hash is computed using the linux crypt function. The actual password is lost and cannot be recovered from the binary – only the crypt hash is stored. You are asked to modify the binary so that the program would behave as if the authentication had succeeded when run (indicated by a message "Authenticated!" being displayed) even when the input password is wrong. One way to do this is to disable the check for the password. Identify the part of the .text section that is responsible for the check, and overwrite the relevant instruction(s). 

_Hint: one useful x86 instruction for this is the NOP instruction that does nothing other than advancing the instruction pointer. Its opcode is 0x90. Of course, you are free to use other instructions to achieve the same result._


# Exercise 2 -- Entry point hijacking

For this task, we will modify the binary hijack_this to make it execute a "win" function in the binary. The win function checks for the value of a key embedded in a global variable in the binary, and prints a message if the value is correct. You first need to find out where that key is stored, and change its value to the correct one, and execute the `win()` function. 

_Note: You could, of course, edit the constant value that the key is compared to in the win function, which would not require a code injection. The purpose of this exercise is to demonstrate the code injection technique so we choose to modify the key variable instead._

A template assembly file, `entry.s`, to create the code to inject has been provided.  You just need to provide three values (see as "TODO" comments in the code). Here's a step-by-step guide to solve this task.

1.	Use objdump to disassemble `hijack_this` to find the three values you need to change. It's a good idea to first use `objdump` to understand the logic of the win function, identify its address and the value it expects from the key variable. 

2.	Modify `entry.s` to change the relevant values based on your findings in the previous step. Then generates the payload to be injected using nasm:

    ```bash
    $ nasm -f bin -o entry.bin entry.s
    ```

3.	Inject the payload `entry.bin` to hijack_entry using the provided elfinject program:

    ```bash
    $ python3 elfins.py hijack_this entry.bin --patchentry
    ```

    This will put the injected code at some address starting from around `0x800000`, and patch the entry point to point to that address. By default, the modified binary is saved to a file called `injected.elf` -- you can change this with the `-o` option. 

4. Verify that the injected code is as you expect, by disassemblying the `.injected` section (by default the injected code is stored in a new section in the binary).

    ```bash
    $ objdump -M intel -dj .injected injected.elf 
    ```

5. Finally, verify that your injected code gets executed by running `injected.elf`. If your patch works it should print a message indicating that you have successfully executed the `win()` function.


# Exercise 3 -- GOT Hijacking

In this exercise, you will hijack a GOT entry in the given binary `myps`. The myps binary is actually the binary for the ps command in linux, but it was compiled as a non-PIE binary, to make code injection easier. 

We will change the behaviour of `myps` by overwriting the `.got.plt` entry for the `fwrite` function, so that it points to our injected code. The payload for the injection in this case will be generated from the assembly file `hello.s`. For this task, you don't need to modify the assembly file. 

As in the previous task, you create the binary payload for the injected code using `nasm`, and name the binary file `hello.bin`, using the command 

```bash
$ nasm -f bin -o hello.bin hello.s 
```

Then inject it into ps.got, but do not modify the entry point:

```bash
$ python3 elfins.py myps hello.bin -o ps.got 
```

The modified binary is saved to `ps.got`. Note that the above command simple injects the hello.bin but has otherwise not made any modifications to the control flow of the original binary. 

The `elfins.py` script can automatically patch the GOT entry using the `--patchgot` option, but for this exercise try to do this manually first, so that you will understand the steps involved in implementing this kind of modification. (This will be important later on when we perform dynamic GOT modification when we discuss exploitaiton techniques.)

Find the entry in `.got.plt` used by `fwrite` (e.g., using `objdump`), and patch it to point to the injected code using a hex editor. Verify that your injected code gets executed by running the modified binary. 

Note that there is an important difference between this task and the GOT hijacking example in the book/lecture. That is, the PLT entries for ps.got are not located in the `.plt` section; instead they are in the `.plt.sec` section. This change was caused by the incorporation of some advanced binary protection techniques in gcc (e.g., control-flow integrity protection). So the section you need to examine for the PLT stub is in `.plt.sec`. 


# Exercise 4 -- GOT hijacking (advanced)

For this task, we will use the same binary `hijack_this` as in Exercise 2. There is only one shared library function used, i.e., the puts function. Your task is to use the GOT hijacking method to hijack the call to `puts`, and set the key value and execute the `win()` function. There is, however, a catch: a successful hijacking must print the message (which triggers a call to puts again) that indicates you have reached the win function. This is slightly tricky as after you hijack the GOT entry to puts, you must restore it back to its original value after you change the value of the key variable. Otherwise, a subsequent call to puts will trigger the call to your injected code again, which may cause the program to loop or crash. To help you complete this task, we have provided a template assembly file `got.s`. You just need to fill some values there (indicated by the TODO comments).

# Exercise 5 -- PLT hijacking

This is similar to Exercise 3, but this time you will overwrite the PLT entry for `fwrite` so it calls the injected code. Use the same payload generated from `hello.s`. You will need to modify the code in the PLT stub for fwrite to call the injected code. This method should also work on PIE binary; test this by using `/bin/ps` in the lab VM as the target for injection. 

Try to do this the "hard way" first, by computing the instruction bytes for `jmp <target>` where `<target>` is the address of the injected code and edit the binary manually using hexedit. Use the `asm` command of pwntools to help you with converting the assembly to instruction bytes (see [this tutorial](./pwnlib_asm.md)).  (The easy way is to just run `elfins.py` with the `--patchaddress` option and provide the address of the PLT entry for `fwrite`). 


# Exercise 6 -- PIE binaries entry point hijacking

In Exercise 5, we see that PLT hijacking also works with PIE binaries, but in that exercise, we do not need to explicitly code the address to return to, as it would have been pushed to the stack by the caller of `fwrite`, so a simple `ret` instruction will return the control back to the caller. 
In this exercise, we will hijack the entry point of a PIE binary, and resumes the normal execution after the injected code has been executed. For this to work, we can't end our injected code with a `ret` instruction to return to the original entry point, as it is not stored in the stack. So we will need to code this with an explicit jump instruction. You are provided with a template to do this in `hello_pie.s`. Use that to implement an entry point hijacking for the binary `myls`, so that every time it is executed, a "Hello world!" will be printed.

**Note:** One important thing to note when working with a PIE binary is that the addresses of its instructions and data will be relocated at runtime, so if you want to jump back to a particular instruction in the original binary from the injected code, you can't use directly the address you see in the disassembly (eg., objdump). However, the relative positions of these addresses do not change at run time. In particular the relative position of the start of the injected code and the original entry point remains the same at runtime. This is why you see in the `hello_pie.s`, the jump back to the original entry point is expressed relative to the label `main:` in `hello_pie.s` (which marks the beginning of the injected code, so not to be confused with the main function in the original binary):

```
jmp main+(orig_entry-payload_entry)
```

# Exercise 7 (extension) -- instrumenting PIE binaries

In Exercise 6, the injected code completely replaces the libc function `fwrite`. For this exercise, you are asked to modify the injected code so that when `fwrite` is called, it will print the string " **pwned** " and then proceed to execute the original `fwrite`. Instrument this code to the `/bin/ps` binary (which is a PIE binary with full RELRO protection) so that when the modified binary is called it will display something like the following: 

```bash
$ ./injected.elf 
 **pwned**  **pwned**  **pwned**  **pwned**     PID TTY          TIME CMD
 **pwned**  **pwned**  **pwned**  **pwned**  104292 pts/1    00:00:09 bash
 **pwned**  **pwned**  **pwned**  **pwned**  105484 pts/1    00:00:00 injected.elf
 ```

**Hint:** You would need to find out where the GOT entry of fwrite is stored, and jump to the address stored in that entry to execute the libc's fwrite function. But make sure that all your instructions are position independent, as their addresses can be relocated at run time. For this, you need to write the equivalent of 

```
jmp QWORD PTR [rip+offset]
```

where offset is the relative distance between that jump instruction and the fwrite GOT entry. In nasm, you can't directly reference the rip register. Instead, you can use the keyword `rel` to achieve a similar effect. For example, if you want to read the address that is at `offset` relative to, e.g., the main: label in your assembly code, you could write in nasm:

```
jmp [rel main+offset]
```

