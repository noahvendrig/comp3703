# COMP3703 Lab 02 -- Basic Binary Analysis in Linux
_Author: Alwen Tiu, 2025_

In this lab, we will review some basic concepts related to the ELF binary format, using `readelf` and `objdump`, the lazy binding mechanism, and finally, learn to apply various basic binary analysis tools to solve a series of Capture the Flag (CTF) challenges.

The CTF challenges in this lab are sourced from Chapter 5 of Andriesse's "Practical Binary Analysis" and the PICOCTF 2021. For the former, the challenge is divided into 8 levels; we have solved the level 1 challenge during the lectures this week, and in this lab, we will solve the challenges at level 2 to level 5. The remaining challenges are optional but you are encouraged to solve them. 

The descriptions for the exercises related to the CTF are intentionally vague – this is because it is intended to simulate a typical early "discovery" stage in vulnerability analysis, where sometimes only a minimum amount of information is available on a given payload. But if you are stuck at any point, the tutors will be there to guide you through the process. 

# Lab Setup

For Exercise 3, you will likely need the `ltrace` tool (that traces the library calls made by a program):

```bash
sudo apt install ltrace
```

Clone this repository into your lab VM:

```bash
cd ~/
git clone https://gitlab.cecs.anu.edu.au/comp3703/2025/labs/lab02
cd lab02/
```

_Note that this repository includes a tool called `binwalk`. The lab VM actually already has an older version of `binwalk` installed, but that version does not work due to an issue with conflicting python packages. So you are provided with a working version in this repository (that was build from the latest release, which is based on Rust) -- use that version instead for Exercise 4._


# Exercise 1 -- the ELF Format

## Exercise 1A

Use readelf or objdump to obtain the following information about the executable file `magic`. Use the man page of readelf/objdump or the option '--help' to help you find suitable options for this exercise.

* Executable header
* Section headers
* Writable sections
* Offset to the dynamic symbol section (`.dynsym`)
* Disassembly of all sections containing instructions.
* Content of the `.rodata` section


## Exercise 1B

The binary `~/lab2/magic`, when run, asked the user to input a certain "magic number". We are going to use static analysis to discover the value of this magic number (so don’t use `gdb` or any other debugger to solve this exercise). 

- First, disassemble the `.text` section using `objdump` and try to understand the logic of the program. Pay particular attention to the memory location where the magic number is likely to be located. (The binary is not stripped, so there are a lot of helpful comments left in the binary to help you solve this exercise). 

- Then use objdump again to find the value of the magic number. Which section should you try to find this number? 

- Finally, confirm that the number you found is the correct one, by inputting the number you found to the binary. (Hint: make sure you take into account the endianness of how integers are represented in memory). 

## Exercise 1C (Extension)

If you disassemble the binary `magic`, you will find the following line in the `.text` section 

```
4011b7: 8b 15 93 2e 00 00  mov edx,DWORD PTR [rip+0x2e93]
```

Notice that there is a reference to the memory address `[rip+0x2e93]`, whose value is copied to the register `edx`. Review the lecture on the memory addressing syntax in Intel x86-64, and try to calculate the actual address that is referred to by `[rip+0x2e93]` in the above code.  Hint: the register rip contains the address of the next instruction to be executed, which is the address of the current instruction + the length of the current instruction. Use this to help you calculate the address referenced by the expression `[rip+0x2e93]`. 

# Exercise 2 -- Lazy Binding

For this exercise, we will examine how the lazy binding mechanism works when a call to a shared library function is made. 

## Exercise 2A 
In the binary `got`, there are two calls to the `libc` `puts` function. Recall that the call to a `libc` function is rerouted through a stub function in the `.plt` section. That stub function will then consult the Global Offset Table (GOT) to find the actual address of the function. The first time a shared library function is called, its address in GOT is not yet patched (it simply points back to an address in `.plt`), but after the first call, the GOT entry for that function will be patched with the actual address. 
Use objdump to disassemble the `.plt` section and find the address of the GOT entry that corresponds to the puts function. 

## Exercise 2B
Use `gdb` to examine how the GOT entry for the `puts` function changes, prior to the first call and after the first call to put. Hint: you would need to set the break points before and after the first call to puts, and then query the memory address of the GOT entry at each break point, e.g., using the command 

```
x/g <address>
```

(replace `<address>` with the actual address of the GOT entry). 

## Exercise 2C  
Repeat Exercise 2B, but this time use the gdb/gef command `got`. See how much simpler it is! 


# Exercise 3 -- Capture the Flag

For this exercise, you are asked to complete the CTF challenges for level 2 to 5. The relevant files for the CTF are located in `~/lab02/ctf/`. The flag to unlock Level 2 of the challenge is 

```
84b34c124b2ba5ca224af8e33b077e9e
```

To unlock the challenge at the next level, use the oracle program in in `~/lab02/ctf/` : 

```bash
$ cd ~/lab02/ctf/
$ ./oracle <flag> 
```
where <flag> is the flag at the current level that you have obtained. 
For example, to unlock Level 2 challenge, run

```
$ ./oracle  84b34c124b2ba5ca224af8e33b077e9e
```
Each level comes with a hint. To see the hint, run
```
$ ./oracle <flag> -h 
```
(replace `<flag>` with the actual flag for that level).

We shall aim to finish level 5 by the end of this tutorial. For each level, you may the following tools/hints useful.

**Static analysis:** Try a combination of basic tools such as:
- file command, to get basic information about the payload. 
- strings command to see if there are any interesting strings embedded in the binary. 
- objdump/readelf to examine sections of ELF files. 
- hexedit, to examine and/or modify the raw bytes of the file if needed. 

**Dynamic analysis:** In addition to static analysis, you may also want to see the examine the runtime behaviour of the program. 
- Try to execute the binary and see what it does. 
- Run the binary under strace and ltrace to examine the calls to shared library functions. 
- Run the binary under GDB. This can be a bit tricky as the binary is stripped, so you will need to find out where to put the breakpoint. One trick is to see the offset to an interesting string in the `.rodata` section using objdump, and then find which instruction loads the string. 

There are solutions for all levels of this CTF that you can find online (e.g., on practicalbinaryanalysis.com). However, try to attempt these challenges first before looking at those solutions. Working out the solutions for these challenges yourself can be more rewarding.

Some specific hints:
- For level 2, try to look at the data the program uses
- For level 3, you will need to fix a broken elf file. Some of these can be fixed using the tool `elfedit` (run `man elfedit` to read its user manual), but others might require direct editing using a hex editor.
- For level 4, try using dynamic analysis (e.g., `gdb`, `ltrace`, `ldd`, etc) to do quick runtime analysis. 


# Exercise 4 (Extension) -- Basic digital forensic

In this exercise, we shall use the `binwalk` tool (included in this repostory) to help solve a forensic challenge from picoCTF 2021. This is a rather simple challenge to solve (once you know the right tool to use -- `binwalk` in this case). 
You are given an image file, which you can download using the command:

```
wget https://tinyurl.com/bdcnce8b -O dolls.jpg
```

The file is an image of a [Matryoshka doll.](https://en.wikipedia.org/wiki/Matryoshka_doll) This is the only hint given and you are supposed to figure out a hidden `flag` in the image. 

Use `binwalk` to help figure out the hidden payload in the image. 
Use the `--help` option to see available options of binwalk:

```
~/lab02/binwalk --help
```

