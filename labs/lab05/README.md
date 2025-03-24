# COMP3703 Lab05 -- Stack-based exploitation

In this lab, we will go through steps in implementing a working stack-exploitation, with the goal of injecting and executing shellcode in a running process. In the process, we will also learn how to use some simple functions from the [pwntools library](https://docs.pwntools.com/en/stable/) to help us automate some of the attack steps. The attack script templates are included to help you create worka-ble exploits – they include comments on features of pwntools that we will use throughout the lab. 


# Lab setup

Download and compile the lab files from gitlab:

```bash
$ cd ~/
$ git clone https://gitlab.cecs.anu.edu.au/comp3703/2025/labs/lab05
$ cd ~/lab05
$ make
```

There are two binaries produced: `hexit` and `hexits` (which is the optimized and stripped version of `hexit`). 

## Disable ASLR

You need to disable ASLR to ensure that the buffer addresses do not change across different runs. 

```bash 
$ sudo sysctl -w kernel.randomize_va_space=0
```

Note that ASLR is turned back on at every restart of the system, so you’d need to do this step again if you restart the VM.


# Payload creation

For Exercise 1, 2 and 3, we will attempt to overflow a buffer in the `hexit` binary. In Exercise 4 and 5, we will target the stripped version `hexits`. This is a simple program that will display the bytes in the file or standard input in hex notation. The programs take as input a block size and a file name -- the file name is optional, and if it is not provided, it defaults to standard input. There are two obvious buffer overflow vulnerabilities that you can exploit: one in `processs_file` and the other in `process_stdin`. In both cases the attacker can supply any block size but the input is always read into a buffer of size 256, so it is trivial to overflow the buffer. 
For Exercise 1-4, we'll exploit the one in `process_file` function, and for Exercise 5, we'll exploit the one in `process_stdin`.  

For each exercise, you will be asked to create a payload, which includes the shellcode, to inject into the buffer of the target binary. To make it easier for you to craft the payload, we have prepared an attack script template in python for each task (`exploit1.py, .., exploit5.py`).

The template exploits already have the shellcode added to the buffer. You will need to fill in the rest, e.g., the return ad-dress that points to the shellcode, NOP sled, etc. Look for the `TODO` items in the script for the places you need to modify. Some of the templates also includes python commands to interact with the program, using python libraries (`os` and `pwntools`). See the comments in these templates for more details. 

# Exericse 1: Shellcode injection -- using a debugger

For this exercise, we are going to perform a shellcode injection exploiting the buffer overflow bug in the `process_file` function in the binary `hexit`.  We will attempt this inside a debugger, to help you figuring out the addresses of the buffer and the location of the return address in the stack, so you can craft a working payload to inject to the running program.

The template attack script (`exploit1.py`) provides additional information on what you need to change in the script to make it work. First you need to find the address of the buffer and the relative position of the stored return address in the stack with respect to the buffer. Once you fill in this information in the script, run it to produce `badfile1`, which you can then load it to the program. You would want to set a break point at the function entry to examine the stack frame to obtain the relevant addresses, create the payload, and resume execution. 

If successful, you will see a shell prompt; test to see if it works (e.g., type a shell command such as `ls`). 

# Exercise 2 – Brute-forcing the buffer address 

For this exercise, we will attempt the buffer overflow attack on `hexit`, outside `gdb`. You will notice that the payload you created in Exercise 1 will not work when used outside gdb, as the address of the buffer is shifted slightly. Generally, the address of the stack can be affected by the size of the arguments and the space allocated for environment variables passed to the program (as these will occupy space in the stack frame of the main function, thereby shifting the addresses of subsequent stack frames of the functions it calls). 

For this exercise, we will attempt to brute force the start address of the buffer. You will still need to find the buffer address using gdb, and then vary that address by a range of offsets. 

Use the attack script template `exploit2.py` to help you with the payload creation. The `exploit2.py` script will attempt to bruteforce the address of the buffer; you don't need to run the hexit command separately, once you fill in all the required information the script, just launch it to start the exploit. 

For this exercise, we will use a slightly different payload, that simply displays the content of the `/etc/passwd` file, just to illustrate the use of the `shellcraft` library in pwntools.  


# Exercise 3 – Return address spraying and NOP sled

For this exercise, we will use the return address spraying and NOP sled to make sure our attack is more robust against buffer address variations. For this, we will still use the buffer address we found through gdb, and we attempt to guess a range of possible buffer addresses to perform an attack outside gdb. However, we do not need to use brute force, as the spraying and the NOP sled will ensure that, if the actual buffer address is in the right range, the return address will be overwritten correctly and it will land on the NOP sled. Use the attack script exploit3.py to help you automate this attack. There are more hints in the `exploit3.py` to guide you through the attack steps. Please refer to the lectures on stack-based exploitation on the method to find an optimum address range. 

# Exercise 4 (extension) – Using de Bruijn sequence to determine buffer offsets

This task is similar to Exercise 1, except that we will use `hexits` (the optimizied and stripped version of hexit). You will find that the addresses and the offsets you discovered in Exercise 1 do not work for this binary. This is due to the compiler optimisation restructing some of instructions and shifting the buffer addresses (relative to rbp) slightly. 

For this task, we will attempt a common technique used to probe memory to figure out offsets of buffers. This technique injects a particular sequence of characters, called a [de Bruijn sequence](https://en.wikipedia.org/wiki/De_Bruijn_sequence) (or cyclic patterns), to the target buffer, with the aim of figuring out the offset of the start of the buffer relative to a certain target (e.g., the return address). 
A de Bruijn sequence with a period of N is a string such that every substring of length N occurs in the string exactly once. This means in particular that given a substring of length N, we can determine exactly its offset relative to the start of the string. 

For our example, we will generate a de Bruijn string with period 8. If we overflow the `read_buffer` in `process_file` with such a sequence, until it overwrites the stored return pointer. 

We can use either pwntools or gef to generate de Bruijn sequences. We show here an example using pwntools. 

```python
>>> from pwn import *
>>> cyclic(64, n=8)
b'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaa'
>>> 
```

This generates a string of length 64, with a period of 8 (so every substring of length 8 is unique). 

To use a de Bruijn sequence to find the offset of `read_buffer`, generate a long enough sequence (e.g., 512 bytes) that is sure to overwrite the return address. Save the sequence to a file, and load that file using `hexits` in `gdb`. When run, this would trigger a crash. You should be able to determine from the output of `gdb` where the crashing address is, e.g., if you see that the instruction crashes at address 0x626161616161616e, using the `find` function of cyclic, we can determine the offset: 

```python
>>> c=cyclic(512,n=8)
>>> c.find(p64(0x626161616161616e))
304
```


Use the attack script `exploit4.py` (which is very similar to exploit1.py) to help you create the payload file for the attack inside gdb. 

# Exercise 5 (extension) –- programming interaction using pwnlib.tubes.process

This exercise is similar to Exercise 3, but we will target `hexits` rather than `hexit`, and instead of creating a badfile, we will attempt to overflow the buffer through standard input. This is meant to show you how to use pwntools to program a two-way interaction with a process without user input. Use the attack script `exploit5.py` to help you automate the attack. 



