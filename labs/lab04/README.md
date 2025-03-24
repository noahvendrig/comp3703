# COMP3703 Lab 04 -- Customising disassembly

_Alwen Tiu, 2025_

In this lab, we will learn how to use the reverse engineering tool Ghidra and how to implement simple custom disassembly tools using the Capstone disassembly framework. 

# Lab setup

Download the lab files from gitlab:

```bash
$ cd ~/
$ git clone https://gitlab.cecs.anu.edu.au/comp3703/2025/labs/lab04
```

We will use the Ghidra reverse engineering tool to solve Exercise 1. Ghidra is not installed in the lab VM, as it requires GUI to run. But it is installed in the lab computers. You can also install Ghidra in your own personal computer from [https://ghidra-se.org](https://ghidra-se.org). Note that you will need an appropriate version of JDK installed to run Ghidra. See Ghidra website for details.

Please make sure you watch the Ghidra tutorial videos (in three parts) posted on Wattle prior to the lab session.

# Exercise 1 -- Reverse engineering with Ghidra

This task is meant to familiarise yourself with Ghidra, by exploring a few basic features of Ghidra, and using it to solve a simple CTF problem.  

For this task we will use the binary `rev50_linux64-bit` included in the lab files. This is actually a CTF problem from crackmes.one, which you can also download here: [https://crackmes.one/crackme/5b8a37a433c5d45fc286ad83](https://crackmes.one/crackme/5b8a37a433c5d45fc286ad83). 

Here are some basic steps to get you started. If you are already familiar with Ghidra, you can go straight to the last step and find the flag. 

* Create new project. Choose the non-sharing option.

* Import rev50_linux64-bit into the project, either through drag and drop or File → Import file. Choose the appropriate format and language: ELF and x86 gcc little endian 64 bit.

* Open the CodeBrowser tool, by double-clicking the icon for the imported binary. When opening the file, you will be asked to run some analyses. For our purpose, it is sufficient to use the default options. However, you can have a look at the description of each analysis to understand what it does, for example:

* Decompiler Switch Analysis

* Embedded Media

* Function Start Search

* The following windows are some of the main windows that we will be interested in. You can use the F1 key to launch a contextual help to learn more about each window. If the window does not exist, you can bring it up via using the Window menu.
    - Listing 
    - Program tree
    - Decompiler
    - Bytes
    - Function graph
    - Function call graph

* We can follow functions and other labels in the Listing window by double-clicking the labels. When rev50_linux64-bit is loaded, the Listing window should show the executable header (if not, you can use the program tree to display the ELF header). Recall that the entry point to the program is not your main function, but the _start function which in turn passes the address to the main function (in register `rdi`) to `__libc_start_main`. From this executable header, keep following appropriate labels until you reach the main function.

* In the Decompiler window it should now show the decompiled main function. If the Decompiler window is not shown, bring it up via Window ->  Decompiler.  In this case, we know that the general function signature for `main` is `int main (int argc, char** argv)`. Try to edit the function signature and rename the variables in the main function and see how the changes propagate. Hint: right-clicking on a C statement in the Decompiler window will bring a menu to modify the decompiled code.

* Now try to figure out what the main function does and find the flag!


# Exercise 2. Identifying overlapping code 

In the lab files, we include an executable binary called `overlapping_bb` (sourced from the textbook) which contains overlapping code blocks. This is caused by a jump instruction that jumps to a target located in the middle of another instruction. In the lecture we have seen that a simple recursive disassembler can identify these overlapping code blocks, but it does not warn the user that such overlapping blocks exist. For this task, we will extend the provided recursive disassembler (in `~/lab04/rdisasm.py`) so that it identifies every jump instruction that jumps into the middle of another instruction. 

Note that we use the python bindings for Capstone for this task to simplify the coding. See  [http://www.capstone-engine.org/lang_python.html](http://www.capstone-engine.org/lang_python.html) to get some general idea of how this python binding works. 

For this task you only need to understand the data structure for representing instructions. The python binding uses the same data structure `cs_ins` in the C++ binding, and you can see the details in the included headerfile (`~/lab04/capstone.h`). The name of the fields for an instruction object in python is identical to the C++ structure `cs_ins`. For example, if `ins` is an instruction object in python, then you can access its address as the field `ins.address`.  A complete example of how to access important data structures in instructions in python can be found in the included script `~/lab04/test_x86.py`, which was provided by the Capstone developer. 

Test your implementation on the binary `~/lab04/overlapping_bb`. 

# Exercise 3. Identifying and disassembling the main function

The included basic recursive disassembler (`~/lab04/rdisasm.py`) does not follow through an indirect jump or an indirect call. This causes a problem when disassembling a stripped binary, since the symbol for the main function is lost, and it is called indirectly through `__libc_start_main`, but the address of `__libc_start_main` is usually provided through a memory addressing syntax (calculated as an offset relative to RIP). 

Your task here is to extend the recursive disassembler rdisasm.py so that it can identify the main function through `__libc_start_main`, even when applied to a stripped binary. (Recall that `__libc_start_main` is a shared library function from libc, so this symbol is still present in a stripped binary).

To solve this task, there are a few subtasks you may need to solve first:

* Identifying the address of the `__libc_start_main`. This you can obtain by querying the ELF binary, e.g., if your ELF object is e then `e.symbols['__libc_start_main']` will give you the address of `__libc_start_main`. 

* Identifying a call to `__libc_start_main`. The call to `__libc_start_main` is usually an indirect call, where the address of `__libc_start_main` is expressed as a memory addressing formula (base + index*scale + displacement), e.g., as in the following code: 
```
0x01078:  ff 15 72 2f 00 00     call    qword ptr [rip + 0x2f72]
```
where the address of the callee is calculated from `[rip + 0x2f72]`. A helper function (`get_cs_ins_mem_target`) has been provided to help you resolve the target address of such a call. Use that to determine whether a given call instruction calls the `__libc_start_main` function. 

* Identifying the first argument to `__libc_start_main`. This is the register that holds the address of the main function. Recall that in x86-64, by the calling convention, the first argument is stored in the RDI register. 

* Detecting a write to the register RDI. Two helper functions (`mov_rdi` and `lea_rdi`) do this for you. That is `mov_rdi(ins)` will return the immediate value assigned to RDI (if it is a MOV instruction writing to RDI) – otherwise it returns 0. Likewise for `lea_rdi`. 

You can try to use `objdump` to disassemble some example binaries and see how the call to __libc_start_main is made, and design your detection algorithm accordingly. For example, you may notice that in a PIE-binary (such as /bin/cat), the RDI is modified using LEA, and in a non-PIE binary (e.g., `~/lab04/stripped.bin`) the RDI is modified using MOV. Try to design your algorithm to work on non-PIE binary first and then extend it to cover PIE binary. 

For this task, in addition to `capstone.h`, you may find the header file `~/lab04/x86.h` useful.  This header file contains specific data structures for X86 instruction set architecture. 

Test your implementation on the binary `~/lab04/stripped.bin` (non-PIE) and `/bin/cat` (PIE). 

