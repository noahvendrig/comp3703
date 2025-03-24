
# A quick tutorial of pwnlib’s asm and disasm commands

Pwntools is a collection of python libraries that are useful for various tasks in reverse engineering and exploitation. One of the libraries is the pwnlib.asm, that can disassemble a wide range of machine code to their corresponding assembly code, and vice versa. 


# Converting assembly code to machine code

The `asm` command of pwnlib translates a given assembly program to machine code. To use this command, load the pwntools library (pwn). Here are some examples of encoding simple commands.


```python
>>> from pwn import *
>>> context.arch = 'amd64'
>>> asm('mov rax, rbx')
b'H\x89\xd8'
>>> asm('mov rax, rbx').hex()
'4889d8'
>>> asm('nop').hex()
'90'
>>> 
```

The command `context.arch = 'amd64'` sets the architecture to Intel x64 (64 bit). The `asm` command uses this information to determine which instruction set architecture to use. 

To translate an assembly command, simply pass the string containing the command to `asm`. The `asm` function returns bytes, which can be converted to hex strings using the `hex()` function, as the above example shows. This works for most assembly commands. However, for commands that use relative addressing, such as some variants jumps (short jumps, near jumps), this can be slightly trick and not well documented. Each of these jumps takes an operand, which is the offset of the target of the jump, relative to the address of the next instruction (i.e., content of the register RIP). A short jump requires a one byte operand (a signed 8-bit integer) and a near jump requires a 4-byte operand (signed 32-bit integer). 

Consider, for example, the following disassembly of an actual binary:

```
401240:       4c 89 f2                mov    rdx,r14
401243:       4c 89 ee                mov    rsi,r13
401246:       44 89 e7                mov    edi,r12d
401249:       41 ff 14 df             call   QWORD PTR [r15+rbx*8]
40124d:       48 83 c3 01             add    rbx,0x1
401251:       48 39 dd                cmp    rbp,rbx
401254:       75 ea                   jne    401240
```

Notice that the instruction at 0x401254 (`jne 401240`) is given an opcode 75, followed by one byte. This is a short conditional jump, which specifies the target of the jump via an offset 0xEA, from the next instruction. Now the offset 0xEA is actually a signed integer, so it is actually -22, in a little endian architecture. You can use python to confirm this in python: 

```python
>>> int.from_bytes(b'\xea', byteorder='little', signed=True)
-22
```

So the target of the jump is (RIP – 22). Since the jne instruction is located at 0x401254, and the length of the instruction (0x75ea) is two bytes, it follows that RIP at this point of the code would be 

```
RIP = 0x401254+2 = 0x401256.
```

The target of the jump is therefore `RIP-22 =  0x401240`. 

However, if you run `asm` to encode `jne 401240`, you would get an error message. 

```python
>>> asm('jne 0x401240')
[ERROR] Shellcode contains relocations:
    Relocation section '.rela.shellcode' at offset 0xa0 contains 1 entry:
      Offset          Info           Type           Sym. Value    Sym. Name + Addend
    000000000002  000000000002 R_X86_64_PC32                        40123c
[ERROR] An error occurred while assembling:
       1: .section .shellcode,"awx"
       2: .global _start
...
```

You should, instead, tell asm that the jump target should be relative to RIP.  In pwnlib, we can use the symbol `$` to access the address of the current instruction, so RIP can be obtained by “$+length”, where “length” is the length of the instruction we want to encode. So if we want encode a short jne (length = 2 byte), and set the target at offset -22 (0xea) from RIP (and therefore it is at offset -20 from the current instruction), we run:  

```python
>>> asm('jne ($-20)')
b'u\xea'
```

# Converting machine code to assembly

To convert machine code to assembly, we use the “disasm” command. Here are some simple examples:

```python
>>> disasm(b'\x4c\x89\xf2')
'   0:   4c 89 f2                mov    rdx, r14'
>>> print(disasm(b'\x4c\x89\xf2'))
   0:   4c 89 f2                mov    rdx, r14
>>> print(disasm(bytes.fromhex('41 55 49 89 f5')))
   0:   41 55                   push   r13
   2:   49 89 f5                mov    r13, rsi
```

Notice that disasm takes a sequence of bytes as input and returns a string. It can disassemble multiple commands, and the output would be separated by newlines, so to get a nicely formatted layout, you probably want to pass the output to the print command. 

By default, disasm assumes that the machine code is loaded at address 0. You can change this by specifying the “vma” (virtual memory address) of the code. For example: 

```python
>>> print(disasm(bytes.fromhex('48 8d 2d f4 2b 00 00'), vma=0x40121d))
  40121d:       48 8d 2d f4 2b 00 00    lea    rbp, [rip+0x2bf4]        # 0x403e18
>>> 
```

Here is another example that shows the disassembly of a relative jump: 

```python
>>> print(disasm(bytes.fromhex('75 ea'), vma=0x401254))
  401254:       75 ea                   jne    0x401240
>>> 
```
