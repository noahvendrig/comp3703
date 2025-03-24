First check elf header since its implied that the file is broken
```bash
user1@comp3703:~/assignment01$ readelf --wide broken_elf -h
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 fd 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            <unknown: fd>
  ABI Version:                       0
  Type:                              <unknown>: 36
  Machine:                           ARM
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          19136 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         30
  Section header string table index: 29
```

We can see issues in following fields: "OS/ABI", "Type", "Machine", "Entry Point Address". We should try to repair these first

we fix using hexedit
- change value at offset `0x07` from `0xFD` to `0x00` to set `OSABI` to `System V`
- change value at offset `0x10` from `0x36` to `0x02` to set `type` to `Executable File`
- change value at offset `0x12` from `0x28` to `0x3E` to set `machine` to `x86-64`

We note that entry point is `0x00` which is unusual.
to find the entry point we need to find address of `.text` section:
```bash
user1@comp3703:~/assignment01$ readelf --wide broken_elf -S | grep .text
  [14] .text             PROGBITS        00000000005260c0 0020c0 0007aa 00  AX  0   0 16
```
- change value at offset `0x18` from `00 00 00 00` to `c0 60 52 00` (little endian) to set `entry` to `0x005260c0`


By examining the program headers, we are interested in the segment containing `.text`. `.text` is located at `0x005260c0`, so we can see that the LOAD at virtual address `0x0000000000526000` is the section of interest. we can see it does not have execute permissions, only read (`R`).
```bash
user1@comp3703:~/assignment01$ readelf --wide -l broken_elf

Elf file type is EXEC (Executable file)
Entry point 0x5260c0
There are 13 program headers, starting at offset 64

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  PHDR           0x000040 0x0000000000524040 0x0000000000524040 0x0002d8 0x0002d8 R   0x8
  INTERP         0x000fa8 0x0000000000524fa8 0x0000000000524fa8 0x00001c 0x00001c R   0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x000000 0x0000000000524000 0x0000000000524000 0x001340 0x001340 R   0x1000
  LOAD           0x002000 0x0000000000526000 0x0000000000526000 0x000879 0x000879 R   0x1000
  LOAD           0x003000 0x0000000000527000 0x0000000000527000 0x00020c 0x00020c R   0x1000
  LOAD           0x003e10 0x0000000000528e10 0x0000000000528e10 0x0002f1 0x000370 RW  0x1000
  DYNAMIC        0x003e20 0x0000000000528e20 0x0000000000528e20 0x0001d0 0x0001d0 RW  0x8
  NOTE           0x000fc8 0x0000000000524fc8 0x0000000000524fc8 0x000020 0x000020 R   0x8
  NOTE           0x000fe8 0x0000000000524fe8 0x0000000000524fe8 0x000044 0x000044 R   0x4
  GNU_PROPERTY   0x000fc8 0x0000000000524fc8 0x0000000000524fc8 0x000020 0x000020 R   0x8
  GNU_EH_FRAME   0x003010 0x0000000000527010 0x0000000000527010 0x00006c 0x00006c R   0x4
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
  GNU_RELRO      0x003e10 0x0000000000528e10 0x0000000000528e10 0x0001f0 0x0001f0 R   0x1
```

To set this section to flag of `RE` (Read + Execute), 

We can see Program header table (PHDR) is located at `0x40`. the load instruction we're interested in is located at `0xE8`. We can see at `0xEC`, the flag is stored. Currently it is `0x04`, which is read. To change to read + execute, we change it to `0x04 + 0x01` (`0x01` represents execute) = `0x05`.

Now we can see we have successfully changed the flag to Read and Execute.
```bash
user1@comp3703:~/assignment01$ readelf -l broken_elf --wide

Elf file type is EXEC (Executable file)
Entry point 0x5260c0
There are 13 program headers, starting at offset 64

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  PHDR           0x000040 0x0000000000524040 0x0000000000524040 0x0002d8 0x0002d8 R   0x8
  INTERP         0x000fa8 0x0000000000524fa8 0x0000000000524fa8 0x00001c 0x00001c R   0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x000000 0x0000000000524000 0x0000000000524000 0x001340 0x001340 R   0x1000
  LOAD           0x002000 0x0000000000526000 0x0000000000526000 0x000879 0x000879 R E 0x1000
```

If we run the program, we can see the flag is successfully printed
```bash
user1@comp3703:~/assignment01$ ./broken_elf
flag{saucy-tint}
```