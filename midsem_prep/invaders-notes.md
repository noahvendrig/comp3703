we see that this looks like base64 data. so lets decode it:
```bash
user1@comp3703:~/midsem_q_pool$ cat invaders.txt | base64 -d
```

maybe its a zip, so lets check first:
```bash
user1@comp3703:~/midsem_q_pool$ cat invaders.txt | base64 -d | gunzip
```

we see some output that resembles an elf file. now we know its a zip file, lets save the decoded base64 as a zip file
```bash
cat invaders.txt | base64 -d > payload.gz
```

now we unzip:
```bash
user1@comp3703:~/midsem_q_pool$ gunzip payload.gz
```

and set the payload file to executable:
```bash
chmod +x payload
```

Now we have an actual elf file, which we can try to repair:
```bash
user1@comp3703:~/midsem_q_pool$ readelf -h payload
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              <unknown>: 33
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          24168 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
```

we see that entry point address is `0x0` and the `Type` is `<unknown> 33`, which is suspicious. we should try to repair this.
We need to set the file type to `Executable`. We do this by setting value at `0x10` to `0x02`. We can see the incorrect value of `0x33` at addr `0x10`. 
we fix it using hexedit.
now we see:
```bash
user1@comp3703:~/midsem_q_pool$ readelf -h payload
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          24168 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
```

Now we need to fix the entry point
we will find the start of the `.text` setion, which is the same as the entry point:
```bash
user1@comp3703:~/midsem_q_pool$ readelf -S payload --wide
There are 31 section headers, starting at offset 0x5e68:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
...
  [15] .text             PROGBITS        0000000000401370 001370 0026c4 00  AX  0   0 16
```

Hence we will set entry point to `0x00401370`. In the elf header, this is located at `0x18`. To write this in little endian, we have `70 13 40 00`. We will fix it using hexedit.

Now running ./payload shows us the space invaders game. We played the game and got nothing
now inspecting the menu. i spammed some buttons and exited. the flag was printed. Oh turns out all i had to do with go to menu and then quit the game...
```
user1@comp3703:~/midsem_q_pool$ ./payload
Thanks for playing!
flag{espressivo-trust}
``` 
