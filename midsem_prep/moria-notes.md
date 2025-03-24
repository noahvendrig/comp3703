in ghidra decompilation, we see that in main, `check_password` is called.
```c
undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  int local_38;
  char local_31 [9];
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  printf("%s",msg);
  printf("\n\nSpeak Friend and Enter > ");
  fgets(local_28,0x10,stdin);
  for (local_38 = 0; local_38 < 6; local_38 = local_38 + 1) {
    iVar1 = toupper((int)local_28[local_38]);
    local_31[local_38] = (char)iVar1;
  }
  check_password(local_31);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

lets investigate `check_password`
```c
void check_password(char *param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  undefined8 local_58;
  undefined8 local_50;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_58 = 0;
  local_50 = 0;
  param_1[6] = '\0';
  strcpy((char *)&local_58,param_1);
  strcat((char *)&local_58,"HWJP");
  iVar1 = strcmp(param_1,"MELLON");
  if (iVar1 == 0) {
    printf(
          "\nIt was like a great shadow, in the middle of which was\na dark form, of man-shape maybe , yet greater; and\na power and terror seemed to be in it and to go before it.\n"
          );
    printf(" -- The Lord of the Rings, The Bridge of Khazad-Dum \n");
    printf("\nYou have unleashed a Balrog!\n");
    dump((EVP_PKEY_CTX *)&local_58);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

We can see that the password is `MELLON`, so we will enter that when the program is run
We notice that after doing this, a file called `balrog is created`.
It looks like base64, so we decrypt it and save it to file `output`.
```bash
base64 -d balrog > output
```

now looking at output, we see it has a weird header, but the rest of the data looks like ELF file:
```bash
user1@comp3703:~/midsem_q_pool$ xxd output | head -n 4
00000000: 7f4f 5243 0201 0100 0000 0000 0000 0000  .ORC............
```

so lets set the magic bytes to that of an elf file: set first 4 bytes to `7f 45 4c 46`.
after `chmod+x output`, we can see it is a stripped ELF binary
```bash
user1@comp3703:~/midsem_q_pool$ file output
output: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f515266fc8789c3af1364e81b22435decf6bb9d5, for GNU/Linux 3.2.0, stripped
```

if we run this elf binary, we can see we need a password to proceed. 
lets examine ghidra decompilation. we see an important function

```c
    undefined8 FUN_004010b0(int param_1,long param_2)

{
  char *__s;
  void *pvVar1;
  long lVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  undefined8 local_38;
  undefined8 uStack_30;
  undefined4 local_28;
  undefined1 local_24;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_28 = 0xf0a5fa3f;
  local_24 = 0xf2;
  local_38 = 0xf7a0e0d7d1ad0f43;
  uStack_30 = 0xcb1bd847d811b834;
  pvVar1 = calloc(0x15,1);
  if (pvVar1 == (void *)0x0) {
    __fprintf_chk(stderr,1,"calloc error\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  __printf_chk(1,&DAT_00402012,s_,---._/_|_/_|_YOU_SHALL_NOT_PASS_004040a0);
  if (param_1 == 4) {
    __s = *(char **)(param_2 + 0x10);
    lVar1 = 0;
    while ((int)__s[lVar1] == (&DAT_00404080)[lVar1]) {
      lVar1 = lVar1 + 1;
      if (lVar1 == 8) {
        sVar2 = strlen(__s);
        FUN_00401440((long)__s,(long)&local_38,(long)pvVar1,(int)sVar2,0x15);
        __printf_chk(1,"Okay you may pass. Here\'s your flag: %s\n",pvVar1);
        if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
          return 0;
        }
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
    }
  }
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

we can see that the program expects 4 params (note the program name counts as the first).
We also note: `__s = *(char **)(param_2 + 0x10)`, which saves the third argument
We also see that the while loop takes values from DAT_00404080. in gdb we can inspect the values of this address:
```bash
gef➤  x/48bx 0x404080
0x404080:       0x47    0x00    0x00    0x00    0x49    0x00    0x00    0x00
0x404088:       0x46    0x00    0x00    0x00    0x31    0x00    0x00    0x00
0x404090:       0x35    0x00    0x00    0x00    0x4d    0x00    0x00    0x00
0x404098:       0x47    0x00    0x00    0x00    0x36    0x00    0x00    0x00
0x4040a0:       0x20    0x20    0x20    0x20    0x20    0x20    0x20    0x20
0x4040a8:       0x20    0x20    0x20    0x20    0x20    0x20    0x20    0x20
```

We can see that we get `47 49 46 31 35 4d 47 36` (hex):
```bash
echo "47 49 46 31 35 4d 47 36" | xxd -r -p
GIF15MG6
```
hence we get `"GIF15MG6"` in ASCII. This should be the third argument, when we test the program:
```bash
user1@comp3703:~/midsem_q_pool$ ./output 1 GIF15MG6 2
                        ,---.
                       /    |
                      /     |
YOU SHALL NOT PASS!! /      |
(Unless you have    /       |
the password)  ___,'        |
             <  -'          :
              `-.__..--'``-,_\_
                 |o/ ` :,.)_`>
                 :/ `     ||/)
                 (_.).__,-` |\ 
                 /( `.``   `| :
                 \'`-.)  `  ; ;
                 | `       /-<
                 |     `  /   `.
 ,-_-..____     /|  `    :__..-'\ 
/,'-.__\\  ``-./ :`      ;       \ 
`\ `\  `\\  \ :  (   `  /  ,   `. \ 
  \` \   \\   |  | `   :  :     .\ \ 
   \ `\_  ))  :  ;     |  |      ): : 
  (`-.-'\ ||  |\ \   ` ;  ;       | | 
   \-_   `;;._   ( `  /  /_       | | 
    `-.-.// ,'`-._\__/_,'         ; | 
       \:: :     /     `     ,   /  | 
        || |    (        ,' /   /   | 
Source: asciiart.eu                   
Okay you may pass. Here's your flag: flag{heartless-trill}
```
