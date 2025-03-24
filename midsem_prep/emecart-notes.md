ghidra decompilation:
```c
undefined8 FUN_00401223(int param_1,long param_2)

{
  int __fd;
  int iVar1;
  undefined8 uVar2;
  int local_10;
  
  __fd = FUN_004010a0("/dev/null",1);
  printf("Watch me as I run.\n");
  if (param_1 < 2) {
    printf("Error: missing argument\n");
    uVar2 = 1;
  }
  else {
    iVar1 = strcmp(*(char **)(param_2 + 8),"ROY7HJX701YH");
    if (iVar1 == 0) {
      for (local_10 = 0; local_10 < DAT_004040f0; local_10 = local_10 + 1) {
        FUN_004011ec(local_10);
        write(__fd,&DAT_00404120,1);
      }
      uVar2 = 0;
    }
    else {
      uVar2 = 1;
    }
  }
  return uVar2;
}
```

we see "ROY7HJX701YH" is needed as a param
we also see that every iteration of the loop is writing to "/dev/null". lets try and capture whats getting sent to there during each iteration
`*0x4012d6` is location of the `write` in the loop
```bash
gef➤  break *0x4012d6
gef➤  r "ROY7HJX701YH"
gef➤  print *0x00404120
$2 = 0x66
gef➤  c
gef➤  print *0x00404120
... repeat this process of going to next iteration and reading the value at that mem address
0x6c
0x66
0x6c
0x61
0x67
0x7b
0x70
0x6c
0x61
0x69
0x6e
0x2d
0x67
0x75
0x74
0x74
0x65
0x72
0x7d
gef➤  c
Continuing.
[Inferior 1 (process 45766) exited normally]
```


hence we get: `66 6c 66 6c 61 67 7b 70 6c 61 69 6e 2d 67 75 74 74 65 72 7d`
converting this to ASCII output using xxd: 
```bash
user1@comp3703:~/midsem_q_pool$ echo -n "66 6c 66 6c 61 67 7b 70 6c 61 69 6e 2d 67 75 74 74 65 72 7d" | xxd -r -p
flflag{plain-gutter}
```
hence we have: `flag{plain-gutter}`