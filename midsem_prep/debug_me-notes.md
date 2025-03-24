Call the main function with the arg "LIID2":
gdb --args debug_me "LIID2"


void unmask_flag(char *key_str)
{
  char *key_str_local;
  char flag [33];
  int i;
  
  for (i = 0; i < 0x21; i = i + 1) {
    flag[i] = '\0';
  }
  decrypt((EVP_PKEY_CTX *)key_str,(uchar *)ct,(size_t *)flag,(uchar *)0x8,(ulong)(uint)len);
  for (i = 0; i < 0x21; i = i + 1) {
    flag[i] = '#';
  }
  return;
}

set a breakpoint just after the decrypt function decrypts the flag (we set it at the start of for loop):
        004016ea 7e  ec           JLE        LAB_004016d8
break *0x4016ea

we also note:
```c
decrypt((EVP_PKEY_CTX *)key_str,(uchar *)ct,(size_t *)flag,(uchar *)0x8,(ulong)(uint)len)
```

we want to read the value at memory location of `flag`.
```
gef> print flag
$4 = "flag{fast-upside}", '\000' <repeats 15 times>
```