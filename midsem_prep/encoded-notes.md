user1@comp3703:~/midsem_q_pool$ readelf -S encoded
There are 29 section headers, starting at offset 0x3348:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align

  [25] .decodeme         PROGBITS         00000000004041f0  000031f0
       000000000000001d  0000000000000000  WA       0     0     16


user1@comp3703:~/midsem_q_pool$ objdump --wide encoded -sj .decodeme

encoded:     file format elf64-x86-64

Contents of section .decodeme:
 4041f0 5a6d7868 5a33746e 6247467a 63793130  ZmxhZ3tnbGFzcy10
 404200 636d4675 63325a6c 636e303d 00        cmFuc2Zlcn0=.   


user1@comp3703:~/midsem_q_pool$ echo "ZmxhZ3tnbGFzcy10cmFuc2Zlcn0=" | base64 -d
flag{glass-transfer}