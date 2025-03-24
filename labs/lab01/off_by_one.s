	.file	"off_by_one.c"
	.intel_syntax noprefix
	.text
	.section	.rodata
.LC0:
	.string	"Option 1"
.LC1:
	.string	"Option 2"
.LC2:
	.string	"You have two options: "
.LC3:
	.string	"[1] %s\n"
.LC4:
	.string	"[2] %s\n"
.LC5:
	.string	"Enter 1 or 2: "
.LC6:
	.string	"%d"
.LC7:
	.string	"So you have chosen: %s\n"
	.text
	.globl	main
	.type	main, @function
main:
	push	rbp
	mov	rbp, rsp
	sub	rsp, 32
	mov	QWORD PTR [rbp-16], OFFSET FLAT:.LC0
	mov	QWORD PTR [rbp-8], OFFSET FLAT:.LC1
	mov	edi, OFFSET FLAT:.LC2
	call	puts
	mov	rax, QWORD PTR [rbp-16]
	mov	rsi, rax
	mov	edi, OFFSET FLAT:.LC3
	mov	eax, 0
	call	printf
	mov	rax, QWORD PTR [rbp-8]
	mov	rsi, rax
	mov	edi, OFFSET FLAT:.LC4
	mov	eax, 0
	call	printf
	mov	edi, OFFSET FLAT:.LC5
	mov	eax, 0
	call	printf
	lea	rax, [rbp-20]
	mov	rsi, rax
	mov	edi, OFFSET FLAT:.LC6
	mov	eax, 0
	call	__isoc99_scanf
	mov	eax, DWORD PTR [rbp-20]
	test	eax, eax
	jle	.L2
	mov	eax, DWORD PTR [rbp-20]
	cmp	eax, 2
	jle	.L3
.L2:
	mov	eax, 0
	jmp	.L5
.L3:
	mov	eax, DWORD PTR [rbp-20]
	cdqe
	mov	rax, QWORD PTR [rbp-16+rax*8]
	mov	rsi, rax
	mov	edi, OFFSET FLAT:.LC7
	mov	eax, 0
	call	printf
	mov	eax, 0
.L5:
	leave
	ret
	.size	main, .-main
	.ident	"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"
	.section	.note.GNU-stack,"",@progbits
