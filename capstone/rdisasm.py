#!/usr/bin/env python3

# Basic Recursive disassembly using the Capstone library 
# (c) 2022-2025 Alwen Tiu
# This is adapted from the C++ version in D. Andriesse's "Practical Binary Analysis" book. 

from pwn import *
from capstone import *
from capstone.x86 import *
import queue 
import argparse 

DEBUG = False 

def debug(s):
    if DEBUG:
        print(s)


# checks whether a section contains a given address
def contains(section, addr):
    vma = section.header['sh_addr'] 
    size = section.header['sh_size']
    return (addr >= vma and (addr-vma) < size)

def bytes2str(arr):
    s = ''
    for i in range(len(arr)):
        s = s + ' ' + arr[i:i+1].hex()

    return s

def print_ins(cs_ins):
    print("%8x: %s\t%s\t%s" % (
        cs_ins.address, 
        "{0:<34}".format(bytes2str(cs_ins.bytes)), 
        cs_ins.mnemonic, cs_ins.op_str)
    )

def is_cs_cflow_group(g):
    return (g == CS_GRP_JUMP) or (g == CS_GRP_CALL) or (g == CS_GRP_RET) or (g == CS_GRP_IRET)

def is_cs_cflow_ins(ins):
    for g in ins.groups: 
        if is_cs_cflow_group(g):
            return True
    return False 

def is_cs_unconditional_cflow_ins(cs_ins):
    if cs_ins.id == X86_INS_JMP or cs_ins.id == X86_INS_LJMP or \
       cs_ins.id == X86_INS_RET or cs_ins.id == X86_INS_RETF or cs_ins.id == X86_INS_RETFQ:
        return True
    else:
        return False 

# calculate the effective address from a memory address formula;
# note: we ignore the segment register
# if the base register is not RIP, return 0 (invalid)
def calc_op_addr(ins, op):
    if op.type != X86_OP_MEM:
        return 0
    mem = op.mem 
    if mem.segment == X86_REG_INVALID and mem.base == X86_REG_RIP  and mem.index == X86_REG_INVALID:
        return (ins.address + ins.size + mem.disp) 

    return 0

# get the "immediate" target of a jump (target address is a constant)
def get_cs_ins_immediate_target(ins):
    for g in ins.groups:
        if is_cs_cflow_group(g):
            for i in ins.operands:
                if i.type == X86_OP_IMM:
                    return i.imm 
    return 0 

# attempt to calculate the target of a jump when the operand is not
# an "immediate", but is calculated using memory addressing formula
# [base + index*scale + disp]
# This only works when the base register is RIP, and index register
# is not used. 
def get_cs_ins_mem_target(ins):
    for g in ins.groups:
        if is_cs_cflow_group(g):
            for i in ins.operands:
                if i.type == X86_OP_MEM:
                    # print("Memory operand detected")
                    # print("Segment: %x" % i.mem.segment)
                    # print("Base:    %x" % i.mem.base)
                    # print("Index:   %x" % i.mem.index)
                    # print("Scale:   %x" % i.mem.scale)
                    # print("Disp.:   %x" % i.mem.disp)
                    addr = calc_op_addr(ins,i)
                    # print("Effective address: %x" % addr)
                    return addr 
    return 0 

# Get the immediate target if it exists. If not, try to calculate the target relative to RIP.  
def get_cs_ins_imm_or_mem_target(ins):
    addr = get_cs_ins_immediate_target(ins)
    if addr == 0:
        addr = get_cs_ins_mem_target(ins)
    return addr 

# checks if RDI is modified through MOV
def mov_rdi(ins):
    if ins.id == X86_INS_MOV:
        # print("MOV instruction detected")
        op1 = ins.operands[0]
        op2 = ins.operands[1]
        if op1.type == X86_OP_REG and op1.reg == X86_REG_RDI:
            # print("MOV RDI, %x" % op2.imm)
            return op2.imm 

    return 0

# checks if RDI is modified through LEA
def lea_rdi(ins):
    if ins.id == X86_INS_LEA:
        op1 = ins.operands[0]
        op2 = ins.operands[1]
        if op1.type == X86_OP_REG and op1.reg == X86_REG_RDI:
            if op2.type == X86_OP_MEM:
                return calc_op_addr(ins, op2) 
    return 0 

# checks if RDI is written either by MOV or LEA
def write_rdi(ins):
    a = mov_rdi(ins)
    if a == 0:
        a = lea_rdi(ins)
    return a 

def fname_from_address(bin, addr):
    for f in bin.functions:
        if addr == bin.functions[f].address:
            return f
        
    return ''

def disasm(bin): 
    # get the .text section
    text = bin.get_section_by_name('.text')

    # address of __libc_start_main
    libc_main_addr = bin.symbols['__libc_start_main']

    debug("__libc_start_main address: " + hex(libc_main_addr))

    # set the architecture
    dis = Cs(CS_ARCH_X86, CS_MODE_64)
    dis.detail = True 

    Q = queue.Queue()
    F = queue.Queue() 

    addr = bin.entry 
    if contains(text, addr):
        debug('entry point: 0x%16x' % addr)
        Q.put(addr)
    
    # add all functions in the .text section to the queue
    for f in bin.functions:
        sym_addr = bin.functions[f].address
        if contains(text, sym_addr):
            F.put(bin.functions[f])
            debug("function symbol: 0x%016x <%s> added" % (sym_addr, f))


    text_vma = text.header['sh_addr']
    text_size = text.header['sh_size']
    text_bytes = text.data()

    seen = dict() 

    while (not(Q.empty())):
        addr = Q.get()

        pc = addr - text_vma
        fname = fname_from_address(bin,addr)
        if fname != '' and not(addr in seen):
            print("%016x: <%s>:" % (addr, fname))  

        while(True):
            if addr in seen:
                debug("; ignoring addr 0x%016x (already seen)" % addr)
                break

            try:
                gen = dis.disasm(text_bytes[pc:], addr, count=1)
                cs_ins = next(gen)
                if (cs_ins.id == X86_INS_INVALID) or (cs_ins.size == 0):
                    break

                seen[cs_ins.address] = True
                print_ins(cs_ins)

                if is_cs_cflow_ins(cs_ins):
                    target = get_cs_ins_immediate_target(cs_ins)
                    
                    if target != 0 and not(target in seen) and contains(text, target):
                        Q.put(target)
                        debug("; -> new target: 0x%016x" % target)
                
                    if is_cs_unconditional_cflow_ins(cs_ins):
                        break
                elif cs_ins.id == X86_INS_HLT:
                    break 
                pc=pc+cs_ins.size 
                addr = addr + cs_ins.size 
            except StopIteration:
                break
        
        print("")

        if Q.empty():
            if not F.empty():
                f = F.get()
                Q.put(f.address)


def main(): 
    global DEBUG 

    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=str, help='path to input file')
    parser.add_argument('--debug', action='store_true', default=False, help='Show debugging information')
    args = parser.parse_args()

    DEBUG = args.debug 

    # open the ELF binary
    bin = ELF(args.file, checksec=False)

    disasm(bin)

    
if __name__ == '__main__':
    main()

