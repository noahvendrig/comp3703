#!/usr/bin/env python3

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>
from __future__ import print_function
from capstone import *
from capstone.x86 import *


X86_CODE64 = b"\x55\x48\x8b\x05\xb8\x13\x00\x00\xe9\xea\xbe\xad\xde\xff\x25\x23\x01\x00\x00\xe8\xdf\xbe\xad\xde\x74\xff"
X86_CODE16 = b"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6\x66\xe9\xb8\x00\x00\x00\x67\xff\xa0\x23\x01\x00\x00\x66\xe8\xcb\x00\x00\x00\x74\xfc"
X86_CODE32 = b"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6\xe9\xea\xbe\xad\xde\xff\xa0\x23\x01\x00\x00\xe8\xdf\xbe\xad\xde\x74\xff"

all_tests = (
        (CS_ARCH_X86, CS_MODE_16, X86_CODE16, "X86 16bit (Intel syntax)", None),
        (CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32 (AT&T syntax)", CS_OPT_SYNTAX_ATT),
        (CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32 (Intel syntax)", None),
        (CS_ARCH_X86, CS_MODE_64, X86_CODE64, "X86 64 (Intel syntax)", None),
        )


def get_eflag_name(eflag):
    if eflag == X86_EFLAGS_UNDEFINED_OF:
        return "UNDEF_OF"
    elif eflag == X86_EFLAGS_UNDEFINED_SF:
        return "UNDEF_SF"
    elif eflag == X86_EFLAGS_UNDEFINED_ZF:
        return "UNDEF_ZF"
    elif eflag == X86_EFLAGS_MODIFY_AF:
        return "MOD_AF"
    elif eflag == X86_EFLAGS_UNDEFINED_PF:
        return "UNDEF_PF"
    elif eflag == X86_EFLAGS_MODIFY_CF:
        return "MOD_CF"
    elif eflag == X86_EFLAGS_MODIFY_SF:
        return "MOD_SF"
    elif eflag == X86_EFLAGS_MODIFY_ZF:
        return "MOD_ZF"
    elif eflag == X86_EFLAGS_UNDEFINED_AF:
        return "UNDEF_AF"
    elif eflag == X86_EFLAGS_MODIFY_PF:
        return "MOD_PF"
    elif eflag == X86_EFLAGS_UNDEFINED_CF:
        return "UNDEF_CF"
    elif eflag == X86_EFLAGS_MODIFY_OF:
        return "MOD_OF"
    elif eflag == X86_EFLAGS_RESET_OF:
        return "RESET_OF"
    elif eflag == X86_EFLAGS_RESET_CF:
        return "RESET_CF"
    elif eflag == X86_EFLAGS_RESET_DF:
        return "RESET_DF"
    elif eflag == X86_EFLAGS_RESET_IF:
        return "RESET_IF"
    elif eflag == X86_EFLAGS_TEST_OF:
        return "TEST_OF"
    elif eflag == X86_EFLAGS_TEST_SF:
        return "TEST_SF"
    elif eflag == X86_EFLAGS_TEST_ZF:
        return "TEST_ZF"
    elif eflag == X86_EFLAGS_TEST_PF:
        return "TEST_PF"
    elif eflag == X86_EFLAGS_TEST_CF:
        return "TEST_CF"
    elif eflag == X86_EFLAGS_RESET_SF:
        return "RESET_SF"
    elif eflag == X86_EFLAGS_RESET_AF:
        return "RESET_AF"
    elif eflag == X86_EFLAGS_RESET_TF:
        return "RESET_TF"
    elif eflag == X86_EFLAGS_RESET_NT:
        return "RESET_NT"
    elif eflag == X86_EFLAGS_PRIOR_OF:
        return "PRIOR_OF"
    elif eflag == X86_EFLAGS_PRIOR_SF:
        return "PRIOR_SF"
    elif eflag == X86_EFLAGS_PRIOR_ZF:
        return "PRIOR_ZF"
    elif eflag == X86_EFLAGS_PRIOR_AF:
        return "PRIOR_AF"
    elif eflag == X86_EFLAGS_PRIOR_PF:
        return "PRIOR_PF"
    elif eflag == X86_EFLAGS_PRIOR_CF:
        return "PRIOR_CF"
    elif eflag == X86_EFLAGS_PRIOR_TF:
        return "PRIOR_TF"
    elif eflag == X86_EFLAGS_PRIOR_IF:
        return "PRIOR_IF"
    elif eflag == X86_EFLAGS_PRIOR_DF:
        return "PRIOR_DF"
    elif eflag == X86_EFLAGS_TEST_NT:
        return "TEST_NT"
    elif eflag == X86_EFLAGS_TEST_DF:
        return "TEST_DF"
    elif eflag == X86_EFLAGS_RESET_PF:
        return "RESET_PF"
    elif eflag == X86_EFLAGS_PRIOR_NT:
        return "PRIOR_NT"
    elif eflag == X86_EFLAGS_MODIFY_TF:
        return "MOD_TF"
    elif eflag == X86_EFLAGS_MODIFY_IF:
        return "MOD_IF"
    elif eflag == X86_EFLAGS_MODIFY_DF:
        return "MOD_DF"
    elif eflag == X86_EFLAGS_MODIFY_NT:
        return "MOD_NT"
    elif eflag == X86_EFLAGS_MODIFY_RF:
        return "MOD_RF"
    elif eflag == X86_EFLAGS_SET_CF:
        return "SET_CF"
    elif eflag == X86_EFLAGS_SET_DF:
        return "SET_DF"
    elif eflag == X86_EFLAGS_SET_IF:
        return "SET_IF"
    else: 
        return None


def print_insn_detail(mode, insn):
    def print_string_hex(comment, str):
        print(comment, end=' '),
        for c in str:
            print("0x%02x " % c, end=''),
        print()

    # print address, mnemonic and operands
    print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

    # "data" instruction generated by SKIPDATA option has no detail
    if insn.id == 0:
        return

    # print instruction prefix
    print_string_hex("\tPrefix:", insn.prefix)

    # print instruction's opcode
    print_string_hex("\tOpcode:", insn.opcode)

    # print operand's REX prefix (non-zero value is relavant for x86_64 instructions)
    print("\trex: 0x%x" % (insn.rex))

    # print operand's address size
    print("\taddr_size: %u" % (insn.addr_size))

    # print modRM byte
    print("\tmodrm: 0x%x" % (insn.modrm))

    # print modRM offset
    if insn.modrm_offset != 0:
        print("\tmodrm_offset: 0x%x" % (insn.modrm_offset))

    # print displacement value
    print("\tdisp: 0x%x" % (insn.disp))

    # print displacement offset (offset into instruction bytes)
    if insn.disp_offset != 0:
        print("\tdisp_offset: 0x%x" % (insn.disp_offset))

    # print displacement size
    if insn.disp_size != 0:
        print("\tdisp_size: 0x%x" % (insn.disp_size))

    # SIB is not available in 16-bit mode
    if (mode & CS_MODE_16 == 0):
        # print SIB byte
        print("\tsib: 0x%x" % (insn.sib))
        if (insn.sib):
            if insn.sib_base != 0:
                print("\t\tsib_base: %s" % (insn.reg_name(insn.sib_base)))
            if insn.sib_index != 0:
                print("\t\tsib_index: %s" % (insn.reg_name(insn.sib_index)))
            if insn.sib_scale != 0:
                print("\t\tsib_scale: %d" % (insn.sib_scale))

    # XOP CC type
    if insn.xop_cc != X86_XOP_CC_INVALID:
        print("\txop_cc: %u" % (insn.xop_cc))

    # SSE CC type
    if insn.sse_cc != X86_SSE_CC_INVALID:
        print("\tsse_cc: %u" % (insn.sse_cc))

    # AVX CC type
    if insn.avx_cc != X86_AVX_CC_INVALID:
        print("\tavx_cc: %u" % (insn.avx_cc))

    # AVX Suppress All Exception
    if insn.avx_sae:
        print("\tavx_sae: TRUE")

    # AVX Rounding Mode type
    if insn.avx_rm != X86_AVX_RM_INVALID:
        print("\tavx_rm: %u" % (insn.avx_rm))

    count = insn.op_count(X86_OP_IMM)
    if count > 0:
        print("\timm_count: %u" % count)
        for i in range(count):
            op = insn.op_find(X86_OP_IMM, i + 1)
            print("\t\timms[%u]: 0x%x" % (i + 1, (op.imm)))
            if insn.imm_offset != 0:
                print("\timm_offset: 0x%x" % (insn.imm_offset))
            if insn.imm_size != 0:
                print("\timm_size: 0x%x" % (insn.imm_size))

    if len(insn.operands) > 0:
        print("\top_count: %u" % len(insn.operands))
        c = -1
        for i in insn.operands:
            c += 1
            if i.type == X86_OP_REG:
                print("\t\toperands[%u].type: REG = %s" % (c, insn.reg_name(i.reg)))
            if i.type == X86_OP_IMM:
                print("\t\toperands[%u].type: IMM = 0x%x" % (c, (i.imm)))
            if i.type == X86_OP_MEM:
                print("\t\toperands[%u].type: MEM" % c)
                if i.mem.segment != 0:
                    print("\t\t\toperands[%u].mem.segment: REG = %s" % (c, insn.reg_name(i.mem.segment)))
                if i.mem.base != 0:
                    print("\t\t\toperands[%u].mem.base: REG = %s" % (c, insn.reg_name(i.mem.base)))
                if i.mem.index != 0:
                    print("\t\t\toperands[%u].mem.index: REG = %s" % (c, insn.reg_name(i.mem.index)))
                if i.mem.scale != 1:
                    print("\t\t\toperands[%u].mem.scale: %u" % (c, i.mem.scale))
                if i.mem.disp != 0:
                    print("\t\t\toperands[%u].mem.disp: 0x%x" % (c, (i.mem.disp)))

            # AVX broadcast type
            if i.avx_bcast != X86_AVX_BCAST_INVALID:
                print("\t\toperands[%u].avx_bcast: %u" % (c, i.avx_bcast))

            # AVX zero opmask {z}
            if i.avx_zero_opmask:
                print("\t\toperands[%u].avx_zero_opmask: TRUE" % (c))

            print("\t\toperands[%u].size: %u" % (c, i.size))

            if i.access == CS_AC_READ:
                print("\t\toperands[%u].access: READ\n" % (c))
            elif i.access == CS_AC_WRITE:
                print("\t\toperands[%u].access: WRITE\n" % (c))
            elif i.access == CS_AC_READ | CS_AC_WRITE:
                print("\t\toperands[%u].access: READ | WRITE\n" % (c))

    (regs_read, regs_write) = insn.regs_access()

    if len(regs_read) > 0:
        print("\tRegisters read:", end="")
        for r in regs_read:
            print(" %s" %(insn.reg_name(r)), end="")
        print("")

    if len(regs_write) > 0:
        print("\tRegisters modified:", end="")
        for r in regs_write:
            print(" %s" %(insn.reg_name(r)), end="")
        print("")
        
    if insn.eflags:
        updated_flags = []
        for i in range(0,46):
            if insn.eflags & (1 << i):
                updated_flags.append(get_eflag_name(1 << i))
        print("\tEFLAGS: %s" % (','.join(p for p in updated_flags)))
        

# ## Test class Cs
def test_class():

    for (arch, mode, code, comment, syntax) in all_tests:
        print("*" * 16)
        print("Platform: %s" % comment)
        print("Code: %s" % code.hex())
        print("Disasm:")

        try:
            md = Cs(arch, mode)
            md.detail = True

            if syntax is not None:
                md.syntax = syntax

            for insn in md.disasm(code, 0x1000):
                print_insn_detail(mode, insn)
                print ()
            print ("0x%x:\n" % (insn.address + insn.size))
        except CsError as e:
            print("ERROR: %s" % e)


if __name__ == '__main__':
    test_class()
