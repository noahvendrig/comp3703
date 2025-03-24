#!/bin/env python3

"""
ELFINS: a simple tool for ELF binary instrumentation
(c) Alwen Tiu, 2025
"""

import lief
import os
import argparse 
import subprocess 
import pwn 

ALIGN=0x1000


def load_files(tfile, pfile, shdr): 
    with open(tfile,'rb') as f: 
        raw_bytes = f.read()

    with open(pfile, 'rb') as f:
        payload = f.read()

    sz = len(raw_bytes)
    pad = ALIGN - sz%ALIGN
    offset = sz + pad

    # if no section header is required, append the payload 
    # to the binary directly
    if shdr == 'none':
        padded_payload = (b'\x00' * pad) + payload 
        raw_bytes = raw_bytes + padded_payload
        
    e = lief.parse(raw_bytes)

    return (e, payload, offset)

def update_segment_data(seg, va, offset, size): 
    seg.virtual_address = va + offset 
    seg.physical_address = va + offset 
    seg.physical_size = size 
    seg.virtual_size = size 
    seg.file_offset = offset
    seg.type = lief.ELF.Segment.TYPE.LOAD
    seg.flags = lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.X
    seg.alignment = ALIGN

def update_section_data(sec, sname, va, offset, size, content): 
    sec.file_offset = offset 
    sec.size=size 
    sec.virtual_address = va + offset 
    sec.name = sname
    sec.type = lief.ELF.Section.TYPE.PROGBITS 
    sec.alignment = 16
    sec.flags = lief.ELF.Section.FLAGS.EXECINSTR | lief.ELF.Section.FLAGS.ALLOC
    sec.content= memoryview(content)

def inject(tfile, pfile, va, sname, shdr, new_segment):
    (e, payload, offset) = load_files(tfile, pfile, shdr)

    payload_len = len(payload)

    seg = e.get(lief.ELF.Segment.TYPE.NOTE)
    if seg is None or new_segment:
        print("Creating a new segment for the injected code.")
        # The add() function updates the section header offset 
        # when a new program header is added, but we don't want that,
        # so revert back to its original offset after the program header 
        # is added
        original_shdr_offset = e.header.section_header_offset 
        seg = e.add(lief.ELF.Segment(), va)
        e.header.section_header_offset = original_shdr_offset
    else:
        print("Reusing a NOTE segment for the injected code.")  
    
    update_segment_data(seg, va, offset, payload_len)

    if shdr != 'none':
        if shdr == 'reuse':
            # hijack .gnu.hash section header for the injected code
            sec = e.get_section('.gnu.hash')
            if sec is None:
                print("Section header .gnu.hash not present")
            else:
                print(f"Reusing a section header (.gnu.hash) for {sname}")

        if shdr == 'new' or sec is None:
            # add a new section, but do not create a segment for it
            sec = e.add(lief.ELF.Section(sname),False)
            print(f"Creating a new section header for {sname}")

        update_section_data(sec, sname, va, offset, payload_len, payload)

    print(f'Code injected at offset: {hex(offset)}, virtual address {hex(seg.virtual_address)}. ')

    return (e, seg.virtual_address) 

def write_changes(e, ofile):
    e.write(ofile)
    subprocess.run(['chmod', '+x', ofile], check=True)
    print(f'Modified binary saved to {ofile}')

def patch_entry(e, va):
    e.header.entrypoint = va
    print(f'Patching entry point to {hex(va)}')        

def patch_got(e, va, fname):
    s = e.get_dynamic_symbol(fname)
    if s is None:
        print(f"There's no GOT entry for function {fname}.")
    else:
        print(f"Patching the GOT entry for {fname}.")
        e.patch_pltgot(s, va)

def patch_address(e, va, addr):
    seg = e.segment_from_virtual_address(addr)
    if seg is None:
        print(f"Address {hex(addr)} is not contained in any segment. Address not patched.")
        return
    if not(seg.has(lief.ELF.Segment.FLAGS.X)):
        print(f"Address {hex(addr)} is not executable.\nAddress not patched.")
        return 

    pwn.context.arch='amd64'
    s = f"jmp {va};"
    b = pwn.asm(s, addr)
    e.patch_address(addr, list(b))
    print(f"Address {hex(addr)} patched to jump to injected code.")

def main():
    parser = argparse.ArgumentParser(
        description='A simple tool for x86-64 ELF binary instrumentation'
        )
    parser.add_argument('target', help='name of the target binary to modify')
    parser.add_argument('payload', help='the binary containing the payload to inject')
    parser.add_argument('-a','--address', type=(lambda x: int(x,0)), dest='va', default=0x800000, 
                      help='memory address where the payload should be loaded to (default=0x800000)')
    parser.add_argument('-n','--name', dest='name', default='.injected', 
                      help='name of the injected section (default=".injected", no section created)')
    parser.add_argument('-o','--output', dest='outfile', default='injected.elf', 
                        help='output file name (default="injected.elf")' ) 
    parser.add_argument('-s','--shdr', dest='shdr', choices=['new', 'reuse', 'none'], default='new', 
                        help='Choose whether to create/reuse/omit section header for the injected code (default=new)')
    parser.add_argument('--newsegment', action='store_true', default=False, help='Create a new segment (default is to reuse a NOTE segment)')
    parser.add_argument('--patchentry', action='store_true', default=False, help='Patch the entry point to point to the injected code')
    parser.add_argument('--patchgot', dest='func_name', default='', help='Patch the GOT entry for the given function to point to the injected code')

    parser.add_argument('--patchaddress', type=(lambda x: int(x,0)), dest='paddr', default=0x00, help='Patch the instruction at the given address to jump to the injected code')

    args=parser.parse_args()

    (e, va) = inject(args.target, args.payload, args.va, args.name, args.shdr, args.newsegment)

    if args.patchentry:
        patch_entry(e, va)
    
    if args.func_name != '': 
        patch_got(e, va, args.func_name)

    if args.paddr != 0x00: 
        patch_address(e, va, args.paddr)

    write_changes(e, args.outfile)

if __name__ == '__main__':
    main()
