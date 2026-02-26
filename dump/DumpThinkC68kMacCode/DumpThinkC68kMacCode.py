#!/usr/bin/env python3
from __future__ import annotations

import os
from mrcrowbar.lib.containers import mac
from mrcrowbar import utils

import machfs
import macresources

import argparse
import collections

ResourceFork = dict[bytes, dict[int, macresources.main.Resource]]

SYSTEM_RAM_SIZE = 0x10000
DUMMY_ADDR = 0xFFFFFFFF

# M68k is big endian.
u16 = utils.from_uint16_be
i16 = utils.from_int16_be
u32 = utils.from_uint32_be

to_u16 = utils.to_uint16_be
to_u32 = utils.to_uint32_be

def u16_to_i16(x: int) -> int:
    if x & 0x8000:
        x -= 0x10000
    return x

def get_file_from_volume(image_filepath: str, path_in_volume: list[str] | None) -> tuple[bytes, ResourceFork]:
    resources: ResourceFork = collections.defaultdict(dict)

    with open(image_filepath, "rb") as f:
        flat = f.read()
        volume = machfs.Volume()
        volume.read(flat)
        print(volume)
        if not path_in_volume:
            raise ValueError("HFS volume was provided without path!")
        for p in path_in_volume:
            volume = volume[p]
        for ax in macresources.parse_file(volume.rsrc):
            resources[ax.type][ax.id] = ax

        return volume.data, resources

def get_file_from_macbinary(filepath: str) -> tuple[bytes, ResourceFork]:
    f = open(filepath, 'rb').read()
    macbinary = mac.MacBinary(f)
    resources: ResourceFork = collections.defaultdict(dict)
    for i in macresources.parse_file(macbinary.resource):
        resources[i.type][i.id] = i

    return macbinary.data, resources

def dump_file(source_filepath: str, target_filepath: str, path: list[str] | None) -> None:
    print(f"dumping {':'.join([source_filepath]+(path if path else []))} to {target_filepath}")
    with open(source_filepath, "rb") as f:
        f.seek(122, os.SEEK_SET)
        is_likely_macbinary = (u16(f.read(2)) & 0xfcff) == 0x8081

        f.seek(0x400, os.SEEK_SET)
        is_likely_hfs_volume = f.read(2)

    if is_likely_hfs_volume == b"BD" or is_likely_hfs_volume == "H+":
        _, resources = get_file_from_volume(source_filepath, path)
    elif is_likely_macbinary:
        _, resources = get_file_from_macbinary(source_filepath)
    else:
        raise ValueError(f"File {source_filepath} must be a HFS disk image or MacBinary file")

    return dump_file_from_resources(resources, target_filepath)

def dump_file_from_resources(resources: ResourceFork, out_filename: str) -> None:
    for resource_type in resources:
        print(resource_type)
        for j, r in resources[resource_type].items():
            if r.name != None:
                print(f"    {j}: {r.name}")
            else:
                print(f"    {j}")

    if b"CODE" not in resources:
        print("Error: no executable code?")
        return

    # TODO: other resource types

    code_resources = resources[b"CODE"]
    crels = resources[b"CREL"]

    jumptable = code_resources[0]
    above_a5_size = u32(jumptable[:4])
    below_a5_size = u32(jumptable[4:8])
    jump_table_size = u32(jumptable[8:12])
    jump_table_offset = u32(jumptable[12:16])
    assert jump_table_size == len(jumptable) - 0x10
    assert jump_table_offset == 0x20

    a5 = below_a5_size + SYSTEM_RAM_SIZE
    for code_resource in code_resources:
        if code_resource == 0:
            continue
        a5 += len(code_resources[code_resource]) - 4
    if b"STRS" in resources:
        a5 += len(resources[b"STRS"][0])

    # CREATE THE HEADER.
    dump = b""
    header = (
        b"J\xffA\xffN\xffK\xff"  # put garbage so address 0 isn't recognized as a string
    )
    # small function to force binary ninja to set the value of a5 as a global reg
    # move.l #a5_value, a5
    # rts
    header += b"\x2a\x7c" + to_u32(a5) + b"\x4e\x75"

    # CREATE SYSTEM RAM.
    # The header goes at the very start of system RAM.
    # TODO: Can we write the header any better? Maybe by changing the system RAM in-place?
    system_ram = bytearray(header + bytes(SYSTEM_RAM_SIZE - len(header)))
    # The A5 world is hardcoded at this address.
    system_ram[0x904:0x908] = to_u32(a5)
    dump += system_ram

    # TODO: Why do we do this?
    if b"STRS" in resources:
        strs_base = len(dump)
        dump += resources[b"STRS"][0]

    # Dump all code segments AFTER A5 world. (A5 world hasn't been constructed yet.)
    segment_bases = {}
    for code_resource in code_resources:
        if code_resource == 0:
            continue

        segment_header = code_resources[code_resource][:4]
        segment_data = bytearray(code_resources[code_resource][4:])
        segment_bases[code_resource] = len(dump)
        first_jumptable_entry_offset = u16(segment_header[:2])

        needs_relocations = False
        if first_jumptable_entry_offset & 0x8000:
            first_jumptable_entry_offset &= ~0x8000
            needs_relocations = True

        jumptable_entry_num = u16(segment_header[2:])
        far_header = False
        if jumptable_entry_num & 0x8000:
            jumptable_entry_num &= ~0x8000
            far_header = True

        print(
            f"code segment {code_resource}: first offset {first_jumptable_entry_offset:04x}, {jumptable_entry_num} jumptable entries",
            end="",
        )
        if needs_relocations:
            print(", reloc", end="")
        if far_header:
            print(", far", end="")
        print()

        # Perform THINK C (Symantec) relocations.
        # CodeWarrior relocations are very different and require a different dumper.
        if needs_relocations and jumptable_entry_num > 0:
            # TODO: refactor
            for j in range(0, len(crels[code_resource]), 2):
                addr = u16(crels[code_resource][j : j + 2]) - 4  # -4 from header
                if addr & 0x1:
                    print("STRS patch ", end="")
                    base = strs_base
                    addr = addr & 0xFFFE
                else:
                    print("A5 patch ", end="")
                    base = a5
                data = u32(segment_data[addr : addr + 4])
                data2 = (data + base) & 0xFFFFFFFF
                segment_data[addr : addr + 4] = to_u32(data2)
                print(f"seg {code_resource} addr {addr:04x} ({data:08x} -> {data2:08x})")
        dump += bytes(segment_data)

    # Construct A5 world (here really just the jumptable).
    a5_world = b"\x00" * 32 # TODO: Account for QuickDraw global vars.
    for i in range(0x10, len(jumptable), 8):
        # Construct jumptable (all loaded jumptable entries).
        # See Inside Macintosh II-61 (The Segment Loader).
        entry = jumptable[i : i + 8]
        if entry[2:4] == b"\x3f\x3c":
            # Unloaded jumptable entry structure:
            #    XX XX: segment offset
            #    3f 3c XX XX: move.w SEGMENT_NUMBER, -(SP)
            #        pushes SEGMENT_NUMBER onto the stack for _LoadSeg trap
            #    a9 f0: _LoadSeg trap number
            segment_offset = u16(entry[:2])
            segment_num = u16(entry[4:6])
            if segment_num in segment_bases:
                addr = segment_bases[segment_num] + segment_offset
            else:
                print(f"WARNING: Code segment {segment_num} not found for jumptable entry {(i-0x10)//8}, replacing with dummy address")
                addr = DUMMY_ADDR

        elif entry[2:4] == b"\x4e\xed":
            # TODO: Get a source for this.
            # Preloaded? jumptable entry structure:
            #    XX XX: ???
            #    4e ed XX XX: jmp OFFSET(a5)
            #    4e 71: nop
            offset = u16(entry[4:6])
            segment_num = 0  # dummy
            addr = offset + a5

        else:
            print(f"WARNING: Unknown format for jumptable entry {(i-0x10)//8}, replacing with dummy address")
            segment_num = 0  # dummy
            addr = DUMMY_ADDR

        # Create a LOADED jumptable entry.
        a5_world += to_u16(segment_num)
        a5_world += b"\x4e\xf9"  # jmp
        a5_world += to_u32(addr)

    below_a5_data = bytes(below_a5_size)

    # Applying DATA in this way ONLY works for binaries that don't do custom loading and compression
    # of A5 world data (like CodeWarrior).
    if b"ZERO" in resources and b"DATA" in resources:
        data_rsrc = bytes(resources[b"DATA"][0])
        zero_rsrc = bytes(resources[b"ZERO"][0])
        total_data_size = len(data_rsrc)
        for i in range(0, len(zero_rsrc), 2):
            total_data_size += u16(zero_rsrc[i : i + 2])

        if total_data_size <= below_a5_size:
            print("Adding DATA below A5 world")
            below_a5_data = bytearray()
            zero_index = 0
            for i in range(0, len(data_rsrc), 2):
                below_a5_data += data_rsrc[i : i + 2]
                if u16(data_rsrc[i : i + 2]) == 0:
                    below_a5_data += bytes(u16(zero_rsrc[zero_index : zero_index + 2]))
                    zero_index += 2

            # TODO refactor
            drel_rsrc = bytes(resources[b"DREL"][0])
            i = 0
            while i < len(drel_rsrc):
                addr = i16(drel_rsrc[i : i + 2])
                if addr >= 0:
                    i += 2
                    addr = -u16(drel_rsrc[i : i + 2])
                if addr & 0x1:
                    print("STRS patch ", end="")
                    base = strs_base
                    addr = u16_to_i16(addr & 0xFFFE)
                else:
                    print("A5 patch ", end="")
                    base = a5
                addr += below_a5_size  # DREL relative to a5
                data = u32(below_a5_data[addr : addr + 4])
                data2 = (data + base) & 0xFFFFFFFF
                below_a5_data[addr : addr + 4] = to_u32(data2)
                print(f"data addr {addr:04x} ({data:08x} -> {data2:08x})")
                i += 2
            below_a5_data = bytes(below_a5_data) + bytes(
                below_a5_size - total_data_size
            )

    dump += below_a5_data
    assert len(dump) == a5
    dump += a5_world

    open(out_filename, "wb").write(dump)

def main():
    parser = argparse.ArgumentParser(description="Dump and preprocess M68K Macintosh code")
    parser.add_argument("source_filepath", help="Source file (disk image or MacBinary file)")
    parser.add_argument("dump_filepath")
    parser.add_argument("--path", help="For disk images, path in the image to read (e.g. \"dir1:dir2:file\")")
    args = parser.parse_args()

    path = args.path.split(":") if args.path else None
    dump_file(args.source_filepath, args.dump_filepath, path)

if __name__ == "__main__":
    main()
