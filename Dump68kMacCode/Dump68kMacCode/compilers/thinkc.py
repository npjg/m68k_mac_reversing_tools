#!/usr/bin/env python3
from __future__ import annotations

from io import BytesIO
from mrcrowbar import utils

from ..constants import DUMP_START_SIGNATURE, SYSTEM_GLOBALS_SIZE
from ..dump import CodeResourceRecord, RawCodeDump
from ..stream import ResourceFork, as_int16, get_code_resource_label

DUMMY_ADDR = 0xFFFFFFFF

# M68k is big endian.
u16 = utils.from_uint16_be
i16 = utils.from_int16_be
u32 = utils.from_uint32_be

to_u16 = utils.to_uint16_be
to_u32 = utils.to_uint32_be

# Stream helpers for reading/writing big-endian integers at the current position.
# These let us walk resources and build the dump sequentially instead of tracking
# manual byte offsets everywhere.
def read_u16(stream: BytesIO) -> int:
    return u16(stream.read(2))

def read_u32(stream: BytesIO) -> int:
    return u32(stream.read(4))

def write_u16(stream: BytesIO, value: int) -> None:
    stream.write(to_u16(value))

def write_u32(stream: BytesIO, value: int) -> None:
    stream.write(to_u32(value))

def dump_file_from_resources(resources: ResourceFork) -> RawCodeDump | None:
    # For debugging purposes, print all the resources we found.
    for resource_type in resources:
        print(resource_type)
        for j, r in resources[resource_type].items():
            if r.name != None:
                print(f"    {j}: {r.name}")
            else:
                print(f"    {j}")

    if b"CODE" not in resources:
        print("ERROR: Found no CODE resources")
        return None

    # TODO: other resource types
    code_resources = resources[b"CODE"]
    crels = resources[b"CREL"]

    # Parse the jumptable.
    # See "The Jump Table" in Mac OS Runtime Architectures - Chapter 10: Classic 68K Runtime Architectures.
    has_jumptable = False
    # This is a default in case we don't have a CODE 0.
    # It is NOT the same as SYSTEM_GLOBALS_SIZE.
    below_a5_size = 0x10000
    if code_resources.get(0):
        # Parse the jumptable header from CODE 0.
        code_resource_zero = BytesIO(bytes(code_resources[0]))
        above_a5_size = read_u32(code_resource_zero)
        below_a5_size = read_u32(code_resource_zero)
        jump_table_size = read_u32(code_resource_zero)
        jump_table_offset = read_u32(code_resource_zero)

        assert jump_table_size == len(code_resources[0]) - 0x10
        assert jump_table_offset == 0x20
        jumptable = BytesIO(code_resource_zero.read())
        has_jumptable = True
    else:
        print("WARNING: Didn't find CODE resource 0, assuming this is a library")

    # Calculate the value of A5.
    # TODO: This is a bit awkward because we are trying to predict the value of A5. Instead, restructure
    # this to be more explicitly a loader/linker. Specifically, separate out these functions:
    #  1. Assemble sections, each into its own buffer, without resolving cross-references. Keep the relocation
    #       tables (CREL/DREL) to one side.
    #  2. Link. Sizes are now known, so compute the base offsets, then apply every fix-up and concatenate.
    # A5 should then become len(system_globals) + len(strs) + len(code) + below_a5_size
    a5 = below_a5_size + SYSTEM_GLOBALS_SIZE
    for code_resource in code_resources:
        if code_resource == 0:
            continue
        # We have to subtract 4 because there are 2 shorts at the start of each CODE
        # resource that contain jumptable metadata; this metadata is not actually dumped.
        a5 += len(code_resources[code_resource]) - 4
    # STRS apparently come BEFORE A5.
    if b"STRS" in resources:
        a5 += len(resources[b"STRS"][0])

    # Create system globals (low memory).
    # The custom dump header will be prefixed before this raw memory image.
    dump = BytesIO()
    header = DUMP_START_SIGNATURE  # put garbage so address 0 isn't recognized as a string
    system_globals_memory = bytearray(header + bytes(SYSTEM_GLOBALS_SIZE - len(header)))
    # This app's A5 is stored in system global CurrentA5 (low memory 0x904).
    system_globals_memory[0x904:0x908] = to_u32(a5)
    dump.write(system_globals_memory)

    # Dump all STRS resources.
    if b"STRS" in resources:
        strs_base = dump.tell()
        dump.write(bytes(resources[b"STRS"][0]))

    # Dump all code segments. (A5 world hasn't been constructed yet.)
    segment_bases = {}
    code_resource_records = []
    for code_resource in code_resources:
        if code_resource == 0:
            continue

        segment_id = BytesIO(bytes(code_resources[code_resource]))
        first_jumptable_entry_offset = read_u16(segment_id)
        jumptable_entry_id = read_u16(segment_id)
        segment_data = BytesIO(segment_id.read())
        segment_base = dump.tell()
        segment_bases[code_resource] = segment_base

        needs_relocations = False
        if first_jumptable_entry_offset & 0x8000:
            first_jumptable_entry_offset &= ~0x8000
            needs_relocations = True

        is_far_header = False
        if jumptable_entry_id & 0x8000:
            jumptable_entry_id &= ~0x8000
            is_far_header = True

        print(
            f"code segment {code_resource}: first offset {first_jumptable_entry_offset:04x}, {jumptable_entry_id} jumptable entries",
            end="",
        )
        if needs_relocations:
            print(", reloc", end="")
        if is_far_header:
            print(", far", end="")
        print()

        # Perform THINK C (Symantec) relocations.
        # CodeWarrior relocations are very different and require a different dumper.
        if needs_relocations and jumptable_entry_id > 0:
            # TODO: refactor
            crel_stream = BytesIO(bytes(crels[code_resource]))
            crel_entry = crel_stream.read(2)
            while crel_entry:
                addr = u16(crel_entry) - 4  # -4 from header
                if addr & 0x1:
                    print("STRS patch ", end="")
                    base = strs_base
                    addr = addr & 0xFFFE
                else:
                    print("A5 patch ", end="")
                    base = a5
                segment_data.seek(addr)
                data = read_u32(segment_data)
                data2 = (data + base) & 0xFFFFFFFF
                segment_data.seek(addr)
                write_u32(segment_data, data2)
                print(f"seg {code_resource} addr {addr:04x} ({data:08x} -> {data2:08x})")
                crel_entry = crel_stream.read(2)

        segment_bytes = segment_data.getvalue()
        code_resource_records.append(CodeResourceRecord(
            get_code_resource_label(code_resource, code_resources[code_resource]),
            segment_base,
            segment_base + len(segment_bytes),
        ))
        dump.write(segment_bytes)

    # Construct A5 world (application-level globals and jump table, SEPARATE from system globals).
    # A5 register points to the boundary between "below A5" and "above A5". In the actual dump, the
    # A5 world appears AFTER all the CODE resources.
    a5_world = BytesIO()
    a5_world.write(b"\x00" * 32) # TODO: Account for QuickDraw global vars.
    if has_jumptable:
        JUMPTABLE_ENTRY_SIZE = 8
        entry_number = 0
        entry = jumptable.read(JUMPTABLE_ENTRY_SIZE)
        while entry:
            # Construct jumptable and make sure all jumptable entries are in
            # the "loaded" format in the dump. See Inside Macintosh II-61 (The Segment Loader).
            if entry[2:4] == b"\x3f\x3c":
                # This jumptable entry is stored unloaded.
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
                    print(f"WARNING: Code segment {segment_num} not found for jumptable entry {entry_number}, replacing with dummy address")
                    addr = DUMMY_ADDR

            elif entry[2:4] == b"\x4e\xed":
                # This jumptable entry is stored preloaded.
                # TODO: Get a source for this.
                # Preloaded? jumptable entry structure:
                #    XX XX: ???
                #    4e ed XX XX: jmp OFFSET(a5)
                #    4e 71: nop
                offset = u16(entry[4:6])
                segment_num = 0  # dummy
                addr = offset + a5

            else:
                print(f"WARNING: Unknown format for jumptable entry {entry_number}, replacing with dummy address")
                segment_num = 0  # dummy
                addr = DUMMY_ADDR

            # Always create a LOADED jumptable entry for our dump.
            print(f"Jumptable entry {entry_number}: CODE {segment_num} @ 0x{addr:0x}")
            write_u16(a5_world, segment_num)
            a5_world.write(b"\x4e\xf9")  # jmp
            write_u32(a5_world, addr)

            entry_number += 1
            entry = jumptable.read(JUMPTABLE_ENTRY_SIZE)

    below_a5_data = bytes(below_a5_size)

    # Put global data in the A5 world.
    # Applying DATA in this way ONLY works for binaries that don't do custom loading and compression
    # of A5 world data (like CodeWarrior).
    if b"ZERO" in resources and b"DATA" in resources:
        data_stream = BytesIO(bytes(resources[b"DATA"][0]))
        zero_stream = BytesIO(bytes(resources[b"ZERO"][0]))
        total_data_size = len(data_stream.getvalue())

        # ZERO holds the run lengths of the compressed-away zero regions in DATA.
        zero_run_length = zero_stream.read(2)
        while zero_run_length:
            total_data_size += u16(zero_run_length)
            zero_run_length = zero_stream.read(2)

        if total_data_size <= below_a5_size:
            print("Adding DATA below A5 world")

            # Decompress DATA into the below-A5 region: each zero word in DATA is
            # followed by a ZERO run length giving how many zero bytes to expand it to.
            below_a5_stream = BytesIO()
            zero_stream.seek(0)
            data_word = data_stream.read(2)
            while data_word:
                below_a5_stream.write(data_word)
                if u16(data_word) == 0:
                    below_a5_stream.write(bytes(read_u16(zero_stream)))
                data_word = data_stream.read(2)

            # TODO refactor
            drel_stream = BytesIO(bytes(resources[b"DREL"][0]))
            drel_entry = drel_stream.read(2)
            while drel_entry:
                addr = i16(drel_entry)
                if addr >= 0:
                    addr = -read_u16(drel_stream)
                if addr & 0x1:
                    print("STRS patch ", end="")
                    base = strs_base
                    addr = as_int16(addr & 0xFFFE)
                else:
                    print("A5 patch ", end="")
                    base = a5
                addr += below_a5_size  # DREL relative to a5
                below_a5_stream.seek(addr)
                data = read_u32(below_a5_stream)
                data2 = (data + base) & 0xFFFFFFFF
                below_a5_stream.seek(addr)
                write_u32(below_a5_stream, data2)
                print(f"data addr {addr:04x} ({data:08x} -> {data2:08x})")
                drel_entry = drel_stream.read(2)
            below_a5_data = below_a5_stream.getvalue() + bytes(
                below_a5_size - total_data_size
            )

    dump.write(below_a5_data)
    assert dump.tell() == a5
    dump.write(a5_world.getvalue())

    return RawCodeDump(dump.getvalue(), code_resource_records)
