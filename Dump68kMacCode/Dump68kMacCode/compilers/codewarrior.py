#!/usr/bin/env python3
# Creates a Ghidra-loadable binary image of a CodeWarrior 68k classic Mac OS program.
# Currently, ONLY near-model programs are supported.
#
# Based on 68k assembly and lowlevel C from CodeWarrior Pro 1
# (MacOS Support:Libraries:Runtime:Runtime 68K:(Sources):Appl68KStartup.c):
# /* Project...: C++ and ANSI-C Compiler Environment			*/
# /* Name......: Startup.c						*/
# /* Purpose...: 68K application startup code example			*/
# /* Copyright.: Copyright (c) 1993-1997 Metrowerks, Inc.		*/
from __future__ import annotations

import sys

from ..constants import DUMP_START_SIGNATURE, SYSTEM_GLOBALS_SIZE
from ..dump import CodeResourceRecord, RawCodeDump
from ..resource import ResourceFork, as_int8, as_int16, as_int32, get_code_resource_label

# Helper functions to read and write big-endian integers, mirroring the C++ read_be*/write_be*.
# In C++ these took a `char *`; here they take a buffer plus an integer index into it.
def read_be32(buffer: bytes | bytearray, index: int) -> int:
    return (
        (buffer[index] << 24)
        | (buffer[index + 1] << 16)
        | (buffer[index + 2] << 8)
        | buffer[index + 3]
    )

def read_be16(buffer: bytes | bytearray, index: int) -> int:
    return (buffer[index] << 8) | buffer[index + 1]

def write_be32(buffer: bytearray, index: int, value: int) -> None:
    buffer[index] = (value >> 24) & 0xFF
    buffer[index + 1] = (value >> 16) & 0xFF
    buffer[index + 2] = (value >> 8) & 0xFF
    buffer[index + 3] = value & 0xFF

def write_be16(buffer: bytearray, index: int, value: int) -> None:
    buffer[index] = (value >> 8) & 0xFF
    buffer[index + 1] = value & 0xFF

# Load a CODE resource (segment) into memory and relocate it.
# (Interestingly, the original seems to totally override the system
#  _LoadSeg and never call it from inside the app.)
def __LoadSeg__(
    segment_number: int,
    code_resource: bytes | bytearray,
    code_size: int,
    a5_base: int,
    code_base: int,
    dump_image: bytearray,
    code_dest: int,
) -> int:
    # Parse segment header from CODE resource.
    # It seems that only CODE 2 and on have this header. CODE 1 has an abbreviated 4-byte header, which is one
    # of the reasons why it is loaded directly in __Startup__ and not by this function.
    print(f"\n*** __LoadSeg__: LOADING CODE {segment_number} ***")
    # From CodeWarrior's StartupLib.h SegmentHeader (all big-endian):
    jtsoffset: int = as_int16(read_be16(code_resource, 0))   # A5 relative offset of this segment's jump table (short)
    jtentries: int = as_int16(read_be16(code_resource, 2))   # number of entries in this segment's jump table
    # The original seems to only use the long version.
    jtloffset: int = as_int32(read_be32(code_resource, 4))   # A5 relative offset of this segment's jump table (long)
    xrefoffset: int = as_int32(read_be32(code_resource, 8))  # offset of xref data in this CODE resource
    print("Header:")
    print(f"  jtsoffset:   0x{jtsoffset & 0xFFFF:04x} ({jtsoffset})")
    print(f"  jtentries:   {jtentries}")
    print(f"  jtloffset:   0x{jtloffset & 0xFFFFFFFF:08x}")
    print(f"  xrefoffset:  0x{xrefoffset & 0xFFFFFFFF:08x}")

    # Append code to dump. Note that the header is INCLUDED as part of the dump.
    print(f"Copying CODE resource ({code_size} bytes) to 0x{code_base:x}")
    dump_image[code_dest:code_dest + code_size] = code_resource[:code_size]

    # Relocate this segment.
    xref_ptr: int = code_dest + xrefoffset
    print(f"Relocating CODE at 0x{code_base:x}")
    __relocate__(dump_image, xref_ptr, dump_image, code_dest, a5_base, code_base)

    # Update jump table entries to the loaded format. We need this because Ghidra needs to be able to resolve intersegment
    # references. As described at Classic 68K Runtime Architecture, "A call that goes through the jump table has the form
    #  JSR offset (A5)
    # where offset is the offset of the jump table entry for the routine from A5 plus 2 bytes." (Though note that the CodeWarrior
    # jumptable format does not require the added 2 bytes!)
    # We need to morph the unloaded jump table entry into its loaded form.

    # The jumptable is at A5 + jtloffset (using long version). jtloffset should never be negative, because "negative offsets
    # from A5 reference global variables, while positive offsets that are greater than 32 refer to jump-table entries."
    # dump_base is the start of the dump image (index 0), so a5_ptr is simply a5_base.
    a5_ptr: int = a5_base
    jumptable_ptr: int = a5_ptr + jtloffset
    print(f"Updating jump table: {jtentries} entries at offset 0x{jtloffset & 0xFFFFFFFF:08x}")

    # Read current (unloaded) jump table entry. Recall this is NOT the standard Mac jumptable format.
    # TODO: Also handle far model jump tables, where the unloaded segment format is different.
    LOADSEG_TRAP_NUMBER = 0xA9F0
    ABSOLUTE_LONG_JUMP_OPCODE = 0x4EF9
    for i in range(jtentries):
        # CodeWarrior JumpTableEntry (packed, 8 bytes):
        #   uint16 jumpinstruction @0, int32 jumpaddress @2, uint16 resourceId @6.
        # BEFORE (unloaded):
        #   entry.jumpinstruction = 0xA9F0  // _LoadSeg trap number
        #   entry.jumpaddress = offset      // offset from segment base
        #   entry.resourceId = N            // segment number
        entry: int = jumptable_ptr + i * 8
        old_instruction: int = read_be16(dump_image, entry + 0)
        if old_instruction != LOADSEG_TRAP_NUMBER:
            print(f"WARNING: Unexpected jump table instruction: {old_instruction:04x}")
        old_address: int = as_int32(read_be32(dump_image, entry + 2))
        segment: int = read_be16(dump_image, entry + 6)

        # Transform this to a loaded jumptable entry. Remember this is STILL the non-standard
        # CodeWarrior format!
        # AFTER (loaded):
        #   entry.jumpinstruction = 0x4EF9 (absolute long jump)
        #   entry.absolute_address = segmentBase + old_offset
        #   entry.segment = N (still there but unused when loaded)
        write_be16(dump_image, entry + 0, ABSOLUTE_LONG_JUMP_OPCODE)
        # Make segment base point to where this segment actually lives in our dump.
        # This is the immediate arg for the absolute jump, which is exactly what Ghidra needs.
        new_address: int = old_address + code_base
        write_be32(dump_image, entry + 2, new_address & 0xFFFFFFFF)
        # Segment number stays the same.
        write_be16(dump_image, entry + 6, segment)

        print(f"  Entry {i} (0x{segment:x}): 0x{old_address & 0xFFFFFFFF:08x} -> 0x{new_address & 0xFFFFFFFF:08x}")

    print(f"*** __LoadSeg__: CODE {segment_number} LOADED ***\n")
    return 0

def __Startup__(
    data0_resource: bytes | None,
    code_resources: list[tuple[int, bytes]],
    above_a5_size: int,
    below_a5_size: int,
) -> bytearray:
    # Calculate total size needed for all CODE resources.
    total_code_size: int = 0
    for _segment_id, code_resource_data in code_resources:
        total_code_size += len(code_resource_data)

    # Allocate zeroed memory for the entire dump (system globals + all CODE resources + A5 world, in that order).
    total_a5_world_size: int = below_a5_size + above_a5_size
    total_dump_size: int = SYSTEM_GLOBALS_SIZE + total_code_size + total_a5_world_size
    dump_image = bytearray(total_dump_size)

    # Create system globals (low memory).
    # Put garbage so address 0 isn't recognized as a string.
    dump_image[0:len(DUMP_START_SIGNATURE)] = DUMP_START_SIGNATURE

    # Calculate A5 position within the allocated memory. The A5 world sits after all the code, and A5 itself points
    # past the below-A5 region (application globals) to the boundary with the above-A5 region (jump table).
    a5_world_offset: int = SYSTEM_GLOBALS_SIZE + total_code_size
    a5_base: int = a5_world_offset + below_a5_size
    # This app's A5 is stored in global var CurrentA5 (low memory 0x904).
    write_be32(dump_image, 0x904, a5_base)

    # Initialize global data area from DATA 0 resource.
    if data0_resource is not None:
        # DATA 0 resource layout:
        # +---------------------------------+
        # | long:   offset of CODE 1 xrefs  |---+
        # +---------------------------------+   |
        # | char[]: compressed init data    |   |
        # +---------------------------------+   |
        # | char[]: compressed DATA 0 xrefs |   |
        # +---------------------------------+   |
        # | char[]: compressed CODE 1 xrefs |<--+
        # +---------------------------------+

        # Decompress initialization data into A5 world.
        init_data_ptr: int = 4  # Skip CODE 1 xrefs offset.
        xref_data_ptr: int = __decomp_data__(data0_resource, init_data_ptr, dump_image, a5_base)

        # Relocate DATA 0 (A5 world).
        print("\n*** __Startup__: RELOCATE DATA 0 (A5 world) ***")
        code1_base: int = SYSTEM_GLOBALS_SIZE  # CODE 1 always starts here
        xref_data_ptr = __relocate__(data0_resource, xref_data_ptr, dump_image, a5_base, a5_base, code1_base)

        # Load and relocate all CODE segments.
        # TODO: Is it true that we must have DATA 0 for this?
        current_code_offset: int = SYSTEM_GLOBALS_SIZE
        for segment_id, code_resource_data in code_resources:
            code_dest: int = current_code_offset

            if segment_id == 1:
                # CODE 1: Direct relocation.
                print(f"Copying CODE 1 ({len(code_resource_data)} bytes) to dump at offset 0x{current_code_offset:x}")
                dump_image[code_dest:code_dest + len(code_resource_data)] = code_resource_data

                print("\n*** __Startup__: RELOCATE CODE RESOURCE 1 ***")
                # Note: the xref (relocation) stream for CODE 1 lives in the DATA 0 resource.
                xref_data_ptr = __relocate__(data0_resource, xref_data_ptr, dump_image, code_dest, a5_base, code1_base)
            else:
                # CODE 2+: Use __LoadSeg__.
                result: int = __LoadSeg__(
                    segment_id, code_resource_data, len(code_resource_data),
                    a5_base, current_code_offset, dump_image, code_dest,
                )
                if result != 0:
                    return bytearray()

            current_code_offset += len(code_resource_data)

        print(f"A5 register: 0x{a5_base:x}")
        print(f"Below A5: 0x{below_a5_size:x} bytes")
        print(f"Above A5: 0x{above_a5_size:x} bytes")
        print(f"Total A5 world size: 0x{total_a5_world_size:x} bytes")
        print(f"Total CODE resources size: 0x{total_code_size:x} bytes ({len(code_resources)} segments)")
        print(f"CODE starts at: 0x{SYSTEM_GLOBALS_SIZE:x}")
        print(f"A5 world starts at: 0x{a5_world_offset:x}")
        print(f"Total dump size: 0x{total_dump_size:x} bytes")

    return dump_image

# ***************************************************************
# * Purpose..: Decompress the DATA resource			*
# * Input....: pointer to DATA resource data			*
# * Input....: pointer to A5 resource				*
# * Returns..: pointer to data after init data			*
# ***************************************************************
#
#	Pack Patterns:
#
#	0x1xxx xxxx: <raw data>		x+1 (1..128)	raw data bytes
#	0x01xx xxxx:			x+1 (1..64)		<x> 0x00 data bytes
#	0x001x xxxx: yyyy yyyy		x+2 (2..33)		<x> <y> data bytes
#	0x0001 xxxx:			x+1 (1..16)		<x> 0xFF data bytes
#	0x0000 0001:			pattern: 0x00000000FFFFXXXX
#	0x0000 0010:			pattern: 0x00000000FFXXXXXX
#	0x0000 0011:			pattern: 0xA9F00000XXXX00XX
#	0x0000 0100:			pattern: 0xA9F000XXXXXX00XX
#	0x0000 0000:	end of data
#
def __decomp_data__(ptr_buffer: bytes | bytearray, ptr: int, dump_image: bytearray, datasegment: int) -> int:
    for i in range(3):
        offset: int = as_int32(read_be32(ptr_buffer, ptr))
        ptr += 4
        to: int = datasegment + offset
        while True:
            data: int = ptr_buffer[ptr]; ptr += 1  # data = *ptr++
            if data & 0x80:
                # decompress (x&0x7f)+1 raw data bytes
                data &= 0x7F
                while True:  # do *to++=*ptr++; while(--data>=0)
                    dump_image[to] = ptr_buffer[ptr]; to += 1; ptr += 1
                    data -= 1
                    if data < 0:
                        break
                continue
            if data & 0x40:
                # decompress (x&0x3f)+1 0x00 data bytes (data is already initialized to 0x00)
                to += (data & 0x3F) + 1
                continue
            if data & 0x20:
                # decompress (x&0x1f)+2 repeating data bytes
                data = (data & 0x1F) + 1
                c: int = ptr_buffer[ptr]; ptr += 1
                # goto cloop
                while True:  # do *to++=c; while(--data>=0)
                    dump_image[to] = c; to += 1
                    data -= 1
                    if data < 0:
                        break
                continue
            if data & 0x10:
                # decompress (x&0x0f)+1 0xFF data bytes
                data &= 0x0F
                c = 0xFF
                # cloop:
                while True:  # do *to++=c; while(--data>=0)
                    dump_image[to] = c; to += 1
                    data -= 1
                    if data < 0:
                        break
                continue
            # switch(data): data is now in 0x00..0x0F
            if data == 0x00:
                break
            elif data == 0x01:  # pattern: 0x00000000FFFFXXXX
                to += 4
                dump_image[to] = 0xFF; to += 1
                dump_image[to] = 0xFF; to += 1
                dump_image[to] = ptr_buffer[ptr]; to += 1; ptr += 1
                dump_image[to] = ptr_buffer[ptr]; to += 1; ptr += 1
                continue
            elif data == 0x02:  # pattern: 0x00000000FFXXXXXX
                to += 4
                dump_image[to] = 0xFF; to += 1
                dump_image[to] = ptr_buffer[ptr]; to += 1; ptr += 1
                dump_image[to] = ptr_buffer[ptr]; to += 1; ptr += 1
                dump_image[to] = ptr_buffer[ptr]; to += 1; ptr += 1
                continue
            elif data == 0x03:  # pattern: 0xA9F00000XXXX00XX
                dump_image[to] = 0xA9; to += 1
                dump_image[to] = 0xF0; to += 1
                to += 2
                dump_image[to] = ptr_buffer[ptr]; to += 1; ptr += 1
                dump_image[to] = ptr_buffer[ptr]; to += 1; ptr += 1
                to += 1  # to++
                dump_image[to] = ptr_buffer[ptr]; to += 1; ptr += 1
                continue
            elif data == 0x04:  # pattern: 0xA9F000XXXXXX00XX
                dump_image[to] = 0xA9; to += 1
                dump_image[to] = 0xF0; to += 1
                to += 1  # to++
                dump_image[to] = ptr_buffer[ptr]; to += 1; ptr += 1
                dump_image[to] = ptr_buffer[ptr]; to += 1; ptr += 1
                dump_image[to] = ptr_buffer[ptr]; to += 1; ptr += 1
                to += 1  # to++
                dump_image[to] = ptr_buffer[ptr]; to += 1; ptr += 1
                continue
            else:
                sys.exit(15)
    return ptr

# ***************************************************************
# * Purpose..: Relocate code/data references of a segment	*
# * Input....: pointer to relocation data			*
# * Input....: pointer to segments base address			*
# * Input....: pointer to relocation base address		*
# * Returns..: pointer to end of relocation data		*
# ***************************************************************
def __reloc_compr__(
    ptr_buffer: bytes | bytearray,
    ptr: int,
    dump_image: bytearray,
    segment: int,
    relocbase: int,
    a5_base: int,
) -> int:
    relocations: int = read_be32(ptr_buffer, ptr)
    ptr += 4

    print(f"Relocating {relocations} references (base 0x{relocbase:x})")
    offset: int = 0
    while relocations > 0:
        c: int = ptr_buffer[ptr]; ptr += 1  # char c = *ptr++
        if c & 0x80:
            # 8-bit signed delta: c<<=1; offset+=c;
            offset += as_int8((c << 1) & 0xFF)
        else:
            if c & 0x40:
                # 15-bit unsigned delta
                word_val: int = as_int16(read_be16(ptr_buffer, ptr - 1))  # c is first byte, read second byte
                ptr += 1
                offset += as_int16((word_val << 2) & 0xFFFF) >> 1
            else:
                # direct signed 31-bit offset
                lword_val: int = as_int32(read_be32(ptr_buffer, ptr - 1))  # c is first byte, read remaining 3 bytes
                ptr += 3
                offset = as_int32((lword_val << 2) & 0xFFFFFFFF) >> 1

        # Get the current value before relocation (big-endian)
        position: int = segment + offset
        unrelocated_value: int = read_be32(dump_image, position)

        # Perform the relocation and write back in big-endian format
        relocated_value: int = (unrelocated_value + relocbase) & 0xFFFFFFFF
        write_be32(dump_image, position, relocated_value)

        # Log the relocation details
        print(
            f"  Offset 0x{offset & 0xFFFFFFFF:X} + 0x{a5_base:X} = 0x{(offset + a5_base) & 0xFFFFFFFF:X}: "
            f"0x{unrelocated_value:X} + 0x{relocbase:X} = 0x{relocated_value:X}"
        )
        relocations -= 1
    return ptr

# ***************************************************************
# * Purpose..: Relocate code/data references of segment		*
# * Input....: xref: pointer to xref data			*
# * Input....: segm: pointer to current segment			*
# * Input....: a5_base: base address for A5 world (DATA segment)	*
# * Input....: code1_base: base address of CODE segment 1	*
# * Returns..: pointer to data after xref			*
# ***************************************************************
def __relocate__(
    ptr_buffer: bytes | bytearray,
    xref: int,
    dump_image: bytearray,
    segm: int,
    a5_base: int,
    code1_base: int,
) -> int:
    ptr: int = xref

    print("Relocating references to A5 world (DATA 0)...")
    ptr = __reloc_compr__(ptr_buffer, ptr, dump_image, segm, a5_base, a5_base)

    print("Relocating references to CODE 1...")
    ptr = __reloc_compr__(ptr_buffer, ptr, dump_image, segm, code1_base, a5_base)

    # Relocate references to same CODE segment.
    print("Relocating internal references...")
    ptr = __reloc_compr__(ptr_buffer, ptr, dump_image, segm, segm, a5_base)

    return ptr

# region Resource loading
# CODE 1 must start with these instructions. This is a guard against creating a junk dump by trying
# to decompress and relocate stuff that isn't actually part of a CodeWarrior binary.
EXPECTED_CODE1_START = bytes([
    # NOTE: We are assuming that CODE 1 always has these jumptable fields, but this might not always be true.
    0x00, 0x00,                          # A5 relative offset of this resource's jump table
    0x00, 0x01,                          # number of entries in this resource's jump table

    0x9D, 0xCE,                          # sub.l A6, A6
    0x59, 0x8F,                          # subq.l A7, 4
    0x2F, 0x3C, 0x43, 0x4F, 0x44, 0x45,  # move.l -[A7], 0x434F4445 ('CODE')
    0x42, 0x67,                          # clr.w -[A7]
    0xA9, 0xA0,                          # syscall GetResource
])

def can_dump(resources: ResourceFork) -> bool:
    if b"CODE" not in resources:
        print("INFO: Can't dump because there are no CODE resources")
        return False

    code_resources_by_id = resources[b"CODE"]
    if 1 not in code_resources_by_id:
        return False

    # Detection keys off the distinctive startup preamble that CodeWarrior emits at the
    # very start of CODE 1.
    code1_data = bytes(code_resources_by_id[1])
    has_full_preamble = len(code1_data) >= len(EXPECTED_CODE1_START)
    return has_full_preamble and code1_data[:len(EXPECTED_CODE1_START)] == EXPECTED_CODE1_START

def dump_code(resources: ResourceFork) -> RawCodeDump | None:
    code_resources_by_id = resources[b"CODE"]

    # Parse jumptable header (big-endian) from CODE 0. The CodeWarrior startup only needs the A5
    # world sizes from here; it rebuilds the jump table from each CODE resource plus DATA 0.
    if 0 not in code_resources_by_id:
        print("ERROR: Cannot find CODE 0 resource (jumptable)")
        return None
    code0_resource = bytes(code_resources_by_id[0])
    above_a5_size: int = read_be32(code0_resource, 0)
    below_a5_size: int = read_be32(code0_resource, 4)
    jump_table_size: int = read_be32(code0_resource, 8)
    jump_table_offset: int = read_be32(code0_resource, 12)

    print("Jumptable info:")
    print(f"  Above A5 size: 0x{above_a5_size:x} ({above_a5_size} bytes)")
    print(f"  Below A5 size: 0x{below_a5_size:x} ({below_a5_size} bytes)")
    print(f"  Jump table size: 0x{jump_table_size:x} ({jump_table_size} bytes)")
    print(f"  Jump table offset: 0x{jump_table_offset:x}")

    # DATA 0 resource holds the compressed A5 world (init data plus the relocation streams).
    if b"DATA" not in resources or 0 not in resources[b"DATA"]:
        print("ERROR: Cannot find DATA 0 resource")
        return None
    data0_resource = bytes(resources[b"DATA"][0])

    # Collect CODE 1+ resources, sorted by id so the size accounting matches the original loader.
    code_resources: list[tuple[int, bytes]] = []
    for segment_id in sorted(code_resources_by_id):
        if segment_id == 0:
            continue
        code_resource_data = bytes(code_resources_by_id[segment_id])
        # An empty CODE resource is meaningless and would break the size accounting later.
        if len(code_resource_data) == 0:
            print(f"ERROR: CODE {segment_id} resource is empty")
            return None
        code_resources.append((segment_id, code_resource_data))

    # Now, actually dump all CODE resources.
    dump = __Startup__(data0_resource, code_resources, above_a5_size, below_a5_size)
    if len(dump) == 0:
        print("ERROR: Dumping failed")
        return None

    # Record where each CODE segment landed. __Startup__ lays the segments out consecutively,
    # in this same sorted order, starting right after the system globals; mirror that accounting.
    code_resource_records: list[CodeResourceRecord] = []
    segment_start_address = SYSTEM_GLOBALS_SIZE
    for segment_id, code_resource_data in code_resources:
        segment_end_address = segment_start_address + len(code_resource_data)
        code_resource_records.append(CodeResourceRecord(
            get_code_resource_label(segment_id, code_resources_by_id[segment_id]),
            segment_start_address,
            segment_end_address,
        ))
        segment_start_address = segment_end_address

    return RawCodeDump(bytes(dump), code_resource_records)
# endregion
