
import struct
from dataclasses import dataclass
from io import BytesIO

from ..constants import DUMP_START_SIGNATURE, SYSTEM_GLOBALS_SIZE
from ..dump import CodeResourceRecord, RawCodeDump, SymbolNameRecord
from ..resource import ResourceFork, as_int16, get_code_resource_label, show_all_resource_types
from ..stream import (
    read_u16,
    to_u32,
    u16,
    u32,
    write_i16_as_u16,
    write_u16,
)

# THINK C libraries (not standalone apps) carry per-CODE-resource metadata in CREL, SYMS, JUMP,
# and NAME resources. NAME carries the full symbol names paired with the CODE resource by id.
# resources. (THE CREL format here is very different from the simple 2-byte format in application CRELs.)
# One entry in a CREL resource in a THINK C library.
@dataclass(frozen=True, repr=False)
class LibraryCodeRelocationEntry:
    unk1: int
    unk2: int
    offset_to_rewrite: int
    offset_from_rewrite_to_instruction_start: int
    symbol_id: int

    def __repr__(self) -> str:
        return (
            f"CREL unk0=0x{self.unk1:04X} unk1=0x{self.unk2:04X} "
            f"rewrite_offset=0x{self.offset_to_rewrite:04X} "
            f"instr_offset={self.offset_from_rewrite_to_instruction_start} "
            f"symbol_id=0x{self.symbol_id:08X}"
        )

# One entry in a SYMS resource in a THINK C library.
@dataclass(frozen=True, repr=False)
class SymbolTableEntry:
    id: int
    unk1: bytes
    type: int # 1 seems to be code, 0 seems to be data. Not sure what JUMP_offset means when applied to data though...
    jump_table_offset: int

    def __repr__(self) -> str:
        # Render the payload as ASCII, replacing non-printable bytes with dots, alongside its hex.
        printable_payload = "".join(
            chr(byte_value) if 32 <= byte_value < 127 else "." for byte_value in self.unk1
        )
        return (
            f"SYMS id={self.id:08X} type={self.type:04X} JUMP_offset={self.jump_table_offset:04X} "
            f"payload?={self.unk1.hex(' ')}  {printable_payload}"
        )

# A full symbol name recovered from a NAME resource, paired with the dumped address of the function it
# names. The pairing comes from the type-1 (code) SYMS entries, which correspond in id order to the
# NAME entries; each such SYMS entry resolves through the JUMP table to a segment offset.
@dataclass(frozen=True)
class RecoveredSymbol:
    start_address: int
    syms_index: int  # position of the paired SYMS entry in the id-sorted order, kept for debugging
    full_name: str

@dataclass(frozen=True)
class LibraryMetadata:
    symbol_table: dict[int, SymbolTableEntry]
    code_relocation_infos: list[LibraryCodeRelocationEntry]
    jump_target_offsets: list[int]
    recovered_symbols: list[RecoveredSymbol]

# SYMS entry type identifying a code symbol (as opposed to type 0, data). Only code symbols have a
# meaningful function address, and only they line up in order with the NAME resource entries.
SYMS_TYPE_CODE = 1

CREL_LIBRARY_RECORD = struct.Struct(">HHHhI")
SYMS_RECORD_START_OFFSET = 0xA
SYMS_RECORD_SIZE = 0xE

def parse_library_crel_record(crel_resource_data: bytes, record_offset: int) -> LibraryCodeRelocationEntry:
    (
        unknown_field_0,
        unknown_field_1,
        address_offset_to_rewrite,
        instruction_start_offset_from_previous,
        symbol_id,
    ) = CREL_LIBRARY_RECORD.unpack_from(crel_resource_data, record_offset)
    return LibraryCodeRelocationEntry(
        unknown_field_0,
        unknown_field_1,
        address_offset_to_rewrite,
        instruction_start_offset_from_previous,
        symbol_id,
    )

def parse_syms_record(syms_resource_data: bytes, record_offset: int) -> SymbolTableEntry:
    symbol_id = u32(syms_resource_data[record_offset:record_offset + 0x04])
    unknown_payload = syms_resource_data[record_offset + 0x04:record_offset + 0x0A]
    symbol_type = u16(syms_resource_data[record_offset + 0x0A:record_offset + 0x0C])
    jump_resource_offset = u16(syms_resource_data[record_offset + 0x0C:record_offset + 0x0E]) - 2
    return SymbolTableEntry(symbol_id, unknown_payload, symbol_type, jump_resource_offset)

def can_dump(resources: ResourceFork) -> bool:
    # There must be one of these for each CODE resource, but
    # we will enforce that later.
    required = (b"CODE", b"CREL", b"SYMS", b"JUMP", b"NAME")
    for resource_type in required:
        if resource_type not in resources:
            print(f"WARNING: Found no {resource_type.decode()} resources")
            return False

    return True

def dump_code(resources: ResourceFork) -> RawCodeDump | None:
    # THINK C libraries (built with, e.g., ) are dramatically different from applications (build with, e.g., )
    #  - Libraries have no standard Macintosh jumptable, and instead store relocation information in JUMP, NAME, SYMS,
    #    and CREL resources. (These CRELs are very different from CRELs for applications.)
    #  - CODE 0 is NOT a jumptable and can just be regular code, if it is present at all.
    #  - All CODEs do NOT have the 4-byte jumptable header; the code just starts immediately.
    code_resources = resources[b"CODE"]

    # Calculate the value of A5.
    # TODO: Figure out where A5 is actually supposed to be in libraries.
    BELOW_A5_SIZE = 0x10000
    a5 = BELOW_A5_SIZE + SYSTEM_GLOBALS_SIZE
    for code_resource in code_resources:
        # There is no jumptable metadata here so we will dump the whole resource.
        a5 += len(code_resources[code_resource])
    # STRS apparently come BEFORE A5.
    if b"STRS" in resources:
        a5 += len(resources[b"STRS"][0])

    # Create system globals (low memory).
    # The custom dump header will be prefixed before this raw memory image.
    dump = BytesIO()
    header = DUMP_START_SIGNATURE  # put garbage so address 0 isn't recognized as a string
    system_globals_memory = bytearray(header + bytes(SYSTEM_GLOBALS_SIZE - len(header)))
    # This app's A5 is stored in system global CurrentA5 (low memory 0x904).
    # TODO: Determine location of A5 for libraries. Currently we'll just initialize it to 0.
    system_globals_memory[0x904:0x908] = to_u32(a5)
    dump.write(system_globals_memory)

    # Dump all code segments.
    library_metadata_by_code_resource = {}
    segment_bases = {}
    code_resource_records = []
    for code_resource_id in code_resources:
        segment_id = BytesIO(bytes(code_resources[code_resource_id]))
        segment_data = BytesIO(segment_id.read())
        segment_base = dump.tell()
        segment_bases[code_resource_id] = segment_base

        library_metadata = parse_library_metadata(resources, code_resource_id, segment_base)
        library_metadata_by_code_resource[code_resource_id] = library_metadata
        apply_library_relocations(segment_data, code_resource_id, segment_base, library_metadata)

        # Save the relocated code.
        segment_bytes = segment_data.getvalue()
        code_resource_records.append(
            CodeResourceRecord(
                get_code_resource_label(code_resource_id, code_resources[code_resource_id]),
                segment_base,
                segment_base + len(segment_bytes),
        ))
        dump.write(segment_bytes)

    # Construct A5 world (application-level globals and jump table, SEPARATE from system globals).
    # A5 register points to the boundary between "below A5" and "above A5". In the actual dump, the
    # A5 world appears AFTER all the CODE resources.
    a5_world = BytesIO()
    a5_world.write(b"\x00" * 32) # TODO: Account for QuickDraw global vars.
    below_a5_data = bytes(BELOW_A5_SIZE)
    dump.write(below_a5_data)
    assert dump.tell() == a5
    dump.write(a5_world.getvalue())

    # Construct full symbol name records.
    symbol_name_records = []
    for code_resource_id in sorted(library_metadata_by_code_resource):
        library_metadata = library_metadata_by_code_resource[code_resource_id]
        for recovered_symbol in library_metadata.recovered_symbols:
            symbol_name_records.append(
                SymbolNameRecord(recovered_symbol.start_address, recovered_symbol.full_name))

    return RawCodeDump(dump.getvalue(), code_resource_records, symbol_name_records)

def has_library_metadata(resources: ResourceFork, code_resource_id: int) -> bool:
    return any(
        code_resource_id in resources.get(resource_type, {})
        for resource_type in (b"CREL", b"SYMS", b"JUMP", b"NAME")
    )

def resolve_jump_table_offset(jump_table_offset: int, jump_target_offsets: list[int]) -> str:
    """Describe where a symbol's JUMP-table offset points within its segment.

    A SYMS entry records an offset into the JUMP table rather than a location. Resolving it means
    reading the JUMP entry at that offset to recover the offset within this segment where the target
    function actually lives. Returns a human-readable summary, describing a broken link rather than
    raising, since this is used for debug output.
    """
    is_valid_jump_offset = jump_table_offset >= 0 and jump_table_offset % 2 == 0
    if not is_valid_jump_offset:
        return f"unresolved (invalid JUMP offset 0x{jump_table_offset:04X})"

    jump_entry_index = jump_table_offset // 2
    if jump_entry_index >= len(jump_target_offsets):
        return f"unresolved (JUMP offset 0x{jump_table_offset:04X} out of range)"

    target_segment_offset = jump_target_offsets[jump_entry_index]
    return f"JUMP[{jump_entry_index}] -> segment offset 0x{target_segment_offset:04X}"

def resolve_jump_table_offset_to_segment_offset(
    jump_table_offset: int, jump_target_offsets: list[int]
) -> int | None:
    """Resolve a SYMS entry's JUMP-table offset to the segment offset of the function it names.

    Returns None when the offset does not point at a valid JUMP-table entry, since our understanding of
    the format is still tentative and a caller pairing recovered names should skip the entry rather than
    abort. This mirrors the leniency of resolve_jump_table_offset, which describes such links instead of
    resolving them.
    """
    is_valid_jump_offset = jump_table_offset >= 0 and jump_table_offset % 2 == 0
    if not is_valid_jump_offset:
        return None
    jump_entry_index = jump_table_offset // 2
    if jump_entry_index >= len(jump_target_offsets):
        return None
    return jump_target_offsets[jump_entry_index]

def parse_library_metadata(
    resources: ResourceFork, code_resource_id: int, segment_base: int
) -> LibraryMetadata:
    # Parse the NAME resource, which carries the full symbol names. Every SYMS entry and CREL
    # relocation refers to its symbol by a byte offset into this resource (the offset to the name's
    # Pascal string in NAME). So we index NAME by that offset.
    name_by_offset = {}
    name_resource = resources.get(b"NAME", {}).get(code_resource_id)
    if name_resource is None:
        raise ValueError(f"Library must have NAME resource for CODE {code_resource_id}")
    name_resource_data = bytes(name_resource)
    name_stream = BytesIO(name_resource_data)
    while name_stream.tell() < len(name_resource_data):
        # An overall length is stored first, followed by the Pascal string with the actual name.
        # For example:
        # 00000000: 0010 0c52 4c45 426c 6f63 6b4d 6f76 6520  ...RLEBlockMove
        # 00000010: 2020 0014 1052 4c45 5365 7448 616e 646c    ...RLESetHandl
        record_length = read_u16(name_stream)
        record_end_offset = name_stream.tell() + record_length
        name_offset = name_stream.tell()  # offset of the Pascal length byte; this is the symbol id
        symbol_name_length = name_stream.read(1)[0]
        symbol_name_bytes = name_stream.read(symbol_name_length)
        name_by_offset[name_offset] = symbol_name_bytes.decode("ascii", errors="replace")
        # Skip the trailing space padding so the next record starts at the right place.
        name_stream.seek(record_end_offset)
    print(f"NAME {code_resource_id}:")
    for name_offset, symbol_name in name_by_offset.items():
        print(f"  @0x{name_offset:04X}: {symbol_name}")

    # Parse the JUMP resource, which lists the segment offset of each relocation target.
    jump_resource = resources.get(b"JUMP", {}).get(code_resource_id)
    if jump_resource is None:
        raise ValueError("Library must have JUMP resource for CODE {code_resource_id}")
    jump_target_offsets = []
    jump_resource_data = bytes(jump_resource)
    jump_stream = BytesIO(jump_resource_data)
    jump_entry_bytes = jump_stream.read(2)
    while jump_entry_bytes:
        if len(jump_entry_bytes) < 2:
            print(f"WARNING: Ignoring trailing byte in JUMP {code_resource_id}")
            break
        jump_target_offsets.append(u16(jump_entry_bytes))
        jump_entry_bytes = jump_stream.read(2)
    print(f"JUMP {code_resource_id}:")
    for entry_index, target_offset in enumerate(jump_target_offsets):
        print(f"  entry {entry_index}: 0x{target_offset:04X}")

    # Parse the SYMS resource, which indexes into the JUMP resource to give the offset to the function it concerns.
    symbol_table = {}
    syms_resource = resources.get(b"SYMS", {}).get(code_resource_id)
    if syms_resource is None:
        raise ValueError("Library must have SYMS resource for CODE {code_resource_id}")
    syms_resource_data = bytes(syms_resource)
    record_offset = 0
    while record_offset + SYMS_RECORD_SIZE <= len(syms_resource_data):
        entry = parse_syms_record(syms_resource_data, record_offset)
        symbol_table[entry.id] = entry
        record_offset += SYMS_RECORD_SIZE
    if record_offset != len(syms_resource_data):
        print(f"WARNING: Ignoring {len(syms_resource_data) - record_offset} trailing byte(s) in SYMS {code_resource_id}")
    print(f"SYMS {code_resource_id} sorted by symbol id:")
    for i, symbol_id in enumerate(sorted(symbol_table)):
        symbol_entry = symbol_table[symbol_id]
        resolved_target = resolve_jump_table_offset(symbol_entry.jump_table_offset, jump_target_offsets)
        print(f"  {i}: {symbol_entry!r} -> {resolved_target}")
        if name_resource is not None and symbol_id not in name_by_offset:
            print(f"    WARNING: SYMS id 0x{symbol_id:08X} does not point at the start of a NAME string")

    # Parse the CREL resource to know what needs to be relocated.
    code_relocation_infos = []
    crel_resource = resources.get(b"CREL", {}).get(code_resource_id)
    if crel_resource is None:
        raise ValueError("Library must have CREL resource for CODE {code_resource_id}")
    crel_resource_data = bytes(crel_resource)
    last_full_record_offset = len(crel_resource_data) - CREL_LIBRARY_RECORD.size
    for record_offset in range(0, last_full_record_offset + 1, CREL_LIBRARY_RECORD.size):
        code_relocation_infos.append(parse_library_crel_record(crel_resource_data, record_offset))
    parsed_crel_bytes = len(code_relocation_infos) * CREL_LIBRARY_RECORD.size
    if parsed_crel_bytes != len(crel_resource_data):
        print(f"WARNING: Ignoring {len(crel_resource_data) - parsed_crel_bytes} trailing byte(s) in CREL {code_resource_id}")
    print(f"CREL {code_resource_id}:")
    for relocation in code_relocation_infos:
        print(f"  {relocation!r}")
        if name_resource is not None and relocation.symbol_id not in name_by_offset:
            print(f"    WARNING: CREL symbol id 0x{relocation.symbol_id:08X} does not point at the start of a NAME string")

    # Recover each code symbol's real name and pair it with the address of the function it names.
    # A symbol's name is the NAME record whose Pascal-length byte sits at the byte offset given by the
    # symbol's id, and its function address comes from resolving its JUMP-table offset. Only type-1
    # (code) symbols name functions; type-0 (data) symbols are skipped. The MacsBug symbol stored inline
    # in the code is either this full name or, in the fixed-length format, just its first eight
    # characters, which is why we can recover the original name exactly rather than guess.
    recovered_symbols = []
    for syms_index, symbol_id in enumerate(sorted(symbol_table)):
        symbol_entry = symbol_table[symbol_id]
        if symbol_entry.type != SYMS_TYPE_CODE:
            continue
        full_symbol_name = name_by_offset.get(symbol_entry.id)
        if full_symbol_name is None:
            # The id doesn't land on a NAME string, so we have no name to place.
            # We've already warned about this.
            continue
        target_segment_offset = resolve_jump_table_offset_to_segment_offset(
            symbol_entry.jump_table_offset, jump_target_offsets)
        if target_segment_offset is None:
            # The symbol doesn't point at a valid JUMP entry, so we can't place its name.
            print(
                f"WARNING: CODE {code_resource_id}: skipping recovered name {full_symbol_name!r}; "
                f"SYMS[{syms_index}] (id 0x{symbol_entry.id:08X}) has unresolvable JUMP offset "
                f"0x{symbol_entry.jump_table_offset:04X}"
            )
            continue
        recovered_symbols.append(
            RecoveredSymbol(segment_base + target_segment_offset, syms_index, full_symbol_name))
    print(f"Recovered symbols for CODE {code_resource_id}:")
    for recovered_symbol in recovered_symbols:
        print(
            f"  SYMS[{recovered_symbol.syms_index}] 0x{recovered_symbol.start_address:08X}: "
            f"{recovered_symbol.full_name}")

    return LibraryMetadata(symbol_table, code_relocation_infos, jump_target_offsets, recovered_symbols)

def apply_library_relocations(segment_data: BytesIO, code_resource_id: int, segment_base: int, metadata: LibraryMetadata) -> None:
    # For CREL type -2 (JSR relocation), the JUMP entry seems to specify the absolute offset
    # in this segment where the JSR should go. Most of the relocation targets look like this before relocation:
    #   4EAD 0000                jsr        [A5 + 0x0]
    # For creating a static dump, we will rewrite the instruction AND offset to do a PC-relative jump. This seems
    # to work well enough.
    # We can't give a full 32-bit address because then we have to shift the code
    # since we only have 16 bits to work with. Since we don't have an A5 world created,
    # maybe we should rewrite the whole instruction as JSR (d16,PC)

    # If you know the absolute address T of the callee in your dumped image, and the JSR instruction starts at address I,
    # then the displacement you write is simply: d16 = T - (I + 2). M68k PC-relative addressing is relative to the
    # extension word address, not the address after the full instruction.
    # As long as that result fits in a signed 16-bit integer (−32768 to +32767), the rewritten instruction will call the
    # desired function without changing the size of the binary.
    # For CREL type -1 (likely a data relocation), the instructions take the form like the following:
    #   pea        (0x664,A5)
    # So we wan either force A5 to a specific value for each CODE resource OR rewrite the instruction to be relative like we do with
    # the JSR instructions. Though note that it can be PEA, LEA, or other ones too... so this can get confusing!
    segment_size = len(segment_data.getbuffer())
    for relocation in metadata.code_relocation_infos:
        relocation_type = relocation.offset_from_rewrite_to_instruction_start
        if relocation_type not in (-2, -1):
            print(
                f"WARNING: Skipping unsupported CREL relocation in CODE {code_resource_id}: "
                f"rewrite_offset=0x{relocation.offset_to_rewrite:04X}, "
                f"instr_offset={relocation_type}, "
                f"symbol_id=0x{relocation.symbol_id:08X}"
            )
            continue

        symbol_entry = metadata.symbol_table.get(relocation.symbol_id)
        if symbol_entry is None:
            print(f"WARNING: Skipping CREL relocation with unknown symbol id 0x{relocation.symbol_id:08X}")
            continue

        if symbol_entry.jump_table_offset < 0 or symbol_entry.jump_table_offset % 2 != 0:
            print(
                f"WARNING: Skipping CREL relocation with invalid JUMP offset "
                f"0x{symbol_entry.jump_table_offset:04X}"
            )
            continue

        jump_entry_index = symbol_entry.jump_table_offset // 2
        if jump_entry_index >= len(metadata.jump_target_offsets):
            print(
                f"WARNING: Skipping CREL relocation with out-of-range JUMP offset "
                f"0x{symbol_entry.jump_table_offset:04X}"
            )
            continue

        rewrite_offset = relocation.offset_to_rewrite
        if rewrite_offset < 0 or rewrite_offset + 2 > segment_size:
            print(
                f"WARNING: Skipping CREL relocation outside CODE {code_resource_id}: "
                f"rewrite_offset=0x{rewrite_offset:04X}"
            )
            continue

        target_segment_offset = metadata.jump_target_offsets[jump_entry_index]
        if relocation_type == -1:
            segment_data.seek(rewrite_offset)
            write_i16_as_u16(segment_data, target_segment_offset)
            print(
                f"LIB data patch seg {code_resource_id} offset {rewrite_offset:04x} "
                f"target {target_segment_offset:04x}"
            )
            continue

        instruction_start = rewrite_offset + relocation_type
        if instruction_start < 0 or instruction_start + 4 > segment_size:
            print(
                f"WARNING: Skipping CREL relocation outside CODE {code_resource_id}: "
                f"instruction_start=0x{instruction_start:04X}"
            )
            continue

        segment_data.seek(instruction_start)
        old_opcode = read_u16(segment_data)
        if old_opcode != 0x4EAD:
            print(
                f"WARNING: CODE {code_resource_id} relocation at 0x{instruction_start:04X} "
                f"expected JSR d16(A5) opcode 4EAD, found {old_opcode:04X}; patching anyway"
            )

        target_address = segment_base + target_segment_offset
        instruction_address = segment_base + instruction_start
        displacement = target_address - (instruction_address + 2)
        if not -0x8000 <= displacement <= 0x7FFF:
            print(
                f"WARNING: Skipping CREL relocation in CODE {code_resource_id}; "
                f"PC-relative displacement {displacement} does not fit in 16 bits"
            )
            continue

        segment_data.seek(instruction_start)
        write_u16(segment_data, 0x4EBA)
        segment_data.seek(rewrite_offset)
        write_i16_as_u16(segment_data, displacement)
        print(
            f"LIB patch seg {code_resource_id} instr {instruction_start:04x} "
            f"target {target_segment_offset:04x} (JSR d16(A5) -> JSR {displacement:+d}(PC))"
        )

