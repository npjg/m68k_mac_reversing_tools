#!/usr/bin/env python3
"""The dump image format shared by every compiler-specific dumper."""
from __future__ import annotations

from dataclasses import dataclass, field

# Signature placed at the very start of the header, with garbage bytes interleaved so the
# disassembler doesn't mistake it (or address 0 of the image) for a null-terminated string.
DUMP_HEADER_SIGNATURE = b"N\xffE\xffW\xffJ\xff"

@dataclass(frozen=True)
class CodeResourceRecord:
    """Where a single CODE resource landed within the dumped system-RAM image."""

    label: str  # human-readable segment label, e.g. "0 (Travel)" or just "1"
    start_address: int  # start offset in the system-RAM address space
    end_address: int  # end offset in the system-RAM address space, exclusive

@dataclass(frozen=True)
class SymbolNameRecord:
    """A full-length symbol name tied to the function it names. Some compilers only store fixed-length
    MacsBug symbols (8 chars max) alongside the code, but full names might be available elsewhere (e.g. NAMES
    resource in THINK C libraries). If these full names are available, we want to provide them to Ghidra.
    """

    start_address: int  # address of the named function within the dumped system-RAM image
    symbol_name: str  # full, real symbol name

@dataclass
class RawCodeDump:
    """A dumper's output."""

    image: bytes
    code_resource_records: list[CodeResourceRecord] = field(default_factory=list)
    symbol_name_records: list[SymbolNameRecord] = field(default_factory=list)

def build_dump_header(
    language_id: str,
    code_resource_records: list[CodeResourceRecord],
    symbol_name_records: list[SymbolNameRecord] | None = None,
) -> bytes:
    # Header format:
    #   signature: NEWJ, with garbage bytes so address 0 isn't recognized as a string.
    #   null-terminated ASCII language id naming the source compiler for auto-detection in Ghidra.
    #   uint32: file offset where the raw system RAM dump begins.
    #   uint32: count of CODE resource records that follow.
    #   CODE resource records:
    #     null-terminated CODE resource label, e.g. "0 (Travel)" or just "1".
    #     uint32: CODE resource start address in system RAM address space.
    #     uint32: CODE resource end address in system RAM address space, exclusive.
    #   uint32: count of symbol name records that follow.
    #   symbol name records (recovered THINK C symbols; see SymbolNameRecord):
    #     uint32: address of the named function within the dumped system-RAM image.
    #     null-terminated full symbol name.
    symbol_name_records = symbol_name_records or []
    encoded_language_id = language_id.encode("ascii") + b"\x00"

    code_resource_record_bytes = bytearray()
    for record in code_resource_records:
        encoded_label = record.label.encode("ascii", errors="replace").replace(b"\x00", b"?")
        code_resource_record_bytes += encoded_label + b"\x00"
        code_resource_record_bytes += record.start_address.to_bytes(4, "big")
        code_resource_record_bytes += record.end_address.to_bytes(4, "big")

    symbol_name_record_bytes = bytearray()
    for symbol_name_record in symbol_name_records:
        symbol_name_record_bytes += symbol_name_record.start_address.to_bytes(4, "big")
        encoded_symbol_name = (
            symbol_name_record.symbol_name.encode("ascii", errors="replace").replace(b"\x00", b"?")
        )
        symbol_name_record_bytes += encoded_symbol_name + b"\x00"

    header_size = (
        len(DUMP_HEADER_SIGNATURE)
        + len(encoded_language_id)
        + 4  # raw dump file offset
        + 4  # CODE resource record count
        + len(code_resource_record_bytes)
        + 4  # symbol name record count
        + len(symbol_name_record_bytes)
    )
    return (
        DUMP_HEADER_SIGNATURE
        + encoded_language_id
        + header_size.to_bytes(4, "big")
        + len(code_resource_records).to_bytes(4, "big")
        + bytes(code_resource_record_bytes)
        + len(symbol_name_records).to_bytes(4, "big")
        + bytes(symbol_name_record_bytes)
    )
