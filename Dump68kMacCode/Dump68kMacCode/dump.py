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

@dataclass
class RawCodeDump:
    """A dumper's output."""

    image: bytes
    code_resource_records: list[CodeResourceRecord] = field(default_factory=list)

def build_dump_header(language_id: str, code_resource_records: list[CodeResourceRecord]) -> bytes:
    # Header format:
    #   signature: NEWJ, with garbage bytes so address 0 isn't recognized as a string.
    #   null-terminated ASCII language id naming the source compiler for auto-detection in Ghidra.
    #   uint32: file offset where the raw system RAM dump begins.
    #   uint32: count of CODE resource records that follow.
    #   records:
    #     null-terminated CODE resource label, e.g. "0 (Travel)" or just "1".
    #     uint32: CODE resource start address in system RAM address space.
    #     uint32: CODE resource end address in system RAM address space, exclusive.
    encoded_language_id = language_id.encode("ascii") + b"\x00"

    record_bytes = bytearray()
    for record in code_resource_records:
        encoded_label = record.label.encode("ascii", errors="replace").replace(b"\x00", b"?")
        record_bytes += encoded_label + b"\x00"
        record_bytes += record.start_address.to_bytes(4, "big")
        record_bytes += record.end_address.to_bytes(4, "big")

    header_size = len(DUMP_HEADER_SIGNATURE) + len(encoded_language_id) + 4 + 4 + len(record_bytes)
    return (
        DUMP_HEADER_SIGNATURE
        + encoded_language_id
        + header_size.to_bytes(4, "big")
        + len(code_resource_records).to_bytes(4, "big")
        + bytes(record_bytes)
    )
