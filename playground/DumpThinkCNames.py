#!/usr/bin/env python3

from __future__ import annotations

import argparse
import io
import struct
from typing import Sequence

UINT16_BE = struct.Struct(">H")

def to_ascii_preview(raw_bytes: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in raw_bytes)

def decode_name(raw_bytes: bytes) -> str:
    return raw_bytes.decode("ascii", errors="replace")

def parse_name_records(file_bytes: bytes, source_label: str, is_verbose: bool) -> None:
    stream = io.BytesIO(file_bytes)

    record_index = 0
    file_size = len(file_bytes)

    while stream.tell() < file_size:
        (record_length,) = UINT16_BE.unpack(stream.read(UINT16_BE.size))
        record_offset = stream.tell()
        record_end_offset = record_offset + record_length
        declared_name_length = stream.read(1)[0]
        name_bytes = stream.read(declared_name_length)
        trailing_padding_bytes = stream.read(record_end_offset - stream.tell())
        has_only_space_padding = all(byte == 0x20 for byte in trailing_padding_bytes)
        decoded_name = decode_name(name_bytes)

        if is_verbose:
            print(
                f"@0x{record_offset:08X} "
                f"rec=0x{record_index:02X} "
                f"len=0x{record_length:02X} "
                f"name_len=0x{declared_name_length:02X} "
                f"padding_len={len(trailing_padding_bytes):02X} "
                f"padding_ok={'yes' if has_only_space_padding else 'no'} "
                f"name={decoded_name} "
            )
        else:
            print(decoded_name)

        record_index += 1

def parse_arguments(argument_values: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse THINK C NAME resources"
    )
    parser.add_argument(
        "filepaths",
        nargs="+",
        help="Filepaths to dumped THINK C resource file(s)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed parsing information",
    )
    return parser.parse_args(argument_values)

def main() -> int:
    arguments = parse_arguments()

    for filepath in arguments.filepaths:
        with open(filepath, "rb") as source_file:
            if arguments.verbose:
                print(filepath)
            parse_name_records(source_file.read(), filepath, arguments.verbose)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())