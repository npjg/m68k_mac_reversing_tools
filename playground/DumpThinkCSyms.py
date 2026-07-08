#!/usr/bin/env python3

import argparse
import struct

RECORD_START_OFFSET: int = 0xA
RECORD_SIZE: int = 0xE

# THINK C libraries (not standalone apps) have SYMS resources that appear to be encoded in some
# way. This script is to help with exploring this format.

def ascii_dump(data: bytes) -> str:
    return "".join(chr(byte_value) if 32 <= byte_value < 127 else "." for byte_value in data)

def parse(data: bytes) -> None:
    off: int = RECORD_START_OFFSET
    while off + RECORD_SIZE <= len(data):
        rec_start: int = off
        id_type: int = struct.unpack(">H", data[off:off + 2])[0]
        rec_id: int = struct.unpack(">H", data[off + 2:off + 4])[0]
        value: int = struct.unpack(">H", data[off + 4:off + 6])[0]
        payload: bytes = data[off + 6:off + RECORD_SIZE]
        print(
            f"@{rec_start:08X}: "
            f"{id_type:04X} "
            f"{rec_id:04X} "
            f"{value:04X} "
            f"\n{payload.hex(' ')}   {ascii_dump(payload)}"
        )
        off += RECORD_SIZE

def main() -> None:
    argument_parser: argparse.ArgumentParser = argparse.ArgumentParser()
    argument_parser.add_argument("filepaths", nargs="+", help="One or more SYMS files to inspect")
    parsed_arguments: argparse.Namespace = argument_parser.parse_args()

    for file_path in parsed_arguments.filepaths:
        print(file_path)
        with open(file_path, "rb") as file_handle:
            data: bytes = file_handle.read()
        parse(data)

if __name__ == "__main__":
    main()