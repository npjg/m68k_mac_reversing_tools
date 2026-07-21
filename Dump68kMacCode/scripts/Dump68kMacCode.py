#!/usr/bin/env python3
"""Dump a 68k classic Mac OS application to a flat Ghidra image,
with relocations and such for supported compilers.
"""
from __future__ import annotations

import argparse

import DumpCodeWarrior
import DumpThinkC

# Maps the command-line dumper name to the routine that dumps that compiler runtime's output.
DUMPERS = {
    "codewarrior": DumpCodeWarrior.dump_file,
    "thinkc": DumpThinkC.dump_file,
}

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dump a 68k classic Mac OS application to a flat image for Ghidra."
    )
    parser.add_argument(
        "dumper",
        choices=sorted(DUMPERS),
        help="Compiler runtime that produced the application: CodeWarrior or THINK C",
    )
    parser.add_argument("source_filepath", help="Source file (disk image or MacBinary file)")
    parser.add_argument("output_filepath")
    parser.add_argument("--path", help='For disk images, path in the image to read (e.g. "dir1:dir2:file")')
    args = parser.parse_args()

    path = args.path.split(":") if args.path else None
    dump_file = DUMPERS[args.dumper]
    dump_file(args.source_filepath, args.output_filepath, path)

if __name__ == "__main__":
    main()
