#!/usr/bin/env python3
"""Dump a 68k classic Mac OS application to a flat Ghidra image,
with relocations and such for supported compilers.

Invoke from the project root as ``python -m Dump68kMacCode``.
"""
from __future__ import annotations

import argparse

from .compilers import codewarrior, thinkc

# Maps the command-line dumper name to the routine that dumps that compiler runtime's output.
DUMPERS = {
    "codewarrior": codewarrior.dump_file,
    "thinkc": thinkc.dump_file,
}

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m Dump68kMacCode",
        description="Dump a 68k classic Mac OS application to a flat image for Ghidra.",
    )
    parser.add_argument(
        "dumper",
        choices=sorted(DUMPERS),
        help="Compiler runtime that produced the application: CodeWarrior or THINK C",
    )
    parser.add_argument("source_filepath", help="Source file (disk image or MacBinary file)")
    parser.add_argument("output_filepath")
    parser.add_argument("--path-in-disk-image", '-p', help='For disk images, path in the image to read (e.g. "dir1:dir2:file")')
    args = parser.parse_args()

    path_in_disk_image = args.path_in_disk_image.split(":") if args.path_in_disk_image else None
    dump_file = DUMPERS[args.dumper]
    dump_file(args.source_filepath, args.output_filepath, path_in_disk_image)

if __name__ == "__main__":
    main()
