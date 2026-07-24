#!/usr/bin/env python3
"""Dump a 68k classic Mac OS application to a flat Ghidra image,
with relocations and such for supported compilers.

Invoke from the project root as ``python -m Dump68kMacCode``.
"""
from __future__ import annotations

import argparse

from .compilers import codewarrior, thinkc_lib, thinkc
from .dump import build_dump_header
from .resource import ResourceFork, read_resource_fork

DETECTORS = {
    "codewarrior": codewarrior.can_dump,
    "thinkc_lib": thinkc_lib.can_dump,
    "thinkc": thinkc.can_dump,
}

DUMPERS = {
    "codewarrior": codewarrior.dump_code,
    "thinkc_lib": thinkc_lib.dump_code,
    "thinkc": thinkc.dump_code,
}

# Maps the dumper name to the M68kMacLanguage Ghidra variant recorded in the dump header, so the
# loader can select the matching processor language automatically. THINK C uses the base variant.
GHIDRA_LANGUAGE_IDS = {
    "codewarrior": "codewarrior",
    "thinkc_lib": "default",
    "thinkc": "default",
}

def detect_dumper(resources: ResourceFork) -> str:
    """Choose which compiler runtime produced this binary."""
    for compiler_name, compiler_can_dump in DETECTORS.items():
        if compiler_can_dump(resources):
            return compiler_name

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m Dump68kMacCode",
        description="Dump a 68k classic Mac OS application to a flat image for Ghidra.",
    )
    parser.add_argument("source_filepath", help="Source file (HFS disk image or MacBinary file)")
    parser.add_argument("output_filepath")
    parser.add_argument(
        "--dumper", "-d",
        choices=sorted(DUMPERS),
        help="Force a compiler runtime instead of auto-detecting it",
    )
    parser.add_argument("--path-in-disk-image", '-p', help='For HFS disk images, path in the image to read (e.g. "dir1:dir2:file")')
    args = parser.parse_args()

    # Read the resource fork, then dump it to a raw memory image with the selected compiler runtime.
    # When the user hasn't forced a dumper, infer it from the fork's contents.
    path_in_disk_image = args.path_in_disk_image.split(":") if args.path_in_disk_image else None
    resources = read_resource_fork(args.source_filepath, path_in_disk_image)
    selected_dumper = args.dumper if args.dumper else detect_dumper(resources)
    print(f"Using {selected_dumper} dumper" + ("" if args.dumper else " (auto-detected)"))
    dump_from_resources = DUMPERS[selected_dumper]
    memory_dump = dump_from_resources(resources)
    if memory_dump is None:
        return  # The dumper already reported why.

    # Prepend the common dump header so Ghidra can locate each CODE segment within the flat image
    # and select the processor language variant matching the compiler runtime we used.
    dump_header = build_dump_header(
        GHIDRA_LANGUAGE_IDS[selected_dumper],
        memory_dump.code_resource_records,
        memory_dump.symbol_name_records,
    )
    with open(args.output_filepath, "wb") as output_file:
        output_file.write(dump_header + memory_dump.image)

if __name__ == "__main__":
    main()
