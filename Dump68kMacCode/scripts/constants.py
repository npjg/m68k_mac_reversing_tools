#!/usr/bin/env python3
"""Constants shared by the 68k Mac OS code dumpers (CodeWarrior and THINK C)."""
from __future__ import annotations

# As described in the readme, "system globals" in the dump is the low-memory region for 68k Mac OS
# system globals (NOT part of an A5 world for any application). Since applications can directly
# read/write these system globals for timing, memory info, etc., we need to be able to track these
# variables in Ghidra.
# Memory layout: [0x0-0x10000: System globals] [0x10000+: CODE segments] [after code: A5 world]
SYSTEM_GLOBALS_SIZE = 0x10000

# Placed at address 0 of every dump so the disassembler doesn't mistake low memory for a string.
DUMP_START_SIGNATURE = b"J\xffA\xffN\xffK\xff"
