# M68k Ghidra Mac Reversing Tools
**Advantage(s)**: Syscalls are functions (so xrefs work), nicer handling of thunks
**Disadvantage(s)**: Stack-based syscall arguments are ugly

1. Make a dump using one of the [dumpers](dump/) corresponding to your compiler.
2. Install the `M68kMacLanguage` Ghidra extension provided in this repo.
3. Open the dump as processor `68000`, variant `Mac`, and the compiler of your choice.
4. Run the `RunAllM68kMacAnalysis.java` script (or its constituents).

# Dump Structure
The dumpers are conceptually very simple - they first create a low-memory region for Mac OS globals, then construct an A5 world (and jump table within it), then relocate and append the CODE resources sequentially:

```
    0x00000000  ┌─────────────────────────────────────┐
                │    LOW-MEMORY SYSTEM GLOBALS        │
                │  - Magic bytes at address 0         │
                │  - M68k exception vectors (0x0-0x3FF)
                │  - Mac OS system globals:           │
                │    • Ticks (0x016A)                 │
                │    • CurrentA5 (0x0904)             │
                │    • ApplLimit (0x0130)             │
                │    • QuickDraw globals (0x800+)     │
                │    • Other system variables         │
                ├─────────────────────────────────────┤
                │              PADDING                │
                │  (Align A5 world at 0x10000)        │
    0x00010000  ├═════════════════════════════════════┤ ◄── System RAM ends (64 KB total)
                │                                     │
                │      BELOW A5 DATA                  │  below_a5_size bytes
                │   (Application Globals)             │
                │  - DATA 0 resource                  │
                │  - Zero-init data (ZERO)            │
                │  - Relocations applied              │
                │                                     │
    A5       ═══╪═════════════════════════════════════╪═══ ◄── A5 Register
                │                                     │           points here
                │      ABOVE A5 DATA                  │  above_a5_size bytes
                │   (Jump Table)                      │
                │  - Entry 0: jmp CODE_1_func_0       │
                │  - Entry 1: jmp CODE_1_func_1       │
                │  - Entry 2: jmp CODE_2_func_0       │
                │  - ...                              │
                │  All entries now LOADED:            │
                │    0x4EF9 <absolute_address>        │
                │                                     │
                ├─────────────────────────────────────┤
                │      CODE SEGMENT 1                 │  CODE 1 size
                │  (Main segment)                     │
                │  - Relocated code                   │
                │  - Function entry points            │
                ├─────────────────────────────────────┤
                │      CODE SEGMENT 2                 │  CODE 2 size
                │  (Additional code)                  │
                │  - Relocated code                   │
                ├─────────────────────────────────────┤
                │      CODE SEGMENT 3                 │  CODE 3 size
                │  (Additional code)                  │
                ├─────────────────────────────────────┤
                │           ...                       │
                │  (More CODE segments)               │
                └─────────────────────────────────────┘
```

# Installation Insructions
To install the Ghidra extension that includes the custom compiler definitions:
1. Build the extension with `build.sh` in the extension directory.
2. In the main Ghidra Project window (NOT CodeBrowser), go to:
   File > Configure > Install Extensions..."
3. Check the box next to 'M68kMacLanguage' and click OK
4. Restart Ghidra

After installation, you should be able to select 68000 (Mac) as the language when importing.

Currently, analysis scripts are still just Ghidra scripts, they are not proper analyzers. This is
to simplify development, but these SHOULD be actual analyzers later.

## TODO
* Finish creating properly typed functions for `_FP68K` routines
* Create properly typed functions for `_*Dispatch`, `_Pack*` routines
* Finish all syscalls
* Direct loader for Ghidra from binhex/derez
