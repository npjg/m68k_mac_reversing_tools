# M68k Ghidra Mac Reversing Tools
**Advantage(s)**: Syscalls are functions (so xrefs work), nicer handling of thunks

**Disadvantage(s)**: Stack-based syscall arguments are ugly

1. Make a dump using one of the [dumpers](dump/) corresponding to your compiler.
2. Install the `M68kMacLanguage` Ghidra extension provided in this repo.

   1. Build the extension with `build.sh` in the extension directory.
   2. In the main Ghidra Project window (NOT CodeBrowser), go to:
      File > Configure > Install Extensions...
   3. Check the box next to 'M68kMacLanguage' and click OK.
   4. Restart Ghidra.

   Alternatively, you can use `quickInstall.sh` for a more development-friendly install.

3. Open the dump as processor `68000`, variant `Mac`, and the compiler of your choice.
4. Run the `RunAllM68kMacAnalysis.java` script (or its constituents).

# Dump Structure
The dumpers are conceptually very simple - they first create a low-memory region for Mac OS globals, then relocate and append the CODE resources (segments) sequentially, then construct the A5 world (app globals and jumptable).

```
    0x00000000  ┌─────────────────────────────────────┐
                │    LOW-MEMORY SYSTEM GLOBALS        │
                │  - M68k exception vectors (0x0-0x3FF)
                │  - Mac OS system globals, e.g.      │
                │    - Ticks (0x016A)                 │
                │    - CurrentA5 (0x0904)             │
                │    - ApplLimit (0x0130)             │
                │    - QuickDraw globals (0x800+)     │
                ├─────────────────────────────────────┤
                │              PADDING                │
                │  (Align CODE 1 at 0x10000)          │
    0x00010000  ├═════════════════════════════════════┤ ◄── System RAM ends
                │      CODE SEGMENT 1                 │
                ├─────────────────────────────────────┤
                │      CODE SEGMENT 2                 │
                ├─────────────────────────────────────┤
                │      CODE SEGMENT 3                 │
                ├─────────────────────────────────────┤
                │           ...                       │
                │  (More CODE segments)               │
                └─────────────────────────────────────┘
   A5 World     │      BELOW A5 DATA (App Globals)    │
                │  - DATA 0 resource                  │
                │  - Zero-init data (ZERO)            │
                │  - Relocations applied              │
             ═══╪═════════════════════════════════════╪═══ ◄── A5 register
                │      ABOVE A5 DATA (Jumptable)      │        points here
                │  - Entry 0: jmp CODE_1_func_0       │
                │  - Entry 1: jmp CODE_1_func_1       │
                │  - Entry 2: jmp CODE_2_func_0       │
                │  - ...                              │
                │  All entries now LOADED:            │
                │    0x4EF9 <absolute_address>        │
                └─────────────────────────────────────┘
```

# Resources
 - [RetroGhidra](https://github.com/hippietrail/RetroGhidra/tree/main) has a [resource fork loader](https://github.com/hippietrail/RetroGhidra/blob/main/src/main/java/retro/ClassicMacResourceForkLoader.java), but it does not construct the A5 world at all. This is a deal-breaker for code that relies heavily on global data.

# VS Code Development
If you have these extensions installed:
* Extension Pack for Java (or at least Language Support for Java by Red Hat)
* Gradle for Java
then opening the folder should cause Gradle to import the project.

## TODO
* Finish creating properly typed functions for `_FP68K` routines
* Create properly typed functions for `_*Dispatch`, `_Pack*` routines
* Finish all syscalls
* Direct loader for Ghidra from binhex/derez
