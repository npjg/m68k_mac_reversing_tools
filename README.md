# M68k Mac Reversing Tools (Binary Ninja and Ghidra)

## Binary Ninja Instructions

**Advantage(s)**: Correct calling convention for syscalls, stack-based syscalls are nice

**Disadvantage(s)**: Thunks in the jumptable don't automatically update name/function prototype

1. Make a dump using [dump.py](dump.py).
2. Add [binary_ninja/loader](binary_ninja/loader) and [https://github.com/ubuntor/binaryninja-m68k](https://github.com/ubuntor/binaryninja-m68k) to Binary Ninja plugins.
3. Open the dump. The loader should run automatically and start disassembling.

## Ghidra Instructions

**Advantage(s)**: Syscalls are functions (so xrefs work), nicer handling of thunks

**Disadvantage(s)**: Stack-based syscall arguments are ugly

1. Make a dump using [dump.py](dump.py).
2. Put the files in [ghidra/processor](ghidra/processor) in `$GHIDRA_INSTALL/Ghidra/Processors/68000/data/languages/`.
3. Put the files in [ghidra/data](ghidra/data) in `$GHIDRA_INSTALL/Ghidra/Features/Base/data/`.
4. Add the scripts in [ghidra/scripts](ghidra/scripts) to Ghidra scripts. These will be in the `Analysis/M68k` category.
5. Open the dump as processor `68000`, variant `Mac`.
6. Run `M68kMacJankLoader.java` (find functions from jumptable), `M68kMacSymbols.java` (find symbols), `M68kMacPropagateThunks.java` (propagate thunk calls), and `M68kMacSyscallScript.java` (markup syscalls) in that order.

## TODO
* Finish creating properly typed functions for `_FP68K` routines
* Create properly typed functions for `_*Dispatch`, `_Pack*` routines
* Finish all syscalls
* Direct loader for Ghidra from binhex/derez
