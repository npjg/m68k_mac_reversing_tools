# M68k Ghidra Mac Reversing Tools
**Advantage(s)**: Syscalls are functions (so xrefs work), nicer handling of thunks
**Disadvantage(s)**: Stack-based syscall arguments are ugly

1. Make a dump using one of the [dumpers](dump/) corresponding to your compiler.
2. Install the `M68kMacLanguage` Ghidra extension provided in this repo.
3. Open the dump as processor `68000`, variant `Mac`, and the compiler of your choice.
4. Run `M68kMacJankLoader.java` (find functions from jumptable), `M68kMacSymbols.java` (find symbols), `M68kMacPropagateThunks.java` (propagate thunk calls), `M68kMacSyscallScript.java` (markup syscalls), and `CodeWarriorDemangler.java` in that order.


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
