
Dump a CodeWarrior classic Macintosh 68k program to load into Ghidra. I have found that several games have useful debug symbols ONLY in the 68k code - not in the PPC code or in the Windows executables.

The [THINK C Ghidra dumper](../DumpThinkC68kMacCode/DumpThinkC68kMacCode.py)) does not generally produce a usable dump for CodeWarrior programs. This is because many such programs use the default CodeWarrior startup code that does nasty things, including constructing the A5 world from a compressed resource (first part of `DATA 0`), decompressing relocation information from last part of `DATA 0`, and then relocating code segments on-demand with a custom `LoadSeg`.

Currently, the utility doesn't parse HFS volumes or resource forks itself; it expects each resource as a raw data file. Here's the workflow for loading into Ghidra:
 - Set up the 68000 Mac Codewarrior processor variant in Ghidra in this repo.
 - Create a dump of your chosen CodeWarrior application with this utility. You can use [resource_dasm](https://github.com/fuzziqersoftware/resource_dasm) to extract resources from MacBinary files made by the [ScummVM Dumper Companion](https://www.scummvm.org/dumper-companion).
 - Load the dump into Ghidra with the 68000 CodeWarrior Mac processor variant, based on the instructions in this repo's main README.
 - Demangle function names with the included [CodeWarriorDemanglerScript](../../ghidra/scripts/CodeWarriorDemanglerScript.java).

Currently, ONLY near-model programs are supported.

# Background Knowledge
See [Chapter 10 (Classic 68K Runtime Architecture)](https://preterhuman.net/macstuff/techpubs/mac/runtimehtml/RTArch-115.html) of _Inside Macintosh: Mac OS Runtime Architectures_.

# TODOs
 - Supporting CodeWarrior RTTI and such. Currently vtables and such must be manually constructed within Ghidra.
