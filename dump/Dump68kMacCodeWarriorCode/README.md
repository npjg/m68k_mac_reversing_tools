
The purpose of this script is to create a memory dump of a CodeWarrior classic Macintosh 68k program for loading into Ghidra. I have found that several games have useful debug symbols ONLY in the 68k code - not in the PPC code or in the Windows executables.

The generic dumper ([DumpGenericM68kMacCode.py](../DumpGeneric68kMacCode.py)) is very useful but does not generally produce a usable dump for programs compiled with CodeWarrior. This is because many CodeWarrior programs use the default CodeWarrior loader that does the following nasty things:
 - Constructs A5 world from a compressed resource (first part of `DATA` 0).
 - Decompresses relocation information from (last part of `DATA` 0) and relocates all code segments when they are loaded.
 - And probably other stuff when there is more than one `CODE` resource.

This script adds this functionality to get a dump usable in Ghidra. Currently, the utility doesn't parse HFS volumes or resource forks itself; it expects each resource as a raw data file. Here's the workflow for loading into Ghidra:
 - Set up the 68000 Mac Codewarrior processor variant in Ghidra in this repo.
 - Create a dump of your chosen application with this utility. You can use [resource_dasm](https://github.com/fuzziqersoftware/resource_dasm) to extract resources from MacBinary files made by the [ScummVM Dumper Companion](https://www.scummvm.org/dumper-companion).
 - Load the dump into Ghidra with the 68000 CodeWarrior Mac processor variant, based on the instructions in this repo's main README.
 - Demangle function names with the included [CodeWarriorDemanglerScript](../../ghidra/scripts/CodeWarriorDemanglerScript.java).

# TODOs
 - Dumping more than one CODE resource.
 - Supporting CodeWarrior RTTI and such. Currently vtables and such must be manually constructed from within Ghidra.

# Source
After reversing much of the CodeWarrior loader, I found that the source code was actually included with CodeWarrior, so the dumper is now based on that. The loader code in the following place in a CodeWarrior Pro 1 installation:
```
MacOS Support:Libraries:Runtime:Runtime 68K:(Sources):Appl68KStartup.c
```
