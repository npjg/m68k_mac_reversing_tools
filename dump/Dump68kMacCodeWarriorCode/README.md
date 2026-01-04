
The purpose of this repo is to create a memory dump of a CodeWarrior classic Macintosh 68k program for loading into Ghidra. I have found that several games have useful debug symbols ONLY in the 68k code - not in the PPC code or in the Windows executables.

The dumper in (m68k_mac_reversing_tools)[https://github.com/ubuntor/m68k_mac_reversing_tools] is very useful but does not generally produce a usable dump for programs compiled with CodeWarrior. This is because many CodeWarrior programs use the default CodeWarrior startup code that does the following nasty things:
 - Constructs A5 world from a compressed resource (first part of `DATA` 0).
 - Decompresses relocation information from (last part of `DATA` 0) and relocates all code segments when they are loaded.
 - And probably other stuff when there is more than one `CODE` resource.

This repo adds this functionality to get a dump usable in Ghidra. Currently, the utility doesn't parse HFS volumes or resource forks itself; it expects each resource as a raw data file. I use (`resource_dasm`)[https://github.com/fuzziqersoftware/resource_dasm] to extract resources from MacBinary files made by the (ScummVM Dumper Companion)[https://www.scummvm.org/dumper-companion].

It would be great to have all of this functionality packaged in a Ghidra extension, but I haven't taken the time to do that yet. So here's the workflow for loading into Ghidra:
 - Set up the 68000 Mac processor variant from (m68k_mac_reversing_tools)[https://github.com/ubuntor/m68k_mac_reversing_tools] in Ghidra.
 - Create a dump of your chosen application with this utility.
 - Load the dump into Ghidra with the 68000 Mac processor variant, as described in (m68k_mac_reversing_tools)[https://github.com/ubuntor/m68k_mac_reversing_tools].
 - Demangle function names with (Ghidra-CodeWarriorDemangler)[https://github.com/Cuyler36/Ghidra-CodeWarriorDemangler].
 - Create class structures manually.

# TODOs
 - Dumping more than one CODE resource.
 - Supporting CodeWarrior RTTI and such. Currently vtables and such must be manually constructed from within Ghidra.
 - Creating a CodeWarrior compiler spec to deal with some observed pecularities when using the default 68000 Mac compiler spec.

# Source
The necessary CodeWarrior loading code in the following place in a CodeWarrior Pro 1 installation:
```
MacOS Support:Libraries:Runtime:Runtime 68K:(Sources):Appl68KStartup.c
```