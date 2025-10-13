
The purpose of this repo is to create a memory dump of a CodeWarrior classic Macintosh 68k program for importing into Ghidra. CodeWarrior injects its own startup code that, among other things, does the following:
 - Constructs A5 world from compressed resource (first part of `DATA` 0).
 - Decompresses relocation information from (last part of `DATA` 0) and relocates all code segments when they are loaded.

Thankfully, all the necessary CodeWarrior loading code in the following place in a CodeWarrior installation (for CodeWarrior Pro 1, at least):
```
MacOS Support:Libraries:Runtime:Runtime 68K:(Sources):Appl68KStartup.c
```

Currently, this code doesn't parse HFS volumes or resource forks itself; it expects each resource as a raw data file. It also expects to already know the size of the A5 world - a future task is adding parsing for the `CODE` 0 resources. But many people do that already, so it wasn't as hard to figure out.

