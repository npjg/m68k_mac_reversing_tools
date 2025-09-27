// Find LINK.W A6 instructions in unanalyzed binary and create functions
// @author
// @category Analysis.M68k
// @keybinding
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.sourcemap.*;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.ISF.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.util.task.ConsoleTaskMonitor;

public class M68kCreateFunctionsBasedOnLinkA6Instructions extends GhidraScript {

    @Override
    public void run() throws Exception {

        Memory memory = currentProgram.getMemory();

        // Target bytes: 4e 56 (LINK.W A6)
        byte[] targetBytes = {(byte)0x4e, (byte)0x56};

        int foundCount = 0;
        int createdCount = 0;

        // Get all memory blocks
        MemoryBlock[] blocks = memory.getBlocks();

        for (MemoryBlock block : blocks) {
            if (!block.isInitialized()) {
                continue;
            }

            println("Searching block: " + block.getName() + " (" +
                    block.getStart() + " - " + block.getEnd() + ")");

            Address currentAddr = block.getStart();
            Address endAddr = block.getEnd();

            while (currentAddr.compareTo(endAddr) < 0) {
                try {
                    // Check if we have the target bytes
                    byte firstByte = memory.getByte(currentAddr);
                    if (firstByte == targetBytes[0]) {
                        Address nextAddr = currentAddr.add(1);
                        if (nextAddr.compareTo(endAddr) <= 0) {
                            byte secondByte = memory.getByte(nextAddr);
                            if (secondByte == targetBytes[1]) {

                                foundCount++;
                                println("Found LINK.W A6 at: " + currentAddr);

                                // Check if there's already a function at this address
                                Function existingFunction =
                                    currentProgram.getFunctionManager().getFunctionAt(currentAddr);

                                if (existingFunction == null) {
                                    // Force disassembly at this location
                                    ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
                                    DisassembleCommand disasmCmd =
                                        new DisassembleCommand(currentAddr, null, true);
                                    disasmCmd.applyTo(currentProgram, monitor);

                                    // Create function
                                    CreateFunctionCmd createFuncCmd =
                                        new CreateFunctionCmd(currentAddr);
                                    if (createFuncCmd.applyTo(currentProgram, monitor)) {
                                        createdCount++;
                                        println("Created function at: " + currentAddr);
                                    } else {
                                        println("Failed to create function at: " + currentAddr);
                                    }
                                } else {
                                    println("Function already exists at: " + currentAddr);
                                }
                            }
                        }
                    }

                    currentAddr = currentAddr.add(1);

                } catch (Exception e) {
                    currentAddr = currentAddr.add(1);
                    continue;
                }
            }
        }

        println("\nSummary:");
        println("Found " + foundCount + " LINK.W A6 instructions");
        println("Created " + createdCount + " new functions");
    }
}