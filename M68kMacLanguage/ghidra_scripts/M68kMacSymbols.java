// Apply MacsBug symbols for each function. No demangling is performed.
// @category Analysis.M68k

import java.io.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import m68kmac.datatypes.MacsBugSymbolDataType;

public class M68kMacSymbols extends GhidraScript {

    private static final byte[][] ENDINGS = {
        { (byte) 0x4e, (byte) 0x75 }, // rts
        { (byte) 0x4e, (byte) 0xd0 }, // jmp (A0)
        { (byte) 0x4e, (byte) 0x74 }  // rtd
    };

    @Override
    protected void run() throws Exception {
        // Verify the processor.
        // TODO: Also make sure we are on the Mac variant.
        if (!currentProgram.getLanguage().getProcessor().toString().equals("68000")) {
            printf("Processor: %s", currentProgram.getLanguage().getProcessor().toString());
            popup("Processor must be 68000");
            return;
        }

        // Search each function and instruction for the ending patterns.
        for (Function func : currentProgram.getFunctionManager().getFunctionsNoStubs(true)) {
            for (Instruction inst : currentProgram.getListing().getInstructions(func.getBody(), true)) {
                for (byte[] ending : ENDINGS) {
                    byte[] instructionBytes = inst.getBytes();
                    // Take first 2 bytes of instruction only (because that is what our ending instruction patterns are).
                    byte[] firstTwoInstructionBytes = Arrays.copyOfRange(instructionBytes, 0, 2);
                    if (Arrays.equals(ending, firstTwoInstructionBytes)) {
                        // Locate MacsBug symbol immediately after return instruction.
                        Address macsBugSymbolStart = inst.getAddress().addNoWrap(instructionBytes.length);

                        // Create MacsBug symbol data type at this location.
                        DataTypeManager dtm = currentProgram.getDataTypeManager();
                        MacsBugSymbolDataType macsBugSymbolDt = new MacsBugSymbolDataType(dtm);
                        Listing listing = currentProgram.getListing();
                        try {
                            // Check if there's already an instruction at this location - skip if so.
                            // This prevents clearing already-disassembled functions.
                            Instruction existingInst = listing.getInstructionAt(macsBugSymbolStart);
                            if (existingInst != null) {
                                // Skip - there's already code here. We expect this to happen when there aren't actually
                                // symbols between functions.
                                printf("INFO: Expected MacsBug symbol at %s but found code: %s\n", macsBugSymbolStart, existingInst.toString());
                                continue;
                            }

                            // Calculate the expected symbol length.
                            MemBuffer buffer = new MemoryBufferImpl(currentProgram.getMemory(), macsBugSymbolStart);
                            int symbolTotalLength = macsBugSymbolDt.getLength(buffer);
                            if (symbolTotalLength <= 0) {
                                continue;  // Invalid symbol format - skip
                            }

                            // Clear existing data in the range where the symbol will be placed.
                            // This prevents conflicts with existing data types, namely auto-detected strings.
                            Address symbolEnd = macsBugSymbolStart.addNoWrap(symbolTotalLength - 1);
                            listing.clearCodeUnits(macsBugSymbolStart, symbolEnd, false);

                            // Create the MacsBug symbol data type.
                            Data symbolData = listing.createData(macsBugSymbolStart, macsBugSymbolDt);
                            if (symbolData != null) {
                                // Extract symbol name from the data type's value.
                                Object symbolValue = symbolData.getValue();
                                if (symbolValue instanceof String) {
                                    String symbolName = (String) symbolValue;
                                    symbolName = symbolName.replace(" ", "_");
                                    func.setName(symbolName, SourceType.ANALYSIS);
                                    printf("MacsBug symbol: %s (%s)\n", symbolName, func.getEntryPoint());
                                }
                            }
                        } catch (Exception e) {
                            printf("WARNING: Failed to create MacsBug symbol at %s: %s\n", macsBugSymbolStart, e.getMessage());
                        }
                    }
                }
            }
        }
    }
}
