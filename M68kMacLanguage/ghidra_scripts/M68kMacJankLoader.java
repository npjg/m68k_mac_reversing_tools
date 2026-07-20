// Walks the dumped jumptable to create thunk and target functions.
// Resolve intersegment calls into direct call references throughout the program.
// @category Analysis.M68k

import java.io.*;
import java.util.*;
import generic.jar.ResourceFile;
import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;

// To understand this script, please read Mac OS Runtime Architectures (Chapter 10 - Classic 68K Runtime Architectures).
public class M68kMacJankLoader extends GhidraScript {
    // A loaded jumptable entry always has an unconditional jump as the actual thunk.
    private static final short UNCONDITIONAL_JUMP_OPCODE = 0x4EF9;

    // A call that goes through the jumptable has the form: JSR offset (A5).
    private static final short INTERSEGMENT_JUMP_OPCODE = 0x4EAD;

    private static final byte[] THINK_C_START = {
        (byte) 0x42, (byte) 0x78, (byte) 0x0a, (byte) 0x4a, (byte) 0x9d, (byte) 0xce
    };

    private static final int DUMMY_ADDR = 0xFFFFFFFF;

    private static final int JUMPTABLE_OFFSET = 0x20;
    private static final int JUMPTABLE_ENTRY_SIZE = 8;

    @Override
    protected void run() throws Exception {
        // Verify the processor.
        if (!currentProgram.getLanguage().getProcessor().toString().equals("68000") ||
            !currentProgram.getLanguageID().toString().contains("mac")) {
            printf("Processor: %s", currentProgram.getLanguage().getProcessor().toString());
            popup("Processor must be 68000 Mac");
            return;
        }

        // Label the static system globals. The text file has a format like:
        //  0x011C, UTableBase
        // So we just label those at the addresses where they should be.
        ResourceFile rFile = Application.findDataFileInAnyModule("m68k_mac_system_globals");
        if (rFile == null) {
            popup("Could not find m68k Mac system globals file");
            return;
        }
        BufferedReader br = new BufferedReader(new FileReader(rFile.getFile(false)));
        String line = null;
        while ((line = br.readLine()) != null) {
            String[] parts = line.trim().split(",", 2);
            Address addr = toAddr(Long.decode(parts[0].trim()));
            String name = parts[1].trim();
            createLabel(addr, name, true, SourceType.ANALYSIS);
        }

        // As documented in the CodeWarrior dumper, CodeWarrior uses a DIFFERENT loaded
        // jumptable layout than the Apple default.
        boolean compilerIsCodewarrior = currentProgram.getCompilerSpec().getCompilerSpecID().toString().contains("codewarrior");

        // Get the value of the A5 register from the CurrentA5 global (0x904),
        // which was written by the dumpers.
        Address a5 = toAddr(getInt(toAddr(0x904)));
        printf("A5: 0x%x\n", a5.getOffset());

        // Parse the whole jumptable.
        // TODO: Is there a better way to parse the jumptable entries than doing all this manual
        // offset stuff?
        Address jumptableEntry = a5.addNoWrap(JUMPTABLE_OFFSET);
        try {
            while (currentProgram.getMemory().contains(jumptableEntry)) {
                // TODO: Actually check the addresses.
                // CodeWarrior dumps seem to have zeroes as the first entry,
                // so skip those for now.
                if (getShort(jumptableEntry) == 0) {
                    jumptableEntry = jumptableEntry.addNoWrap(JUMPTABLE_ENTRY_SIZE);
                    continue;
                }

                Address possibleJumpInstructionAddr = compilerIsCodewarrior ? jumptableEntry : jumptableEntry.addNoWrap(2);
                if (getShort(possibleJumpInstructionAddr) != UNCONDITIONAL_JUMP_OPCODE) {
                    // We hit something that doesn't look like a valid loaded jumptable entry, so
                    // assume this is the end of the jumptable.
                    // TODO: Store the jumptable size in the dumps so we don't have to guess.
                    break;
                }

                int funcAddrInt = getInt(possibleJumpInstructionAddr.addNoWrap(2));
                if (funcAddrInt == DUMMY_ADDR) {
                    jumptableEntry = jumptableEntry.addNoWrap(JUMPTABLE_ENTRY_SIZE);
                    continue;
                }
                Address jumpTargetAddr = toAddr(funcAddrInt);
                printf("Jumptable @ %s: %s\n", jumptableEntry, jumpTargetAddr);

                // Clear everything from the jumptable entry so we can recreate it properly.
                // Auto-analyzers sometimes create junk in the jumptable that prevents our ability
                // to properly create the thunks later on.
                Address jumptableEntryEnd = jumptableEntry.addNoWrap(JUMPTABLE_ENTRY_SIZE - 1);
                clearListing(jumptableEntry, jumptableEntryEnd);
                // Remove any functions overlapping this jumptable entry range.
                AddressSet jumptableEntrySet = new AddressSet(jumptableEntry, jumptableEntryEnd);
                Iterator<Function> functionIterator = currentProgram.getFunctionManager().getFunctionsOverlapping(jumptableEntrySet);
                while (functionIterator.hasNext()) {
                    removeFunction(functionIterator.next());
                }

                // Define the segment ID before disassembling the thunk.
                // This visually delimits the data and helps avoid junk decompilations.
                Address segmentIdAddr = compilerIsCodewarrior ? jumptableEntry.addNoWrap(6) : jumptableEntry;
                createData(segmentIdAddr, ShortDataType.dataType);

                // Make sure the actual thunk target exists.
                disassemble(jumpTargetAddr);
                createFunction(jumpTargetAddr, null);

                // Make sure the thunk exists.
                disassemble(possibleJumpInstructionAddr);
                createFunction(possibleJumpInstructionAddr, null);

                jumptableEntry = jumptableEntry.addNoWrap(JUMPTABLE_ENTRY_SIZE);
            }
        } catch (Exception e) {
            printf("Jumptable analysis failed: %s\n", e.getMessage());
        }

        // Identify and label the entry point (first jumptable entry).
        // TODO: This also needs to be reworked for CodeWarrior.
        Address startAddr = toAddr(getInt(a5.addNoWrap(JUMPTABLE_OFFSET + 4)));
        printf("Entry point: %s\n", startAddr);
        createLabel(startAddr, "_start", false, SourceType.ANALYSIS);
        if (Arrays.equals(getBytes(startAddr, THINK_C_START.length), THINK_C_START)) {
            // Think C (Symantec): main offset stored before start.
            int mainJumptableOffset = getInt(startAddr.addNoWrap(-4));
            Address entryPoint = toAddr(getInt(a5.addNoWrap(mainJumptableOffset + 2))); // skip jmp, get addr
            printf("main: %s\n", entryPoint);
            addEntryPoint(entryPoint);
            createLabel(entryPoint, "main", false, SourceType.ANALYSIS);
        } else {
            // TODO: Handle entry points for other compilers.
            addEntryPoint(startAddr);
        }

        // Point all intersegment calls [JSR offset(A5)] in the program to their targets.
        // For example, suppose the original disassembly is
        //   1000:  JSR  $132(A5)
        // By default, Ghidra cannot tell where that goes. But by understanding the jumptable,
        // we can determine A5 + 0x132 actually points to, say, 0x00415C20. Note that we do NOT
        // rewrite any machine code. We simply tell Ghidra this instruction is actually an
        // unconditional call to a known address.
        for (Function func : currentProgram.getFunctionManager().getFunctionsNoStubs(true)) {
            for (Instruction inst : currentProgram.getListing().getInstructions(func.getBody(), true)) {
                if (getShort(inst.getAddress()) == INTERSEGMENT_JUMP_OPCODE) {
                    short offset = getShort(inst.getAddress().addNoWrap(2));
                    boolean offsetIsLikelyValid = (offset >= JUMPTABLE_OFFSET && offset % 8 == 2);
                    if (!offsetIsLikelyValid) {
                        printf("[@%s] WARNING: Got invalid A5 offset %d\n", inst.getAddress(), offset);
                        continue;
                    }

                    // Refer directly to the JMP instruction in the jumptable entry.
                    jumptableEntry = toAddr(getInt(a5.addNoWrap(offset)));
                    Address thunkAddr = compilerIsCodewarrior ? jumptableEntry : jumptableEntry.addNoWrap(2);
                    printf("[@%s] Resolve thunk at %d to %s\n", inst.getAddress(), offset, thunkAddr);
                    ReferenceManager refman = currentProgram.getReferenceManager();
                    refman.removeAllReferencesFrom(inst.getAddress());
                    Reference ref = refman.addMemoryReference(inst.getAddress(), thunkAddr, RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, Reference.MNEMONIC);
                    refman.setPrimary(ref, true);
                }
            }
        }
    }
}
