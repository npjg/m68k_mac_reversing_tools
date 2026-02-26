// Rewrite memory reference for instructions that call A5 world thunks (calls through the jumptable).
// @category Analysis.M68k

import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class M68kMacPropagateThunks extends GhidraScript {

    // As described in Inside Macintosh: Mac OS Runtime Architectures (Chapter 10 - Classic 68K Runtime Architectures),
    // A call that goes through the jump table has the form: JSR offset (A5).
    private static final byte[] INTERSEGMENT_JUMP_INSTRUCTION_PATTERN = {
        (byte) 0x4e, // JSR
        (byte) 0xad, // (A5)
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

        // Get the value of the A5 register.
        // TODO: The THINK C dumper sets A5 to 0x904, but CodeWarrior can arbitrarily set A5.
        // Right now, we just prompt for it - but later on we should automatically get it from somewhere.
        Address a5 = askAddress("A5 Value", "Enter the A5 register value:");

        // Rewrite the memory references.
        for (Function func : currentProgram.getFunctionManager().getFunctionsNoStubs(true)) {
            for (Instruction inst : currentProgram.getListing().getInstructions(func.getBody(), true)) {
                if (ByteBuffer.wrap(INTERSEGMENT_JUMP_INSTRUCTION_PATTERN).equals(ByteBuffer.wrap(inst.getBytes(), 0, 2))) {
                    short offset = getShort(inst.getAddress().addNoWrap(2));
                    // Check that the offset points to a thunk in the A5 world.
                    if (offset < 0x20 || offset % 8 != 2) {
                        continue;
                    }

                    Address target = toAddr(getInt(a5.addNoWrap(offset + 2)));
                    ReferenceManager refman = currentProgram.getReferenceManager();
                    refman.removeAllReferencesFrom(inst.getAddress());
                    Reference ref = refman.addMemoryReference(inst.getAddress(),
                        target, RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, Reference.MNEMONIC);
                    refman.setPrimary(ref, true);
                }
            }
        }
    }
}
