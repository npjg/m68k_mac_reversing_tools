//Finds MacsBug symbols for each function
//@category Analysis.M68k

import java.io.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class M68kMacSymbols extends GhidraScript {

    private static final byte[][] ENDINGS = {
        { (byte) 0x4e, (byte) 0x75 }, // rts
        { (byte) 0x4e, (byte) 0xd0 }, // jmp (A0)
        { (byte) 0x4e, (byte) 0x74 }  // rtd
    };

    @Override
    protected void run() throws Exception {
        if (!currentProgram.getLanguage().getProcessor().toString().equals("68000")) {
            printf("Processor: %s", currentProgram.getLanguage().getProcessor().toString());
            popup("Processor must be 68000");
            return;
        }

        // get symbol as described in MacsBug Reference and Debugging Guide, Appendix D (Procedure Names)
        for (Function func : currentProgram.getFunctionManager().getFunctionsNoStubs(true)) {
            for (Instruction inst : currentProgram.getListing().getInstructions(func.getBody(), true)) {
                for (byte[] ending : ENDINGS) {
                    byte[] instructionBytes = inst.getBytes();
                    if (Arrays.equals(ending, Arrays.copyOfRange(instructionBytes, 0, 2))) { // take first 2 bytes only
                        Address symbolAddr = inst.getAddress().addNoWrap(instructionBytes.length);
                        int length = getByte(symbolAddr) & 0xff;
                        symbolAddr = symbolAddr.addNoWrap(1);
                        if (length == 0x80) {
                            // With a variable-length format, the first byte is in the range $80 to $9F.
                            // Stripping the high-order bit produces a length in the range $00 through $1F.
                            // If the length is zero, the next byte contains the actual length, in the range
                            // $01 through $FF.
                            //
                            // So since we added one to the symbol address already, we are getting the NEXT byte.
                            // So this is the length byte right here, and we want to read past it.
                            length = getByte(symbolAddr) & 0xff;
                            symbolAddr = symbolAddr.addNoWrap(1);
                        } else if (length > 0x80) {
                            length -= 0x80;
                        } else {
                            // TODO: 16 byte fixed length symbols
                            // With fixed-length format, the first byte is in the range $20 through $7F.
                            // The high-order bit may or may not be set. The high-order bit of the second
                            // byte is set for 16-character names, clear for 8-character names. Fixed-length
                            // 16-character names are used in object Pascal to show class.method names instead
                            // of procedure names. The method name is contained in the first 8 bytes and the
                            // class name is in the second 8 bytes. MacsBug swaps the order and inserts the period
                            // before displaying the name.
                            length = 8;
                            symbolAddr = symbolAddr.addNoWrap(-1);
                        }
                        byte[] symbolBytes = getBytes(symbolAddr, length);
                        if (length > 0) {
                            boolean goodSymbol = true;
                            for (int i = 0; i < symbolBytes.length; i++) {
                                int val = symbolBytes[i] & 0xff;
                                if (val < 32 || val > 126) {
                                    // Last char might be unprintable (Symantec C++ bug), omit it
                                    if (i == symbolBytes.length - 1) {
                                        length--;
                                    } else {
                                        goodSymbol = false;
                                    }
                                    break;
                                }
                            }
                            if (goodSymbol) {
                                String symbol = new String(getBytes(symbolAddr, length));
                                symbol = symbol.replace(" ", "_");
                                func.setName(symbol, SourceType.ANALYSIS);
                            }
                        }
                    }
                }
            }
        }
    }
}
