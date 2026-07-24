package m68kmac.common;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * The "symbol name" section of the custom M68k Mac dump header.
 *
 * This section is necessary because some compilers, such as THINK C, store a short-format MacsBug symbol
 * alongside the code but provide full names elsewhere. When these full names are available, we want to use them.
 * The dumper can recover these full names and provide them for us here.
 */
public final class DumperProvidedSymbolNames {

    /** Program options group under which the loader stashes the raw symbol-name section. */
    public static final String OPTIONS_GROUP = "Dumper-Provided Symbols";

    /** Option name holding the raw symbol-name section bytes (see {@link #parse}). */
    public static final String SECTION_OPTION = "Dumper-Provided Symbols";

    private DumperProvidedSymbolNames() {
    }

    /**
     * A full symbol name provided by the dumper.
     */
    public record DumperProvidedSymbolNameRecord(long startAddress, String symbolName) {
    }

    /**
     * Parse the symbol-name section into its records.
     */
    public static List<DumperProvidedSymbolNameRecord> parse(byte[] symbolNameSection) throws IOException {
        List<DumperProvidedSymbolNameRecord> symbolNameRecords = new ArrayList<>();
        boolean sectionIsPresent = symbolNameSection != null && symbolNameSection.length >= Integer.BYTES;
        if (!sectionIsPresent) {
            return symbolNameRecords;
        }

        BinaryReader reader = new BinaryReader(new ByteArrayProvider(symbolNameSection), false);
        long recordCount = reader.readNextUnsignedInt();
        for (long recordIndex = 0; recordIndex < recordCount; recordIndex++) {
            long startAddress = reader.readNextUnsignedInt();
            String symbolName = reader.readNextAsciiString();
            symbolNameRecords.add(new DumperProvidedSymbolNameRecord(startAddress, symbolName));
        }

        return symbolNameRecords;
    }
}
