package m68kmac.datatypes;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Custom data type for MacsBug symbol debug information.
 *
 * MacsBug symbols appear after function return instructions and encode the function name
 * with a variable-length format as described in the MacsBug Reference and Debugging Guide,
 * Appendix D (Procedure Names).
 *
 * Format:
 * - First byte is length indicator:
 *   - 0x80: Extended format - next byte contains actual length (1-255)
 *   - 0x81-0x9F: Variable length format - subtract 0x80 to get length (1-31)
 *   - 0x20-0x7F: Fixed-length format (8 or 16 bytes, currently only 8-byte supported)
 * - Symbol name bytes (variable length)
 * - Optional padding to 4-byte boundary (longword alignment)
 */
public class MacsBugSymbolDataType extends DynamicDataType {

    /**
     * MacsBug symbol format types.
     */
    private enum FormatType {
        EXTENDED,   // 0x80: Two-byte length encoding
        VARIABLE,   // 0x81-0x9F: One-byte length encoding
        FIXED       // 0x20-0x7F: Fixed 8-byte format
    }

    /**
     * Holds parsed information about a MacsBug symbol's structure.
     */
    private static class SymbolInfo {
        final FormatType formatType;  // Which format variant this symbol uses
        final int symbolLength;       // Length of just the symbol name
        final int symbolOffset;       // Byte offset where the symbol name starts
        final int totalLength;        // Total length including length bytes and padding

        SymbolInfo(FormatType formatType, int symbolLength, int symbolOffset, int totalLength) {
            this.formatType = formatType;
            this.symbolLength = symbolLength;
            this.symbolOffset = symbolOffset;
            this.totalLength = totalLength;
        }
    }

    public MacsBugSymbolDataType() {
        this(null);
    }

    public MacsBugSymbolDataType(DataTypeManager dtm) {
        super("MacsBugSymbol", dtm);
    }

    @Override
    public DataType clone(DataTypeManager dtm) {
        if (dtm == getDataTypeManager()) {
            return this;
        }
        return new MacsBugSymbolDataType(dtm);
    }

    @Override
    public String getDescription() {
        return "MacsBug debug symbol";
    }

    @Override
    public String getMnemonic(Settings settings) {
        return "MacsBugSym";
    }

    @Override
    protected DataTypeComponent[] getAllComponents(MemBuffer buffer) {
        // PARSE the symbol format using the shared parser.
        SymbolInfo info = parseSymbolInfo(buffer);
        if (info == null) {
            return null;
        }

        // BUILD component array based on the format type.
        java.util.List<DataTypeComponent> components = new java.util.ArrayList<>();
        int componentOrdinal = 0;

        // Add length-encoding components based on format type.
        if (info.formatType == FormatType.EXTENDED) {
            components.add(new ReadOnlyDataTypeComponent(
                ByteDataType.dataType, this, 1, componentOrdinal++, 0, "length_indicator", null));
            components.add(new ReadOnlyDataTypeComponent(
                ByteDataType.dataType, this, 1, componentOrdinal++, 1, "actual_length", null));
        } else if (info.formatType == FormatType.VARIABLE) {
            components.add(new ReadOnlyDataTypeComponent(
                ByteDataType.dataType, this, 1, componentOrdinal++, 0, "length_byte", null));
        }
        // FIXED format has no length-encoding bytes

        // Add symbol name component.
        if (info.symbolLength > 0) {
            StringDataType stringDt = new StringDataType();
            components.add(new ReadOnlyDataTypeComponent(
                stringDt, this, info.symbolLength, componentOrdinal++,
                info.symbolOffset, "symbol_name", null));
        }

        // Add padding component if present (totalLength > symbolOffset + symbolLength).
        int unpaddedLength = info.symbolOffset + info.symbolLength;
        int paddingBytes = info.totalLength - unpaddedLength;
        if (paddingBytes > 0) {
            // Create array data type for multiple padding bytes if needed.
            DataType paddingType = paddingBytes == 1
                ? ByteDataType.dataType
                : new ArrayDataType(ByteDataType.dataType, paddingBytes, 1);
            components.add(new ReadOnlyDataTypeComponent(
                paddingType, this, paddingBytes, componentOrdinal++,
                unpaddedLength, "padding", null));
        }

        return components.toArray(new DataTypeComponent[0]);
    }

    @Override
    public String getRepresentation(MemBuffer buffer, Settings settings, int length) {
        String symbolName = extractSymbolName(buffer);
        if (symbolName != null) {
            return String.format("\"%s\"", symbolName);
        }
        return "<Invalid MacsBug symbol>";
    }

    @Override
    public Object getValue(MemBuffer buffer, Settings settings, int length) {
        // Return the symbol name string as the value.
        return extractSymbolName(buffer);
    }

    @Override
    public Class<?> getValueClass(Settings settings) {
        return String.class;
    }

    @Override
    public DataType getReplacementBaseType() {
        return ByteDataType.dataType;
    }

    /**
     * Parse MacsBug symbol format and calculate lengths.
     *
     * This is the single source of truth for MacsBug symbol format parsing.
     *
     * @param buffer The memory buffer containing the MacsBug symbol
     * @return SymbolInfo with parsed details, or null if invalid format
     */
    private SymbolInfo parseSymbolInfo(MemBuffer buffer) {
        try {
            int offset = 0;
            int lengthIndicator = buffer.getByte(offset) & 0xFF;

            FormatType formatType;
            int symbolLength;
            int symbolOffset;

            if (lengthIndicator == 0x80) {
                // EXTENDED FORMAT: first byte is 0x80, next byte contains actual length.
                formatType = FormatType.EXTENDED;
                offset++;
                symbolLength = buffer.getByte(offset) & 0xFF;
                offset++;
                symbolOffset = offset;
            } else if (lengthIndicator > 0x80 && lengthIndicator <= 0x9F) {
                // VARIABLE LENGTH FORMAT: subtract 0x80 to get length.
                formatType = FormatType.VARIABLE;
                symbolLength = lengthIndicator - 0x80;
                offset++;
                symbolOffset = offset;
            } else if (lengthIndicator >= 0x20 && lengthIndicator <= 0x7F) {
                // FIXED LENGTH FORMAT: 8 bytes (first byte is part of symbol name).
                formatType = FormatType.FIXED;
                symbolLength = 8;
                symbolOffset = offset;  // First byte is part of symbol
            } else {
                // Invalid length indicator.
                return null;
            }

            // VERIFY symbol contains printable ASCII characters.
            for (int i = 0; i < symbolLength; i++) {
                int charValue = buffer.getByte(symbolOffset + i) & 0xFF;
                if (charValue < 32 || charValue > 126) {
                    if (i == symbolLength - 1) {
                        // Last character unprintable (Symantec C++ bug) - adjust length.
                        symbolLength--;
                    } else {
                        // Invalid character in middle of symbol.
                        return null;
                    }
                    break;
                }
            }

            // CALCULATE total length with padding to 4-byte boundary (longword alignment).
            int unpaddedLength = symbolOffset + symbolLength;
            int totalLength = ((unpaddedLength + 3) / 4) * 4;  // Round up to next multiple of 4

            return new SymbolInfo(formatType, symbolLength, symbolOffset, totalLength);

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Calculate the total length of the MacsBug symbol in the buffer.
     *
     * This includes the length indicator byte(s), symbol name, and padding to 4-byte alignment.
     *
     * @param buffer The memory buffer containing the MacsBug symbol
     * @return The total length in bytes, or -1 if the symbol format is invalid
     */
    public int getLength(MemBuffer buffer) {
        SymbolInfo info = parseSymbolInfo(buffer);
        return info != null ? info.totalLength : -1;
    }

    /**
     * Extract the symbol name string from a MacsBug symbol in the buffer.
     */
    private String extractSymbolName(MemBuffer buffer) {
        SymbolInfo info = parseSymbolInfo(buffer);
        if (info == null || info.symbolLength == 0) {
            return null;
        }

        try {
            // EXTRACT symbol bytes from the buffer.
            byte[] symbolBytes = new byte[info.symbolLength];
            for (int i = 0; i < info.symbolLength; i++) {
                symbolBytes[i] = buffer.getByte(info.symbolOffset + i);
            }

            return new String(symbolBytes, 0, info.symbolLength);

        } catch (Exception e) {
            return null;
        }
    }
}
