package m68kmac.analysis;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.framework.options.Options;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import m68kmac.datatypes.MacsBugSymbolDataType;

/**
 * Analyzer that applies MacsBug function names to functions in m68k classic Mac programs.
 * TODO: I think PPC programs with symbols probably use a similar format, but this
 * analyzer right now ONLY supports m68k.
 * TODO: Are there other types of symbols that can be applied than just function names?
 *
 * MacsBug symbols appear immediately after function return instructions and encode
 * the function name. This analyzer locates these symbols and applies them as function
 * names, with fallback to searching for plain ASCII strings between functions if MacsBug
 * parsing fails. Any names found are NOT demangled.
 *
 */
public class M68kMacSymbolsAnalyzer extends AbstractAnalyzer {
    private static final String NAME = "m68k Classic Mac Symbols";
    private static final String DESCRIPTION = "Apply MacsBug symbols to functions.";

    // Return instruction patterns to search for.
    private static final short[] RETURN_PATTERNS = {
        0x4E75, // RTS
        0x4ED0, // JMP (A0)
        0x4E74  // RTD
    };

    private static final int MIN_ASCII_SYMBOL_LENGTH = 4;

    private static final String MACSBUG_TAG = "MacsBug Symbol";
    private static final String OPTION_OVERWRITE = "Overwrite previously applied symbols";
    private boolean overwriteNonDefaultNames = false;

    public M68kMacSymbolsAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        // Run after functions are created.
        setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after());
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        // Only analyze 68000 Mac programs.
        String processor = program.getLanguage().getProcessor().toString();
        return processor.equals("68000") &&
               program.getLanguageID().toString().contains("mac");
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(
            OPTION_OVERWRITE,
            false,
            null,
            "Overwrite symbols previously applied by this or other analyzers. (This WILL undo demangled names and such.)");
    }

    @Override
    public void optionsChanged(Options options, Program program) {
        overwriteNonDefaultNames = options.getBoolean(OPTION_OVERWRITE, false);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        monitor.setMessage("Applying MacsBug symbols...");
        Listing listing = program.getListing();
        DataTypeManager dtm = program.getDataTypeManager();
        MacsBugSymbolDataType macsBugSymbolDt = new MacsBugSymbolDataType(dtm);

        // Search each function for return instructions.
        for (Function function : program.getFunctionManager().getFunctionsNoStubs(true)) {
            monitor.checkCancelled();

            // Make sure this is a fuction name we can overwrite.
            Symbol symbol = function.getSymbol();
            if (symbol.getSource() != SourceType.DEFAULT && !overwriteNonDefaultNames) {
                // ONLY overwrite default function names.
                continue;
            }

            for (Instruction instruction : listing.getInstructions(function.getBody(), true)) {
                try {
                    // Check if this is a return instruction.
                    boolean isReturnInstruction = false;
                    for (short pattern : RETURN_PATTERNS) {
                        if (program.getMemory().getShort(instruction.getAddress()) == pattern) {
                            isReturnInstruction = true;
                            break;
                        }
                    }
                    if (!isReturnInstruction) {
                        continue;
                    }

                    // Symbol should be immediately after the return instruction.
                    Address symbolStartAddress = instruction.getAddress().addNoWrap(instruction.getBytes().length);

                    // Skip if there's already an instruction here, because most likely there is thus no symbol
                    // between these two functions.
                    Instruction existingInstruction = listing.getInstructionAt(symbolStartAddress);
                    if (existingInstruction != null) {
                        // TODO: Maybe add a comment at this address saying no symbol was found?
                        continue;
                    }

                    // Try to create a MacsBug symbol.
                    boolean symbolApplied = false;
                    try {
                        MemoryBufferImpl buffer = new MemoryBufferImpl(program.getMemory(), symbolStartAddress);
                        int symbolLength = macsBugSymbolDt.getLength(buffer);
                        if (symbolLength > 0) {
                            // There is probably an auto-detected string here already, so clear existing data
                            // in the symbol range. (Remember we already ensured there was no code here).
                            Address symbolEndAddress = symbolStartAddress.addNoWrap(symbolLength - 1);
                            listing.clearCodeUnits(symbolStartAddress, symbolEndAddress, false);

                            // Create the MacsBug symbol.
                            Data symbolData = listing.createData(symbolStartAddress, macsBugSymbolDt);
                            if (symbolData != null) {
                                Object symbolValue = symbolData.getValue();
                                if (symbolValue instanceof String) {
                                    String symbolName = (String) symbolValue;
                                    String normalizedName = symbolName.replace(" ", "_");
                                    function.setName(normalizedName, SourceType.ANALYSIS);
                                    symbolApplied = true;
                                }
                            }
                        }
                    } catch (Exception e) {
                        // MacsBug symbol parsing failed, try fallback.
                        // We do not issue a warning to the log here.
                    }

                    // Try to interpret the bytes between this function and the next as a plain ASCII string.
                    // Note that this string is NOT zero-terminated! This format occurs in some THINK C/Symantec C
                    // libraries, like After Dark.
                    if (!symbolApplied) {
                        String asciiSymbol = extractTrailingAsciiSymbol(program, symbolStartAddress, listing);
                        if (asciiSymbol != null) {
                            String normalizedName = asciiSymbol.replace(" ", "_");
                            function.setName(normalizedName, SourceType.ANALYSIS);
                        }
                    }

                } catch (Exception e) {
                    log.appendMsg(String.format("[@%s] Failed to get symbol: %s\n", instruction.getAddress(), e.getMessage()));
                }
            }
        }

        return true;
    }

    /**
     * Try to extract a plain ASCII symbol from the given bytes.
     * Reads printable ASCII characters until hitting non-ASCII or existing code/data.
     */
    private String extractTrailingAsciiSymbol(Program program, Address startAddress,
            Listing listing) {
        try {
            Memory memory = program.getMemory();
            Address currentAddress = startAddress;
            StringBuilder symbolBuilder = new StringBuilder();

            while (memory.contains(currentAddress)) {
                // Stop if we hit existing code or data
                if (listing.getInstructionAt(currentAddress) != null ||
                    listing.getDefinedDataAt(currentAddress) != null) {
                    break;
                }

                byte byteValue = memory.getByte(currentAddress);

                // Check if this is printable ASCII (0x20-0x7E)
                int asciiValue = byteValue & 0xff;
                if (asciiValue < 0x20 || asciiValue > 0x7e) {
                    break;
                }

                symbolBuilder.append((char) asciiValue);
                currentAddress = currentAddress.next();

                if (currentAddress == null) {
                    break;
                }
            }

            // Return symbol if it's long enough
            if (symbolBuilder.length() >= MIN_ASCII_SYMBOL_LENGTH) {
                return symbolBuilder.toString();
            }

        } catch (MemoryAccessException e) {
            // Return null on error
        }

        return null;
    }
}
