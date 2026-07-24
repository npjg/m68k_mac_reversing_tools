package m68kmac.analysis;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.framework.options.Options;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import m68kmac.common.DumperProvidedSymbolNames;
import m68kmac.common.DumperProvidedSymbolNames.DumperProvidedSymbolNameRecord;
import m68kmac.datatypes.MacsBugSymbolDataType;

import java.util.HashMap;
import java.util.Map;

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

        // Load any dumper-provided symbol names, keyed by the address of the function each one names.
        Map<Long, DumperProvidedSymbolNameRecord> dumperProvidedNamesByAddress = loadDumperProvidedNames(program, log);

        // Apply a MacsBug symbol stored inline in the code, wherever one sits after a function's return instruction.
        Map<Long, String> inlineStemByAddress = applyInlineSymbols(program, listing, macsBugSymbolDt, monitor, log);

        // Apply any dumper-provided symbol names.
        applyDumperProvidedNames(program, dumperProvidedNamesByAddress, inlineStemByAddress, monitor, log);

        return true;
    }

    /**
     * Apply the MacsBug symbol (either long or short format) stored inline after a function.
     * Return the symbol name found for each function keyed by its start address so any dumper-provided
     * names can be prefix-checked against them.
     */
    private Map<Long, String> applyInlineSymbols(Program program, Listing listing,
            MacsBugSymbolDataType macsBugSymbolDt, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        Map<Long, String> inlineStemByAddress = new HashMap<>();

        // Search each function for return instructions.
        for (Function function : program.getFunctionManager().getFunctionsNoStubs(true)) {
            monitor.checkCancelled();

            // ONLY overwrite default function names.
            if (function.getSymbol().getSource() != SourceType.DEFAULT && !overwriteNonDefaultNames) {
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
                    if (listing.getInstructionAt(symbolStartAddress) != null) {
                        // TODO: Maybe add a comment at this address saying no symbol was found?
                        continue;
                    }

                    // Try to create a long-format MacsBug symbol.
                    String inlineStem = null;
                    MemoryBufferImpl buffer = new MemoryBufferImpl(program.getMemory(), symbolStartAddress);
                    int symbolLength = macsBugSymbolDt.getLength(buffer);
                    if (symbolLength > 0) {
                        // There is probably an auto-detected string here already, so clear existing data
                        // in the symbol range. (Remember we already ensured there was no code here).
                        Address symbolEndAddress = symbolStartAddress.addNoWrap(symbolLength - 1);
                        listing.clearCodeUnits(symbolStartAddress, symbolEndAddress, false);

                        // Create the MacsBug symbol.
                        Data symbolData = listing.createData(symbolStartAddress, macsBugSymbolDt);
                        if (symbolData != null && symbolData.getValue() instanceof String) {
                            inlineStem = (String) symbolData.getValue();
                        }
                    }

                    if (inlineStem != null) {
                        function.setName(inlineStem.replace(" ", "_"), SourceType.ANALYSIS);
                        inlineStemByAddress.put(function.getEntryPoint().getOffset(), inlineStem);
                    }

                } catch (Exception e) {
                    log.appendMsg(
                        String.format("[@%s] Failed to create symbol: %s\n", instruction.getAddress(), e.getMessage())
                    );
                }
            }
        }

        return inlineStemByAddress;
    }

    /**
     * Apply any dumper-provided names.
     */
    private void applyDumperProvidedNames(Program program, Map<Long, DumperProvidedSymbolNameRecord> dumperProvidedNamesByAddress,
            Map<Long, String> inlineStemByAddress, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        for (Map.Entry<Long, DumperProvidedSymbolNameRecord> recoveredEntry : dumperProvidedNamesByAddress.entrySet()) {
            monitor.checkCancelled();

            Address functionAddress = space.getAddress(recoveredEntry.getKey());
            Function function = program.getFunctionManager().getFunctionAt(functionAddress);
            if (function == null) {
                // The metadata says a function lives here but Ghidra didn't find one, so trust the
                // metadata and create the function.
                function = createFunctionAt(program, functionAddress, monitor);
                if (function == null) {
                    log.appendMsg(
                        String.format("[%s] Could not create function for dumper-provided name \"%s\"", functionAddress, recoveredEntry.getValue().symbolName()));
                    continue;
                }
            }

            // Our own MacsBug name is always safe to upgrade; anything else follows the overwrite rule.
            boolean namedByInlinePass = inlineStemByAddress.containsKey(recoveredEntry.getKey());
            boolean canOverwrite = namedByInlinePass
                || function.getSymbol().getSource() == SourceType.DEFAULT
                || overwriteNonDefaultNames;
            if (!canOverwrite) {
                continue;
            }

            applyDumperProvidedName(function, inlineStemByAddress.get(recoveredEntry.getKey()), recoveredEntry.getValue(), log);
        }
    }

    /**
     * Define a function at an address the dumper-provided names says one should occupy but Ghidra hasn't found.
     * Any data already sitting on those bytes is cleared and the region disassembled first. Returns the
     * created function, or null if it could not be created.
     */
    private Function createFunctionAt(Program program, Address address, TaskMonitor monitor) {
        Listing listing = program.getListing();

        // Only lay down code if there isn't any yet; existing instructions are left as they are.
        if (listing.getInstructionAt(address) == null) {
            listing.clearCodeUnits(address, address, false);
            new DisassembleCommand(address, null, true).applyTo(program, monitor);
        }
        new CreateFunctionCmd(address).applyTo(program, monitor);
        return program.getFunctionManager().getFunctionAt(address);
    }

    /**
     * Load any dumper-provided names, keyed by the address of the function each one names.
     */
    private Map<Long, DumperProvidedSymbolNameRecord> loadDumperProvidedNames(Program program, MessageLog log) {
        Map<Long, DumperProvidedSymbolNameRecord> recoveredNameByAddress = new HashMap<>();
        try {
            Options options = program.getOptions(DumperProvidedSymbolNames.OPTIONS_GROUP);
            byte[] symbolNameSection = options.getByteArray(DumperProvidedSymbolNames.SECTION_OPTION, null);
            for (DumperProvidedSymbolNameRecord record : DumperProvidedSymbolNames.parse(symbolNameSection)) {
                recoveredNameByAddress.put(record.startAddress(), record);
            }
        } catch (Exception e) {
            log.appendMsg("Could not read recovered symbol names: " + e.getMessage());
        }
        return recoveredNameByAddress;
    }

    /**
     * Apply a dumper-provided name to the function it names.
     */
    private void applyDumperProvidedName(Function function, String inlineStem,
            DumperProvidedSymbolNameRecord dumperProvidedName, MessageLog log) {
        String fullSymbolName = dumperProvidedName.symbolName();

        // As a sanity check, make sure the name we are replacing is a prefix of the dumper-provided name.
        // Refuse to clobber the existing name if not.
        // Compare case-insensitively.
        String unpaddedStem = inlineStem == null ? null : inlineStem.replaceAll(" +$", "");
        boolean inlineStemIsPrefix = unpaddedStem == null
            || fullSymbolName.regionMatches(true, 0, unpaddedStem, 0, unpaddedStem.length());
        if (!inlineStemIsPrefix) {
            String mismatchedPrefixWarning = String.format(
                "[@%s] Keeping MacsBug symbol \"%s\" because it is not a prefix of dumper-provided name \"%s\"", function.getEntryPoint(), inlineStem, fullSymbolName);
            log.appendMsg(mismatchedPrefixWarning);
            function.getProgram().getListing().setComment(function.getEntryPoint(), CommentType.PLATE, mismatchedPrefixWarning);
            return;
        }

        try {
            function.setName(fullSymbolName.replace(" ", "_"), SourceType.ANALYSIS);
        } catch (Exception e) {
            log.appendMsg(
                String.format("[@%s] Failed to apply dumper-provided name: %s", function.getEntryPoint(), e.getMessage())
            );
        }
    }
}
