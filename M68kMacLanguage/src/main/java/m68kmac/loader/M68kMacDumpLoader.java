package m68kmac.loader;

import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import m68kmac.common.DumperProvidedSymbolNames;

import java.io.IOException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Loader for custom M68k Mac dump format. Eventually, all relocations and such should be done within
 * Ghidra, but for now it is way easier to just load the finished dump.
 *
 * Dumps that start with J A N K are an older format that are a pure memory dump and do NOT contain
 * metadata about the actual names and locations of CODE resources. So they just load as two memory blocks:
 * - SYSTEM: Mac OS low memory globals.
 * - PROGRAM: Code segments plus the entire A5 world.
 *
 * Dumps that start with N E W J may include a prefix header with CODE resource ranges and names, so
 * those CODE resources can be loaded into separate named memory blocks for easier navigation.
 */
public class M68kMacDumpLoader extends AbstractProgramWrapperLoader {

    public static final String LOADER_NAME = "Custom M68k Mac Dump";
    private static final int SYSTEM_GLOBALS_SIZE = 0x10000;

    private static final String DEFAULT_COMPILER_SPEC_ID = "default";
    private static final String CODEWARRIOR_COMPILER_SPEC_ID = "codewarrior";
    private static final String LANGUAGE_ID = "68000:BE:32:mac";

    private static final short SIGNATURE_LENGTH = 8;
    private static final byte[] DUMP_SIGNATURE = { // J A N K
        (byte) 0x4A, (byte) 0xFF, (byte) 0x41, (byte) 0xFF,
        (byte) 0x4E, (byte) 0xFF, (byte) 0x4B, (byte) 0xFF
    };

    // This contains metadata about the CODE resources included in this dump, used
    // to create named blocks for each CODE resource.
    private static final byte[] DUMP_HEADER_SIGNATURE = { // N E W J
        (byte) 0x4E, (byte) 0xFF, (byte) 0x45, (byte) 0xFF,
        (byte) 0x57, (byte) 0xFF, (byte) 0x4A, (byte) 0xFF
    };

    @Override
    public String getName() {
        return LOADER_NAME;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();
        DumpMetadata dumpMetadata = getDumpMetadata(provider);
        if (dumpMetadata != null) {
            // Offer both compiler variants, but mark the one the dump producer recorded in the header
            // as preferred so it is selected automatically.
            boolean codewarriorIsPreferred = CODEWARRIOR_COMPILER_SPEC_ID.equals(dumpMetadata.compilerSpecId);
            loadSpecs.add(new LoadSpec(this, 0,
                new LanguageCompilerSpecPair(LANGUAGE_ID, DEFAULT_COMPILER_SPEC_ID), !codewarriorIsPreferred));
            loadSpecs.add(new LoadSpec(this, 0,
                new LanguageCompilerSpecPair(LANGUAGE_ID, CODEWARRIOR_COMPILER_SPEC_ID), codewarriorIsPreferred));
        }

        return loadSpecs;
    }

    @Override
    protected void load(Program program, Loader.ImporterSettings settings)
            throws CancelledException, IOException {

        // Extract settings using record accessor methods.
        ByteProvider provider = settings.provider();
        TaskMonitor monitor = settings.monitor();
        MessageLog log = settings.log();

        Memory memory = program.getMemory();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

        try {
            // READ THE DUMP HEADER.
            // Read the header from the dump.
            DumpMetadata dumpLayout = getDumpMetadata(provider);
            long memoryImageOffset = dumpLayout.memoryImageOffset;
            long memoryImageLength = provider.length() - memoryImageOffset;

            // CREATE SYSTEM BLOCK.
            // This contains low memory globals for 68k Mac OS.
            monitor.setMessage("Loading SYSTEM block...");
            byte[] systemGlobals = provider.readBytes(memoryImageOffset, SYSTEM_GLOBALS_SIZE);
            Address systemStart = space.getAddress(0);
            MemoryBlock systemBlock = memory.createInitializedBlock(
                "SYSTEM", systemStart, systemGlobals.length,
                (byte)0, monitor, false);
            systemBlock.setRead(true);
            systemBlock.setWrite(true);
            systemBlock.setExecute(false);
            systemBlock.setComment("m68k Classic Mac low memory globals");
            memory.setBytes(systemStart, systemGlobals);

            // CREATE CODE RESOURCE BLOCKS.
            // New dumps carry CODE resource ranges in the prefix header. Older dumps still use
            // one PROGRAM block for all non-system memory.
            monitor.setMessage("Loading CODEs and A5 world...");
            if (dumpLayout.codeResourceMetadataRecords.isEmpty()) {
                // Fall back to previous behavior of putting everything in one PROGRAM block.
                long blockSize = memoryImageLength - SYSTEM_GLOBALS_SIZE;
                createProgramBlock(memory, space, provider, monitor, log, memoryImageOffset,
                    SYSTEM_GLOBALS_SIZE, blockSize,
                    "PROGRAM", "CODEs + A5 World");
            } else {
                createProgramBlocksFromHeader(memory, space, provider, monitor, log, dumpLayout, memoryImageLength);
            }

            // SET A5 REGISTER FOR ENTIRE PROGRAM.
            // This is critical for resolving global data references.
            monitor.setMessage("Setting A5 register value...");
            int a5Value = memory.getInt(space.getAddress(0x904));
            if (a5Value <= SYSTEM_GLOBALS_SIZE || Integer.toUnsignedLong(a5Value) >= memoryImageLength) {
                throw new IOException("Out-of-bounds A5 value: 0x" + Integer.toHexString(a5Value));
            }
            SetRegisterCmd cmd = new SetRegisterCmd(
                program.getLanguage().getRegister("A5"),
                space.getMinAddress(),
                space.getMaxAddress(),
                java.math.BigInteger.valueOf(a5Value));
            if (!cmd.applyTo(program)) {
                log.appendMsg("WARNING: Failed to set A5 register value");
            }

            // STASH RECOVERED SYMBOL NAMES.
            // Park the raw symbol-name section on the program so the symbols analyzer can later resolve
            // inline short MacsBug names to full names (if available). It runs as a separate pass and only has the
            // program to work from, so this must live in the database rather than in loader-local state.
            if (dumpLayout.symbolNameSection.length > 0) {
                program.getOptions(DumperProvidedSymbolNames.OPTIONS_GROUP)
                    .setByteArray(DumperProvidedSymbolNames.SECTION_OPTION, dumpLayout.symbolNameSection);
            }

        } catch (Exception e) {
            log.appendException(e);
            throw new IOException("Failed to load M68k Mac dump: " + e.getMessage(), e);
        }
    }

    private void createProgramBlocksFromHeader(Memory memory, AddressSpace space, ByteProvider provider,
            TaskMonitor monitor, MessageLog log, DumpMetadata dumpLayout, long memoryImageLength)
            throws Exception {
        // We already created the SYSTEM block, so look after that.
        long nextAddressNotInMemoryBlock = SYSTEM_GLOBALS_SIZE;

        for (CodeResourceRecord codeResourceMetadataRecord : dumpLayout.codeResourceMetadataRecords) {
            // Make sure this resource looks sensible.
            boolean codeStartsInSystemGlobals = codeResourceMetadataRecord.startAddress < SYSTEM_GLOBALS_SIZE;
            boolean codeEndsBeforeStart = codeResourceMetadataRecord.endAddress <= codeResourceMetadataRecord.startAddress;
            boolean codeIsLongerThanMemoryImage = codeResourceMetadataRecord.endAddress > memoryImageLength;
            boolean codeOverlapsPreviousRange = codeResourceMetadataRecord.startAddress < nextAddressNotInMemoryBlock;
            boolean codeOutOfBounds = codeStartsInSystemGlobals || codeEndsBeforeStart || codeIsLongerThanMemoryImage || codeOverlapsPreviousRange;
            if (codeOutOfBounds) {
                // TODO: Make this a format string for easier reading.
                log.appendMsg("WARNING: Skipping out-of-bounds CODE resource range " +
                    codeResourceMetadataRecord.name + " [0x" + Long.toHexString(codeResourceMetadataRecord.startAddress) +
                    ", 0x" + Long.toHexString(codeResourceMetadataRecord.endAddress) + ")");
                continue;
            }

            long codeSize = codeResourceMetadataRecord.endAddress - codeResourceMetadataRecord.startAddress;
            createProgramBlock(memory, space, provider, monitor, log,
                dumpLayout.memoryImageOffset, codeResourceMetadataRecord.startAddress, codeSize,
                makeBlockName("CODE", codeResourceMetadataRecord.name), "CODE " + codeResourceMetadataRecord.name);

            nextAddressNotInMemoryBlock = Math.max(nextAddressNotInMemoryBlock, codeResourceMetadataRecord.endAddress);
        }

        // TODO: The A5 world can be before OR after all CODE resources.
        if (nextAddressNotInMemoryBlock < memoryImageLength) {
            createProgramBlock(memory, space, provider, monitor, log, dumpLayout.memoryImageOffset,
                nextAddressNotInMemoryBlock, memoryImageLength - nextAddressNotInMemoryBlock,
                "A5WORLD", "A5 World");
        }
    }

    private void createProgramBlock(Memory memory, AddressSpace space, ByteProvider provider,
            TaskMonitor monitor, MessageLog log, long memoryImageOffset, long startAddress, long size,
            String name, String comment) throws Exception {
        byte[] data = provider.readBytes(memoryImageOffset + startAddress, size);
        Address blockAddress = space.getAddress(startAddress);
        String blockName = getUniqueBlockName(memory, name);
        MemoryBlock block = memory.createInitializedBlock(blockName, blockAddress, data.length, (byte)0, monitor, false);

        block.setRead(true);
        block.setWrite(true);
        block.setExecute(startAddress >= SYSTEM_GLOBALS_SIZE);
        block.setComment(comment);
        memory.setBytes(blockAddress, data);

        // log.appendMsg("Created " + blockName + " block at 0x" + Long.toHexString(startAddress) + ", size: 0x" + Long.toHexString(size));
    }

    private DumpMetadata getDumpMetadata(ByteProvider provider) throws IOException {
        BinaryReader reader = new BinaryReader(provider, false);
        byte[] signature = reader.readNextByteArray(SIGNATURE_LENGTH);
        boolean hasOldDumpSignature = Arrays.equals(signature, DUMP_SIGNATURE);
        if (hasOldDumpSignature) {
            // If the dump file starts at offset 0 with the old JANK signature,
            // then the raw memory image begins at file offset 0 (there is no metadata to parse).
            // This format doesn't name a compiler, so assume the default variant.
            // log.appendMsg("Detected raw image (no metadata)");
            return new DumpMetadata(0, DEFAULT_COMPILER_SPEC_ID, List.of(), new byte[0]);
        }

        // Make sure we have the new dump format before we go any further.
        boolean hasNewDumpSignature = Arrays.equals(signature, DUMP_HEADER_SIGNATURE);
        if (!hasNewDumpSignature) {
            // log.appendMsg("Detected raw image (no metadata)");
            return null;
        }

        String compilerSpecId = reader.readNextAsciiString();
        long memoryImageOffset = Integer.toUnsignedLong(reader.readNextInt());
        long recordCount = Integer.toUnsignedLong(reader.readNextInt());
        if (memoryImageOffset < reader.getPointerIndex() || memoryImageOffset + SYSTEM_GLOBALS_SIZE > provider.length()) {
            // TODO: Throw exception here
            return null;
        }

        List<CodeResourceRecord> codeResources = new ArrayList<>();
        for (long i = 0; i < recordCount; i++) {
            // Read each null-terminated CODE resource name.
            String name = reader.readNextAsciiString();
            long startAddress = Integer.toUnsignedLong(reader.readNextInt());
            long endAddress = Integer.toUnsignedLong(reader.readNextInt());
            codeResources.add(new CodeResourceRecord(name, startAddress, endAddress));
        }
        codeResources.sort((left, right) -> Long.compare(left.startAddress, right.startAddress));

        // Everything between the CODE records and the raw memory image is the full symbol-name section
        // Older dumps end right after the CODE records, leaving nothing here, so this is empty for them.
        // We hand the raw bytes to the symbols analyzer to parse.
        long symbolNameSectionLength = memoryImageOffset - reader.getPointerIndex();
        byte[] symbolNameSection = symbolNameSectionLength > 0
            ? reader.readNextByteArray((int) symbolNameSectionLength)
            : new byte[0];

        return new DumpMetadata(memoryImageOffset, compilerSpecId, codeResources, symbolNameSection);
    }

    private String makeBlockName(String prefix, String name) {
        String sanitizedName = name.replaceAll("[^A-Za-z0-9_.() -]", "_").trim();
        if (sanitizedName.isEmpty()) {
            sanitizedName = "unnamed";
        }
        return prefix + " " + sanitizedName;
    }

    private String getUniqueBlockName(Memory memory, String requestedName) {
        String blockName = requestedName;
        int suffix = 1;
        while (memory.getBlock(blockName) != null) {
            blockName = requestedName + "." + suffix++;
        }
        return blockName;
    }

    private record DumpMetadata(long memoryImageOffset, String compilerSpecId,
        List<CodeResourceRecord> codeResourceMetadataRecords, byte[] symbolNameSection) {}

    private record CodeResourceRecord(String name, long startAddress, long endAddress) {}

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
            DomainObject domainObject, boolean isLoadIntoProgram, boolean loadAsBinary) {
        List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject,
            isLoadIntoProgram, loadAsBinary);
        // Currently no custom options needed
        return list;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
        // Currently no custom options to validate
        return super.validateOptions(provider, loadSpec, options, program);
    }
}
