package m68kmac.loader;

import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.util.Option;
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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Loader for custom M68k Mac dump format. Eventually, all relocations and such should be done within
 * Ghidra, but for now it is way easier to just load the finished dump.
 *
 * This loader creates two memory blocks:
 * - SYSTEM: Mac OS low memory globals (0x0 - 0x10000).
 * - PROGRAM: Code segments plus the entire A5 world (0x10000 onwards).
 *
 * To really do justice to the dump, we should create memory blocks for each CODE resource, as well as
 * the A5 world. That would be the cleanest, but it requires more information than is currently saved
 * in the dump. So we will live with two memory regions for now.
 */
public class M68kMacDumpLoader extends AbstractProgramWrapperLoader {

    public static final String LOADER_NAME = "Custom M68k Mac Dump";
    private static final int SYSTEM_RAM_SIZE = 0x10000;
    private static final byte[] DUMP_SIGNATURE = {
        (byte) 0x4A, (byte) 0xFF, (byte) 0x41, (byte) 0xFF,
        (byte) 0x4E, (byte) 0xFF, (byte) 0x4B, (byte) 0xFF
    };

    @Override
    public String getName() {
        return LOADER_NAME;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // Check for our dump format signature at start.
        if (provider.length() < SYSTEM_RAM_SIZE) {
            return loadSpecs;
        }
        byte[] header = provider.readBytes(0, DUMP_SIGNATURE.length);
        boolean isValidDump = true;
        for (int i = 0; i < DUMP_SIGNATURE.length; i++) {
            if (header[i] != DUMP_SIGNATURE[i]) {
                isValidDump = false;
                break;
            }
        }

        if (isValidDump) {
            // Add 68000 language spec.
            loadSpecs.add(new LoadSpec(this, 0,
                new LanguageCompilerSpecPair("68000:BE:32:mac", "default"), true));
        }

        return loadSpecs;
    }

    @Override
    protected void load(Program program, Loader.ImporterSettings settings)
            throws CancelledException, IOException {

        // Extract settings using record accessor methods.
        ByteProvider provider = settings.provider();
        LoadSpec loadSpec = settings.loadSpec();
        List<Option> options = settings.options();
        TaskMonitor monitor = settings.monitor();
        MessageLog log = settings.log();

        Memory memory = program.getMemory();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        InputStream input = provider.getInputStream(0);

        try {
            // CREATE SYSTEM BLOCK.
            // This contains low memory globals for 68k Mac OS.
            monitor.setMessage("Loading SYSTEM block...");
            byte[] systemRam = new byte[SYSTEM_RAM_SIZE];
            int bytesRead = input.read(systemRam);
            if (bytesRead != SYSTEM_RAM_SIZE) {
                throw new IOException("Failed to read complete SYSTEM block");
            }

            Address systemStart = space.getAddress(0);
            MemoryBlock systemBlock = memory.createInitializedBlock(
                "SYSTEM", systemStart, systemRam.length,
                (byte)0, monitor, false);
            systemBlock.setRead(true);
            systemBlock.setWrite(true);
            systemBlock.setExecute(false);
            systemBlock.setComment("68k Mac OS low memory globals");
            memory.setBytes(systemStart, systemRam);

            // READ A5 VALUE for register context.
            int a5Value = readInt(systemRam, 0x904);
            if (a5Value <= SYSTEM_RAM_SIZE || a5Value >= provider.length()) {
                throw new IOException("Out-of-bounds A5 value: 0x" + Integer.toHexString(a5Value));
            }

            // CREATE PROGRAM BLOCK.
            // Include everything onwards in the dump (code segments and entire A5 world).
            monitor.setMessage("Loading PROGRAM block...");
            long programStart = SYSTEM_RAM_SIZE;
            long programSize = provider.length() - programStart;
            byte[] programData = new byte[(int)programSize];
            bytesRead = input.read(programData);
            if (bytesRead != programSize) {
                throw new IOException("Failed to read complete PROGRAM block");
            }

            Address programAddr = space.getAddress(programStart);
            MemoryBlock programBlock = memory.createInitializedBlock(
                "PROGRAM", programAddr, programData.length,
                (byte)0, monitor, false);
            programBlock.setRead(true);
            programBlock.setWrite(true);
            programBlock.setExecute(true);
            programBlock.setComment("Code segments and entire A5 world");
            memory.setBytes(programAddr, programData);
            log.appendMsg("Created PROGRAM block at 0x" +
                Long.toHexString(programStart) + ", size: 0x" +
                Long.toHexString(programSize));

            // SET A5 REGISTER FOR ENTIRE PROGRAM.
            // This is critical for resolving global data references.
            monitor.setMessage("Setting A5 register value...");
            SetRegisterCmd cmd = new SetRegisterCmd(
                program.getLanguage().getRegister("A5"),
                space.getMinAddress(),
                space.getMaxAddress(),
                java.math.BigInteger.valueOf(a5Value));
            if (!cmd.applyTo(program)) {
                log.appendMsg("WARNING: Failed to set A5 register value");
            }

        } catch (Exception e) {
            log.appendException(e);
            throw new IOException("Failed to load M68k Mac dump: " + e.getMessage(), e);
        } finally {
            input.close();
        }
    }

    /**
     * Read a big-endian 32-bit integer from a byte array.
     */
    private int readInt(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24) |
               ((data[offset + 1] & 0xFF) << 16) |
               ((data[offset + 2] & 0xFF) << 8) |
               (data[offset + 3] & 0xFF);
    }

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
