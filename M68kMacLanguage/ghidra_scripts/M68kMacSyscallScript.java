// Resolves M68k Mac syscalls.
// @category Analysis.M68k
import java.io.*;
import java.util.*;
import java.util.Map.Entry;

import generic.jar.ResourceFile;
import ghidra.app.cmd.memory.AddUninitializedMemoryBlockCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.lang.BasicCompilerSpec;
import ghidra.program.model.lang.SpaceNames;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

// Originally based on ResolveX86orX64LinuxSyscallsScript, but extensively refactored to be  easier to understand.

public class M68kMacSyscallScript extends GhidraScript {
    private static final String SYSCALL_SPACE_NAME = "syscall";
    private static final int SYSCALL_SPACE_LENGTH = 0x10000;

    private static final String FP68K_SPACE_NAME = "fp68k";
    private static final int FP68K_SPACE_LENGTH = 0x10000;
    private static final long FP68K_SYSCALL_TRAP_NUMBER = 0xa9eb;

    // This is the name of the userop (aka CALLOTHER) in the pcode translation of the native "syscall" instruction.
    private static final String SYSCALL_CALLOTHER = "syscall";

    // The calling convention to use for system calls (must be defined in the appropriate CSPEC).
    private static final String SYSCALL_CALLING_CONVENTION_NAME = "syscall";
    private static final String FP68K_CALLING_CONVENTION_NAME = "__stdcall";

    // File containing maps from syscall numbers/selectors to function info.
    private static final String SYSCALL_DATA_FILENAME = "m68k_mac_syscalls";
    private static final String FP68K_DATA_FILENAME = "m68k_mac_fp68k";

    private AddressSpace syscallSpace;
    private AddressSpace fp68kSpace;
    private Map<Long, String> syscallNumberToData;
    private Map<Long, String> fp68kSelectorToData;
    private Map<Address, Long> fp68kSelectors;
    private DataTypeManager dtm;

    /**
     * Carries the normalized target metadata needed to create or update the synthetic callee
     * for one syscall site. The rest of the script consumes this shape regardless of whether
     * the source was a normal trap or an FP68K selector-based subcall.
     */
    private class SyscallResolution {
        private long syscallNumber;
        private String syscallName;
        private String[] syscallData;
        private AddressSpace targetSpace;
        private boolean isFP68K;

        private SyscallResolution(long syscallNumber) {
            this.syscallNumber = syscallNumber;
            this.syscallName = "syscall_" + String.format("%08X", syscallNumber);
            this.syscallData = null;
            this.targetSpace = syscallSpace;
            this.isFP68K = false;
        }
    }

    @Override
    protected void run() throws Exception {
        // VERIFY THE PROCESSOR.
        // TODO: Also make sure we are on the Mac variant.
        if (!currentProgram.getLanguage().getProcessor().toString().equals("68000")) {
            printf("Processor: %s", currentProgram.getLanguage().getProcessor().toString());
            popup("Processor must be 68000");
            return;
        }

        // GET SYSCALL ADDRESS SPACES.
        syscallSpace = getOrCreateAddressSpace(SYSCALL_SPACE_NAME, SYSCALL_SPACE_LENGTH);
        if (syscallSpace == null) {
            return;
        }
        // The FP68K selectors are in a separate address space since they are basically sub-syscalls of
        // FP68K, and putting them in the same address space as the main syscalls would cause weird conflicts.
        fp68kSpace = getOrCreateAddressSpace(FP68K_SPACE_NAME, FP68K_SPACE_LENGTH);
        if (fp68kSpace == null) {
            return;
        }

        // READ SYSCALL NAME AND PARAM DATA.
        syscallNumberToData = getSyscallNumberMap();
        fp68kSelectorToData = getFP68KSelectorMap();

        // GET ALL FUNCTIONS THAT HAVE SYSCALLS.
        // Note that this will not find system call instructions that are not in defined functions.
        Map<Function, Map<Address, Long>> funcsToSyscalls = getSyscallsInFunctions(currentProgram, monitor);
        if (funcsToSyscalls.isEmpty()) {
            popup("No system calls found within defined functions. Maybe analysis needs to be run first?");
            return;
        }
        // We also want to extract FP68K selectors from all FP68K syscall sites that we found.
        fp68kSelectors = resolveFP68KSelectors(funcsToSyscalls, currentProgram, monitor);

        // LABEL EACH SYSCALL CALL SITE.
        dtm = BuiltInDataTypeManager.getDataTypeManager();
        for (Map<Address, Long> syscallMap : funcsToSyscalls.values()) {
            // Label each syscall in this function.
            for (Entry<Address, Long> entry : syscallMap.entrySet()) {
                labelSyscallSite(entry);
            }
        }
    }

    /**
     * Converts one discovered syscall site into a stable analysis artifact.
     */
    private void labelSyscallSite(Entry<Address, Long> entry) throws Exception {
        // GET THE SYSCALL TARGET.
        // In Ghidra, this should look something like the following once we are done:
        //                          **************************************************************
        //                          *                          FUNCTION                          *
        //                          **************************************************************
        //                          void __stdcall _FP68K_FADDD(pointer src, pointer dest, u
        //          void              <VOID>         <RETURN>
        //          pointer           Stack[0x6]:4   src
        //          pointer           Stack[0x2]:4   dest
        //          ushort            Stack[0x0]:2   opword
        //                          _FP68K_FADDD
        //  k::00000800                 ??         ??
        //  k::00000801                 ??         ??
        Address syscallSite = entry.getKey();
        Long syscallNumber = entry.getValue();
        SyscallResolution callResolution;
        if (syscallNumber == FP68K_SYSCALL_TRAP_NUMBER) {
            callResolution = resolveFp68kCallMetadata(syscallSite, syscallNumber);
        } else {
            callResolution = resolveRegularSyscallMetadata(syscallNumber);
        }
        if (callResolution == null) {
            return;
        }
        Address callTarget = callResolution.targetSpace.getAddress(callResolution.syscallNumber);

        // CREATE THE STUB SYSCALL FUNCTION IN THE RESPECTIVE ADDRESS SPACE.
        Function callee = currentProgram.getFunctionManager().getFunctionAt(callTarget);
        if (callee == null) {
            callee = createFunction(callTarget, callResolution.syscallName);
        }
        callee.setCallingConvention(callResolution.isFP68K ? FP68K_CALLING_CONVENTION_NAME : SYSCALL_CALLING_CONVENTION_NAME);

        // APPLY THE FUNCTION SIGNATURE TO THE STUB SYSCALL FUNCTION.
        ArrayList<ParameterImpl> syscallParams = new ArrayList();
        if (callResolution.syscallData != null && callResolution.syscallData.length >= 2) {
            callee.setCustomVariableStorage(true);

            String dataCallingConvention = callResolution.syscallData[1];
            if (dataCallingConvention.equals("custom")) {
                applyCustomSignatureToSyscall(callee, callResolution.syscallData, syscallParams, dtm);

            } else if (dataCallingConvention.equals("pascal")) {
                applyPascalSignatureToSyscall(callee, callResolution.syscallData, syscallParams, dtm);

            } else {
                printf("WARNING: Invalid calling convention " + dataCallingConvention);
            }
        }
        callee.replaceParameters(syscallParams, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);

        // CREATE AN EXPLICIT CROSS-REFERENCE FROM THE SYSCALL SITE TO THE STUB.
        // From the syscall call site to the syscall stub.
        Reference ref = currentProgram.getReferenceManager().addMemoryReference(
            syscallSite, callTarget, RefType.CALLOTHER_OVERRIDE_CALL, SourceType.USER_DEFINED, Reference.MNEMONIC);
        // Make this override the active/authoritative reference when multiple refs could exist from
        // the same source operand.
        currentProgram.getReferenceManager().setPrimary(ref, true);
    }

    /**
     * Resolves FP68K-specific metadata for a trap site. FP68K calls are two-stage (trap plus
     * selector), so this method translates the call site into selector-backed target metadata
     * and adapts selector table rows into the shared syscall signature format.
     */
    private SyscallResolution resolveFp68kCallMetadata(Address callSite, Long syscallNumber) {
        SyscallResolution callResolution = new SyscallResolution(syscallNumber);
        callResolution.isFP68K = true;
        Long selector = fp68kSelectors.get(callSite);
        if (selector != null) {
            // Use the FP68K address space and selector as syscall number.
            callResolution.targetSpace = fp68kSpace;
            callResolution.syscallNumber = selector;

            String fp68kData = fp68kSelectorToData.get(selector);
            if (fp68kData != null) {
                // PARSE FP68K DATA.
                // The format is "selector, name, comment, operand1, operand2, ...". Like the following:
                //  0x280a, FCPXL, compare long (signal invalid if unordered), pointer src, pointer dest, word opword
                String[] fp68kParts = fp68kData.split(",");
                if (fp68kParts.length >= 3) {
                    callResolution.syscallName = "_FP68K_" + fp68kParts[1].trim();
                    // Convert FP68K data to syscallData format for consistent processing.
                    callResolution.syscallData = new String[fp68kParts.length];
                    callResolution.syscallData[0] = callResolution.syscallName;
                    // All params are passed on the stack, pushed left-to-right by address.
                    callResolution.syscallData[1] = "pascal";
                    // All functions actually return void (because they modify their params in-place).
                    callResolution.syscallData[2] = "void";
                    // Add parameters from remaining fp68kParts.
                    if (fp68kParts.length > 3) {
                        // TODO: We need to push the later ones in here. We have something that is null at the end here.
                        for (int i = 3; i < fp68kParts.length; i++) {
                            callResolution.syscallData[i] = fp68kParts[i].trim();
                        }
                    }

                } else {
                    String errorMsg = String.format("ERROR: Invalid FP68K data format for selector 0x%04x at %s:\n %s\n", selector, callSite, fp68kData);
                    printf(errorMsg);
                    throw new RuntimeException(errorMsg);
                }
            } else {
                printf("WARNING: No FP68K data for selector 0x%04x at %s\n", selector, callSite);
                return null;
            }
        } else {
            printf("WARNING: Couldn't resolve selector for _FP68K at %s\n", callSite);
            return null; // Skip this syscall if we can't resolve the selector.
        }
        return callResolution;
    }

    /**
     * Resolves a non-FP68K syscall using the primary syscall table and normalizes the parsed
     * metadata into a {@link SyscallResolution}. If no table row exists, the default synthetic
     * name remains in place so analysis can still proceed deterministically.
     */
    private SyscallResolution resolveRegularSyscallMetadata(Long syscallNumber) {
        SyscallResolution callResolution = new SyscallResolution(syscallNumber);
        String rawSyscallData = syscallNumberToData.get(callResolution.syscallNumber);
        if (rawSyscallData != null) {
            // Read the syscall data directly.
            callResolution.syscallData = rawSyscallData.split(",");
            if (callResolution.syscallData != null) {
                for (int i = 0; i < callResolution.syscallData.length; i++) {
                    callResolution.syscallData[i] = callResolution.syscallData[i].trim();
                }
                callResolution.syscallName = callResolution.syscallData[0];
            }
        }
        return callResolution;
    }

    /**
     * Applies a signature row using explicit storage locations from the metadata file.
     */
    private void applyCustomSignatureToSyscall(
            Function callee, String[] syscallData,
            ArrayList<ParameterImpl> params, DataTypeManager dtm) throws InvalidInputException {
        for (int i = 2; i < syscallData.length; i++) {
            String s = syscallData[i];
            if (s.equals("noreturn")) {
                callee.setNoReturn(true);

            } else if (s.startsWith("purge")) {
                int purgeSize = Integer.decode(s.substring(5).trim());
                callee.setStackPurgeSize(purgeSize);

            } else if (i == 2) { // return type
                if (s.equals("void")) {
                    callee.setReturn(DataType.VOID, VariableStorage.VOID_STORAGE, SourceType.USER_DEFINED);

                } else {
                    String[] returnData = s.split("@");
                    DataType returnType = parseType(dtm, returnData[0].trim());
                    VariableStorage returnStorage = parseStorage(currentProgram, returnData[1].trim());
                    callee.setReturn(returnType, returnStorage, SourceType.USER_DEFINED);
                }

            } else {
                String paramName = s.substring(s.indexOf(" "), s.indexOf("@")).trim();
                DataType paramType = parseType(dtm, s.substring(0, s.indexOf(" ")));
                VariableStorage paramStorage = parseStorage(currentProgram,
                    s.substring(s.indexOf("@") + 1).trim());
                params.add(new ParameterImpl(paramName, paramType, paramStorage, currentProgram));
            }
        }
    }

    /**
     * Applies a Pascal-style stack signature by computing purge size and stack slots from the
     * declared types. This is primarily used for FP68K entries.
     */
    private void applyPascalSignatureToSyscall(
            Function callee, String[] syscallData,
            ArrayList<ParameterImpl> params, DataTypeManager dtm) throws InvalidInputException {
        int purgeSize = 0;
        // skip return type
        for (int i = 3; i < syscallData.length; i++) {
            String s = syscallData[i];
            if (s.equals("noreturn")) {
                continue;

            } else {
                purgeSize += parseType(dtm, s.substring(0, s.indexOf(" "))).getLength();
            }
        }

        callee.setStackPurgeSize(purgeSize);
        int stackPtr = purgeSize;
        for (int i = 2; i < syscallData.length; i++) {
            String s = syscallData[i];
            if (s.equals("noreturn")) {
                callee.setNoReturn(true);

            } else if (i == 2) { // return type
                if (s.equals("void")) {
                    callee.setReturn(DataType.VOID, VariableStorage.VOID_STORAGE, SourceType.USER_DEFINED);

                } else {
                    DataType returnType = parseType(dtm, s);
                    int size = returnType.getLength();
                    VariableStorage returnStorage = new VariableStorage(currentProgram, purgeSize, size);
                    callee.setReturn(returnType, returnStorage, SourceType.USER_DEFINED);
                }

            } else {
                String paramName = s.substring(s.indexOf(" ")).trim();
                DataType paramType = parseType(dtm, s.substring(0, s.indexOf(" ")));
                int size = paramType.getLength();
                VariableStorage paramStorage = new VariableStorage(currentProgram, stackPtr - size, size);
                stackPtr -= size;
                params.add(new ParameterImpl(paramName, paramType, paramStorage, currentProgram));
            }
        }
    }

    /**
     * Maps compact type tokens from the metadata files into concrete Ghidra datatypes.
     */
    private DataType parseType(DataTypeManager dtm, String s) {
        if (s.contains("out")) {
            String dataTypeName = s + "_be_careful_check_address";
            DataType[] datatypes = getDataTypes(dataTypeName);
            DataType dt = null;
            if (datatypes.length == 0) {
                // absolutely awful
                int size = Integer.parseInt(s.substring(3));
                DataType struct = new PointerDataType(new StructureDataType("_"+dataTypeName, 0), size);
                dt = new TypedefDataType(dataTypeName, struct);

            } else {
                dt = datatypes[0];
            }
            return dt;

        } else if (s.equals("pointer")) {
            // Generic pointer type for FP68K parameters
            return new PointerDataType(dtm);

        } else if (s.equals("word")) {
            // 16-bit unsigned integer (opword selector)
            return new UnsignedShortDataType(dtm);

        } else {
            DataType dt = dtm.getDataType("/"+s);
            if (dt == null) {
                printf("WARNING: Could not resolve data type '%s', using default pointer\n", s);
                return new PointerDataType(dtm);
            }
            return dt;
        }
    }

    /**
     * Decodes the storage token syntax used by the syscall metadata into Ghidra variable storage.
     * Supports both explicit stack offsets and named-register storage declarations.
     */
    private VariableStorage parseStorage(Program p, String s) throws InvalidInputException {
        if (s.contains("[")) {
            int stackOffset = Integer.decode(s.substring(s.indexOf("[")+1, s.indexOf("]")).trim());
            int size = Integer.decode(s.substring(s.indexOf(":")+1).trim());
            return new VariableStorage(p, stackOffset, size);

        } else {
            return new VariableStorage(p, p.getLanguage().getRegister(s));
        }
    }

    /**
     * Builds the working set of syscall sites to process by scanning instructions in non-stub
     * functions and extracting trap numbers from decoded userops. Preserves grouping by containing function.
     */
    private Map<Function, Map<Address, Long>> getSyscallsInFunctions(
            Program program, TaskMonitor tMonitor) throws CancelledException {
        Map<Function, Map<Address, Long>> funcsToSyscalls = new HashMap<>();
        for (Function func : program.getFunctionManager().getFunctionsNoStubs(true)) {
            tMonitor.checkCanceled();
            for (Instruction inst : program.getListing().getInstructions(func.getBody(), true)) {
                Long syscallNum = instructionToSyscallNumber(inst);
                if (syscallNum != null) {
                    Map<Address, Long> syscallMap = funcsToSyscalls.get(func);
                    if (syscallMap == null) {
                        syscallMap = new HashMap<>();
                        funcsToSyscalls.put(func, syscallMap);
                    }
                    syscallMap.put(inst.getAddress(), syscallNum);
                }
            }
        }
        return funcsToSyscalls;
    }

    /**
     * Interprets one instruction as a syscall trap when its pcode contains the expected
     * CALLOTHER userop and the instruction bytes encode a trap value. Returns {@code null} for
     * non-syscall instructions or when instruction bytes are unavailable.
     */
    private Long instructionToSyscallNumber(Instruction inst) {
        try {
            Long retVal = null;
            for (PcodeOp op : inst.getPcode()) {
                if (op.getOpcode() == PcodeOp.CALLOTHER) {
                    int index = (int) op.getInput(0).getOffset();
                    if (inst.getProgram().getLanguage().getUserDefinedOpName(index).equals(
                        SYSCALL_CALLOTHER)) {
                        byte[] bytes = inst.getBytes();
                        retVal = (((long)bytes[0] & 0xFF) << 8) | ((long)bytes[1] & 0xFF);
                    }
                }
            }
            return retVal;
        } catch (MemoryAccessException e) {
            return null;
        }
    }

    /**
     * Recovers FP68K selector values for call sites previously identified as FP68K traps. The
     * current strategy pattern-matches the immediately preceding push-style move.
     */
    private Map<Address, Long> resolveFP68KSelectors(
            Map<Function, Map<Address, Long>> funcsToSyscalls,
            Program program, TaskMonitor tMonitor) throws CancelledException {
        Map<Address, Long> addressesToSelectors = new HashMap<>();
        Listing listing = program.getListing();

        for (Function func : funcsToSyscalls.keySet()) {
            tMonitor.checkCanceled();

            for (Entry<Address, Long> entry : funcsToSyscalls.get(func).entrySet()) {
                if (entry.getValue() == FP68K_SYSCALL_TRAP_NUMBER) {
                    Address callSite = entry.getKey();
                    // Look at the instruction immediately before the _FP68K syscall
                    Instruction prevInst = listing.getInstructionBefore(callSite);
                    if (prevInst != null) {
                        // Check for "move.w #selector,-(SP)" pattern
                        String mnemonic = prevInst.getMnemonicString();
                        if (mnemonic.startsWith("move") && prevInst.getNumOperands() >= 2) {
                            // Check if destination is -(SP) or -(A7)
                            String destOp = prevInst.getDefaultOperandRepresentation(1);
                            if (destOp.contains("-(SP)") || destOp.contains("-(A7)")) {
                                // Extract the immediate value (selector) from the first operand
                                Object[] srcObjs = prevInst.getOpObjects(0);
                                if (srcObjs != null && srcObjs.length > 0 && srcObjs[0] instanceof Scalar) {
                                    Scalar selector = (Scalar) srcObjs[0];
                                    long selectorValue = selector.getUnsignedValue();
                                    addressesToSelectors.put(callSite, selectorValue);
                                    continue;
                                }
                            } else {
                                printf("WARNING: Destination operand is not -(SP): %s\n", destOp);
                            }
                        } else {
                            printf("WARNING: Not a move instruction or insufficient operands\n");
                        }
                    } else {
                        printf("WARNING: No instruction found before _FP68K syscall\n");
                    }

                    printf("WARNING: Couldn't extract FP68K selector\n");
                }
            }
        }

        return addressesToSelectors;
    }

    /**
     * Loads the primary syscall metadata table.
     */
    private Map<Long, String> getSyscallNumberMap() {
        Map<Long, String> syscallMap = new HashMap<>();
        ResourceFile rFile = Application.findDataFileInAnyModule(SYSCALL_DATA_FILENAME);
        if (rFile == null) {
            popup("ERROR: Couldn't open syscall data file, using default names!");
            return syscallMap;
        }

        try (FileReader fReader = new FileReader(rFile.getFile(false));
                BufferedReader bReader = new BufferedReader(fReader)) {
            String line = null;
            while ((line = bReader.readLine()) != null) {
                boolean lineIsComment = line.startsWith("#");
                boolean lineIsEmpty = line.trim().length() == 0;
                if (lineIsComment || lineIsEmpty) {
                    continue;
                }

                String[] parts = line.trim().split(",", 2);
                Long number = Long.decode(parts[0].trim());
                syscallMap.put(number, parts[1].trim());
            }
        }
        catch (IOException e) {
            Msg.showError(this, null, "ERROR: Couldn't read syscall data file!", e.getMessage(), e);
        }
        return syscallMap;
    }

    /**
     * Loads the FP68k selectors metadata table.
     */
    private Map<Long, String> getFP68KSelectorMap() {
        Map<Long, String> fp68kMap = new HashMap<>();
        ResourceFile rFile = Application.findDataFileInAnyModule(FP68K_DATA_FILENAME);
        if (rFile == null) {
            popup("ERROR: Couldn't open FP68K data file. FP68K handling likely won't work.");
            return fp68kMap;
        }
        try (FileReader fReader = new FileReader(rFile.getFile(false));
                BufferedReader bReader = new BufferedReader(fReader)) {
            String line = null;
            while ((line = bReader.readLine()) != null) {
                boolean lineIsComment = line.startsWith("#");
                if (lineIsComment) {
                    continue;
                }

                String[] parts = line.split(",");
                if (parts.length >= 4) {
                    Long selector = Long.decode(parts[0].trim());
                    fp68kMap.put(selector, line);
                }
            }
        }
        catch (IOException e) {
            Msg.showError(this, null, "ERROR: Couldn't read FP68K data file", e.getMessage(), e);
        }
        return fp68kMap;
    }

    /**
     * Ensures the synthetic address space used for syscall stubs exists.
     */
    private AddressSpace getOrCreateAddressSpace(String spaceName, int spaceLength) {
        AddressSpace addressSpace = currentProgram.getAddressFactory().getAddressSpace(spaceName);
        if (addressSpace == null) {
            // Don't muck with address spaces if we don't have exclusive access to the program.
            if (!currentProgram.hasExclusiveAccess()) {
                popup("Must have exclusive access to " + currentProgram.getName() + " to run this script");
                return null;
            }

            Address startAddr = currentProgram.getAddressFactory().getAddressSpace(
                SpaceNames.OTHER_SPACE_NAME).getAddress(0x0L);
            AddUninitializedMemoryBlockCmd cmd = new AddUninitializedMemoryBlockCmd(
                spaceName, null, this.getClass().getName(), startAddr,
                spaceLength, true, true, true, false, true);

            if (!cmd.applyTo(currentProgram)) {
                popup("Failed to create " + spaceName);
                return null;
            }
            addressSpace = currentProgram.getAddressFactory().getAddressSpace(spaceName);
        }
        else {
            printf("INFO: Address space %s already exists\n", spaceName);
        }
        return addressSpace;
    }
}
