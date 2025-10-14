//Resolves M68k Mac syscalls (based on ResolveX86orX64LinuxSyscallsScript)
//@category Analysis.M68k
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
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class M68kMacSyscallScript extends GhidraScript {

    private static final String SYSCALL_SPACE_NAME = "syscall";

    private static final int SYSCALL_SPACE_LENGTH = 0x10000;

    private static final String FP68K_SPACE_NAME = "fp68k";

    private static final int FP68K_SPACE_LENGTH = 0x10000;

    //this is the name of the userop (aka CALLOTHER) in the pcode translation of the
    //native "syscall" instruction
    private static final String SYSCALL_CALLOTHER = "syscall";

    //file containing map from syscall numbers to syscall names
    private static final String syscallFileName = "m68k_mac_syscalls";

    //the calling convention to use for system calls (must be defined in the appropriate .cspec file)
    private static final String callingConvention = "syscall";

    // File containing map from FP68K selectors to function info.
    private static final String fp68kFileName = "m68k_mac_fp68k";
    private static final long FP68K_SYSCALL = 0xa9eb;

    @Override
    protected void run() throws Exception {
        if (!currentProgram.getLanguage().getProcessor().toString().equals("68000")) {
            printf("Processor: %s", currentProgram.getLanguage().getProcessor().toString());
            popup("Processor must be 68000");
            return;
        }

        //get the space where the system calls live.
        //If it doesn't exist, create it.
        AddressSpace syscallSpace =
            currentProgram.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME);
        if (syscallSpace == null) {
            //don't muck with address spaces if you don't have exclusive access to the program.
            if (!currentProgram.hasExclusiveAccess()) {
                popup("Must have exclusive access to " + currentProgram.getName() +
                    " to run this script");
                return;
            }
            Address startAddr = currentProgram.getAddressFactory().getAddressSpace(
                SpaceNames.OTHER_SPACE_NAME).getAddress(0x0L);
            AddUninitializedMemoryBlockCmd cmd = new AddUninitializedMemoryBlockCmd(
                SYSCALL_SPACE_NAME, null, this.getClass().getName(), startAddr,
                SYSCALL_SPACE_LENGTH, true, true, true, false, true);
            if (!cmd.applyTo(currentProgram)) {
                popup("Failed to create " + SYSCALL_SPACE_NAME);
                return;
            }
            syscallSpace = currentProgram.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME);
        }
        else {
            printf("AddressSpace %s found, continuing...\n", SYSCALL_SPACE_NAME);
        }

        //get the space where FP68K functions live.
        //If it doesn't exist, create it.
        AddressSpace fp68kSpace =
            currentProgram.getAddressFactory().getAddressSpace(FP68K_SPACE_NAME);
        if (fp68kSpace == null) {
            if (!currentProgram.hasExclusiveAccess()) {
                popup("Must have exclusive access to " + currentProgram.getName() +
                    " to run this script");
                return;
            }
            Address startAddr = currentProgram.getAddressFactory().getAddressSpace(
                SpaceNames.OTHER_SPACE_NAME).getAddress(0x0L);
            AddUninitializedMemoryBlockCmd cmd = new AddUninitializedMemoryBlockCmd(
                FP68K_SPACE_NAME, null, this.getClass().getName(), startAddr,
                FP68K_SPACE_LENGTH, true, true, true, false, true);
            if (!cmd.applyTo(currentProgram)) {
                popup("Failed to create " + FP68K_SPACE_NAME);
                return;
            }
            fp68kSpace = currentProgram.getAddressFactory().getAddressSpace(FP68K_SPACE_NAME);
        }
        else {
            printf("AddressSpace %s found, continuing...\n", FP68K_SPACE_NAME);
        }

        //get all of the functions that contain system calls
        //note that this will not find system call instructions that are not in defined functions
        Map<Function, Map<Address, Long>> funcsToSyscalls = getSyscallsInFunctions(currentProgram, monitor);
        if (funcsToSyscalls.isEmpty()) {
            popup("No system calls found (within defined functions)");
            return;
        }

        //get the map from system call numbers to system call names
        Map<Long, String> syscallNumberToData = getSyscallNumberMap();
        Map<Long, String> fp68kSelectorToData = getFP68KSelectorMap();

        // Resolve FP68K selectors using symbolic propagation
        Map<Address, Long> fp68kSelectors = resolveFP68KSelectors(funcsToSyscalls, currentProgram, monitor);

        // Flatten the map for easier processing
        Map<Address, Long> addressesToSyscalls = new HashMap<>();
        for (Map<Address, Long> syscallMap : funcsToSyscalls.values()) {
            addressesToSyscalls.putAll(syscallMap);
        }

        DataTypeManager dtm = BuiltInDataTypeManager.getDataTypeManager();

        for (Entry<Address, Long> entry : addressesToSyscalls.entrySet()) {
            Address callSite = entry.getKey();
            Long offset = entry.getValue();
            String syscallName = "syscall_"+String.format("%08X", offset);
            String[] syscallData = null;
            AddressSpace targetSpace = syscallSpace;

            // Check if this is a _FP68K syscall
            if (offset == FP68K_SYSCALL) {
                Long selector = fp68kSelectors.get(callSite);
                if (selector != null) {
                    // Use the FP68K address space and selector as offset
                    targetSpace = fp68kSpace;
                    offset = selector;
                    String fp68kData = fp68kSelectorToData.get(selector);
                    if (fp68kData != null) {
                        // Parse FP68K data: selector, name, comment, # of operands
                        String[] fp68kParts = fp68kData.split(",");
                        if (fp68kParts.length >= 3) {
                            syscallName = "_FP68K_" + fp68kParts[1].trim();
                            // Convert FP68K data to syscallData format for consistent processing
                            syscallData = new String[fp68kParts.length];
                            syscallData[0] = syscallName;
                            // All params are passed on the stack, pushed left-to-right by address.
                            syscallData[1] = "pascal";
                            // All functions actually return void (because they modify their params in-place).
                            syscallData[2] = "void";
                            // Add parameters from remaining fp68kParts
                            if (fp68kParts.length > 3) {
                                // TODO: We need to push the later ones in here. We have something that is null at the end here.
                                printf("Creating FP68K function at %s: %s with %d operands (selector 0x%04x)\n",
                                    callSite, syscallName, fp68kParts.length - 3, selector);
                                for (int i = 3; i < fp68kParts.length; i++) {
                                    syscallData[i] = fp68kParts[i].trim();
                                    printf(fp68kParts[i].trim() + "\n");
                                }
                            } else {
                                printf("Creating FP68K function at %s: %s (selector 0x%04x, no operand count)\n",
                                    callSite, syscallName, selector);
                            }
                        } else {
                            String errorMsg = String.format("ERROR: Invalid FP68K data format for selector 0x%04x at %s\n" +
                                "  Expected format: 'selector, name, comment, operands'\n" +
                                "  Got: %s (only %d parts)\n",
                                selector, callSite, fp68kData, fp68kParts.length);
                            printf(errorMsg);
                            throw new RuntimeException(errorMsg);
                        }
                    } else {
                        printf("Warning: No FP68K data for selector 0x%04x at %s\n", selector, callSite);
                        continue;
                    }
                } else {
                    printf("Warning: Couldn't resolve selector for _FP68K at %s\n", callSite);
                    continue; // Skip this syscall if we can't resolve the selector.
                }
            } else if (syscallNumberToData.get(offset) != null) {
                // Read the syscall data directly.
                syscallData = syscallNumberToData.get(offset).split(",");
                if (syscallData != null) {
                    for (int i = 0; i < syscallData.length; i++) {
                        syscallData[i] = syscallData[i].trim();
                    }
                    syscallName = syscallData[0];
                }
            }

            Address callTarget = targetSpace.getAddress(offset);
            Function callee = currentProgram.getFunctionManager().getFunctionAt(callTarget);
            if (callee == null) {
                callee = createFunction(callTarget, syscallName);
            }
            callee.setCallingConvention(callingConvention);

            try {
                ArrayList<ParameterImpl> params = new ArrayList();
                if (syscallData != null && syscallData.length >= 2) {
                    callee.setCustomVariableStorage(true);
                    String callingConvention = syscallData[1];

                    if (callingConvention.equals("custom")) {
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
                                VariableStorage paramStorage = parseStorage(currentProgram, s.substring(s.indexOf("@")+1).trim());
                                params.add(new ParameterImpl(paramName, paramType, paramStorage, currentProgram));
                            }
                        }
                    }

                    else if (callingConvention.equals("pascal")) {
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
                            }
                            else if (i == 2) { // return type
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
                    } else {
                        printf("Invalid calling convention "+callingConvention);
                    }
                }
                callee.replaceParameters(params, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);
            } catch (InvalidInputException e) {
                printf("Failed to parse syscall data for "+syscallName);
            }
            Reference ref = currentProgram.getReferenceManager().addMemoryReference(callSite,
                callTarget, RefType.CALLOTHER_OVERRIDE_CALL, SourceType.USER_DEFINED, Reference.MNEMONIC);
            //overriding references must be primary to be active
            currentProgram.getReferenceManager().setPrimary(ref, true);
        }
    }

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
        } else {
            return dtm.getDataType("/"+s);
        }
    }

    private VariableStorage parseStorage(Program p, String s) throws InvalidInputException {
        if (s.contains("[")) {
            int stackOffset = Integer.decode(s.substring(s.indexOf("[")+1, s.indexOf("]")).trim());
            int size = Integer.decode(s.substring(s.indexOf(":")+1).trim());
            return new VariableStorage(p, stackOffset, size);
        } else {
            return new VariableStorage(p, p.getLanguage().getRegister(s));
        }
    }

    //TODO: better error checking!
    private Map<Long, String> getSyscallNumberMap() {
        Map<Long, String> syscallMap = new HashMap<>();
        ResourceFile rFile = Application.findDataFileInAnyModule(syscallFileName);
        if (rFile == null) {
            popup("Error opening syscall number file, using default names");
            return syscallMap;
        }
        try (FileReader fReader = new FileReader(rFile.getFile(false));
                BufferedReader bReader = new BufferedReader(fReader)) {
            String line = null;
            while ((line = bReader.readLine()) != null) {
                //lines starting with # are comments
                if (!line.startsWith("#")) {
                    String[] parts = line.trim().split(",", 2);
                    Long number = Long.decode(parts[0].trim());
                    syscallMap.put(number, parts[1].trim());
                }
            }
        }
        catch (IOException e) {
            Msg.showError(this, null, "Error reading syscall map file", e.getMessage(), e);
        }
        return syscallMap;
    }

    /**
     * Scans through all of the functions defined in {@code program} and returns
     * a map which takes a function to the set of addresses in its body which contain
     * system calls
     * @param program program containing functions
     * @param tMonitor monitor
     * @return map function -> addresses in function containing syscalls
     * @throws CancelledException if the user cancels
     */
    private Map<Function, Map<Address, Long>> getSyscallsInFunctions(Program program,
            TaskMonitor tMonitor) throws CancelledException {
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
     * Resolves the FP68K selector for _FP68K syscalls.
     * The selector is pushed onto the stack immediately before the _FP68K syscall.
     * This method looks at the instruction before the syscall to extract the selector value.
     * @param funcsToSyscalls map from functions to syscall addresses and numbers
     * @param program program containing the functions
     * @param tMonitor monitor
     * @return map from addresses of _FP68K syscalls to their selector values
     * @throws CancelledException if the user cancels
     */
    private Map<Address, Long> resolveFP68KSelectors(Map<Function, Map<Address, Long>> funcsToSyscalls,
            Program program, TaskMonitor tMonitor) throws CancelledException {
        Map<Address, Long> addressesToSelectors = new HashMap<>();
        Listing listing = program.getListing();

        printf("\n=== Resolving FP68K Selectors ===\n");

        for (Function func : funcsToSyscalls.keySet()) {
            tMonitor.checkCanceled();

            for (Entry<Address, Long> entry : funcsToSyscalls.get(func).entrySet()) {
                if (entry.getValue() == FP68K_SYSCALL) {
                    Address callSite = entry.getKey();
                    printf("\nFound _FP68K syscall at %s\n", callSite);

                    // Look at the instruction immediately before the _FP68K syscall
                    Instruction prevInst = listing.getInstructionBefore(callSite);
                    if (prevInst != null) {
                        printf("  Previous instruction: %s %s\n",
                            prevInst.getMnemonicString(),
                            prevInst.toString().substring(prevInst.toString().indexOf(' ') + 1));

                        String mnemonic = prevInst.getMnemonicString();

                        // Check for "move.w #selector,-(SP)" pattern
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
                                    printf("  ✓ Extracted selector: 0x%04x\n", selectorValue);
                                    continue;
                                }
                            } else {
                                printf("  ✗ Destination operand is not -(SP): %s\n", destOp);
                            }
                        } else {
                            printf("  ✗ Not a move instruction or insufficient operands\n");
                        }
                    } else {
                        printf("  ✗ No instruction found before _FP68K syscall\n");
                    }

                    printf("  ✗ Warning: Couldn't extract FP68K selector\n");
                }
            }
        }

        printf("\n=== FP68K Selector Resolution Complete ===\n");
        printf("Resolved %d FP68K selectors\n\n", addressesToSelectors.size());

        return addressesToSelectors;
    }

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

    private Map<Long, String> getFP68KSelectorMap() {
        Map<Long, String> fp68kMap = new HashMap<>();
        ResourceFile rFile = Application.findDataFileInAnyModule(fp68kFileName);
        if (rFile == null) {
            popup("Error opening FP68K selector file, using default handling");
            return fp68kMap;
        }
        try (FileReader fReader = new FileReader(rFile.getFile(false));
                BufferedReader bReader = new BufferedReader(fReader)) {
            String line = null;
            while ((line = bReader.readLine()) != null) {
                if (!line.startsWith("#") && line.trim().length() > 0) {
                    String[] parts = line.split(",");
                    if (parts.length >= 4) {
                        Long selector = Long.decode(parts[0].trim());
                        fp68kMap.put(selector, line);
                    }
                }
            }
        }
        catch (IOException e) {
            Msg.showError(this, null, "Error reading FP68K selector map file", e.getMessage(), e);
        }
        return fp68kMap;
    }
}
