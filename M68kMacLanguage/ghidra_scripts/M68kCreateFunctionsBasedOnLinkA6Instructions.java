// Create functions using ASCII strings as anchors for CodeWarrior 68k binaries
// @author
// @category Analysis.M68k
// @keybinding
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.lang.*;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.data.*;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

public class M68kCreateFunctionsBasedOnLinkA6Instructions extends GhidraScript {

    private Address startAddress = null;

    private List<Address> getExistingStrings(MemoryBlock block) {
        List<Address> stringAddresses = new ArrayList<>();

        try {
            Listing listing = currentProgram.getListing();

            // Get all defined data in the block
            DataIterator dataIterator = listing.getDefinedData(block.getStart(), true);

            while (dataIterator.hasNext() && monitor.isCancelled() == false) {
                Data data = dataIterator.next();

                // Check if this data is after our start address
                if (startAddress != null && data.getAddress().compareTo(startAddress) < 0) {
                    continue;
                }

                // Check if this is a string type
                DataType dataType = data.getDataType();
                if (dataType instanceof StringDataType ||
                    dataType instanceof TerminatedStringDataType ||
                    (dataType instanceof TypeDef &&
                     ((TypeDef)dataType).getBaseDataType() instanceof AbstractStringDataType)) {

                    // Get the string value
                    Object value = data.getValue();
                    String stringValue = (value != null) ? value.toString() : "";

                    println("[INFO] Found existing string at " + data.getAddress() + ": \"" + stringValue + "\"");
                    stringAddresses.add(data.getAddress());
                }
            }
        } catch (Exception e) {
            println("[ERROR] Exception while getting existing strings: " + e.getMessage());
        }

        // Sort addresses
        Collections.sort(stringAddresses, (a, b) -> a.compareTo(b));
        return stringAddresses;
    }

    private Address findFunctionStart(Memory memory, Address searchStart, Address searchEnd) {
        // Look for the start of executable code after the previous string
        Address currentAddr = searchStart;

        try {
            while (currentAddr.compareTo(searchEnd) < 0) {
                // Skip padding bytes (common alignment values)
                byte b = memory.getByte(currentAddr);
                if (b == 0x00 || b == (byte) 0xFF || b == (byte) 0x9D) {
                    currentAddr = currentAddr.add(1);
                    continue;
                }

                // Check if this looks like the start of an instruction
                // Look for common M68k instruction patterns
                if (currentAddr.add(1).compareTo(searchEnd) < 0) {
                    byte[] bytes = new byte[2];
                    memory.getBytes(currentAddr, bytes);
                    int word = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);

                    // Check for common function start patterns
                    // MOVEA.L (SP+n),A1 (0x226F xxxx), LINK A6,#n (0x4E56), etc.
                    if ((word & 0xFFF8) == 0x226F ||  // MOVEA.L (SP+n),A1
                        (word & 0xFFF8) == 0x206F ||  // MOVEA.L (SP+n),A0
                        word == 0x4E56 ||             // LINK A6,#n
                        (word & 0xF000) == 0x2000 ||  // MOVE.L variants
                        (word & 0xF000) == 0x4000) {  // Various common opcodes

                        return currentAddr;
                    }
                }

                currentAddr = currentAddr.add(1);
            }
        } catch (Exception e) {
            // Return best guess if exception
        }

        return currentAddr;
    }

    private Address findFunctionEnd(Memory memory, Address functionStart, Address nextStringAddr) {
        // Look backwards from the next string to find where the function likely ends
        Address searchAddr = nextStringAddr.subtract(1);

        try {
            // Skip backwards past padding/null bytes
            while (searchAddr.compareTo(functionStart) > 0) {
                byte b = memory.getByte(searchAddr);
                if (b != 0x00 && b != (byte) 0xFF && b != (byte) 0x9D) {
                    return searchAddr;
                }
                searchAddr = searchAddr.subtract(1);
            }
        } catch (Exception e) {
            // Return best guess if exception
        }

        return searchAddr;
    }

    @Override
    public void run() throws Exception {
        // Get start address from user if desired
        String startAddrStr = askString("Start Address (optional)",
            "Enter start address (hex) or leave empty to process entire binary:", "");

        if (!startAddrStr.trim().isEmpty()) {
            try {
                // Remove 0x prefix if present
                if (startAddrStr.toLowerCase().startsWith("0x")) {
                    startAddrStr = startAddrStr.substring(2);
                }
                long startOffset = Long.parseLong(startAddrStr, 16);
                startAddress = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(startOffset);
                println("[INFO] Using start address: " + startAddress);
            } catch (NumberFormatException e) {
                println("[ERROR] Invalid start address format: " + startAddrStr);
                return;
            }
        }

        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();

        for (MemoryBlock block : blocks) {
            if (!block.isInitialized()) {
                continue;
            }

            println("Searching block: " + block.getName() + " (" +
                    block.getStart() + " - " + block.getEnd() + ")");

            // Get all existing defined strings in this block (these are our anchors)
            List<Address> stringAddresses = getExistingStrings(block);

            if (stringAddresses.isEmpty()) {
                println("[INFO] No existing strings found in block " + block.getName());
                continue;
            }

            println("[INFO] Found " + stringAddresses.size() + " existing strings in block " + block.getName());

            // Create functions between consecutive strings
            for (int i = 0; i < stringAddresses.size(); i++) {
                try {
                    Address currentStringAddr = stringAddresses.get(i);
                    Address nextStringAddr = (i + 1 < stringAddresses.size()) ?
                        stringAddresses.get(i + 1) : block.getEnd();

                    // Get the string value from the existing defined data
                    Data stringData = currentProgram.getListing().getDataAt(currentStringAddr);
                    String currentString = (stringData != null && stringData.getValue() != null) ?
                        stringData.getValue().toString() : "<?>";

                    // Find where the previous function likely ended (or use previous string end + 1)
                    Address searchStart;
                    if (i == 0) {
                        // First string - start from block beginning or user-specified start
                        searchStart = (startAddress != null && startAddress.compareTo(block.getStart()) > 0) ?
                            startAddress : block.getStart();
                    } else {
                        // Start after the previous string
                        Address prevStringAddr = stringAddresses.get(i - 1);
                        Data prevStringData = currentProgram.getListing().getDataAt(prevStringAddr);
                        int prevStringLength = (prevStringData != null) ? prevStringData.getLength() : 1;
                        searchStart = prevStringAddr.add(prevStringLength);
                    }

                    // Find the actual function start (skip padding, find first instruction)
                    Address functionStart = findFunctionStart(memory, searchStart, currentStringAddr);

                    // Find the function end (work backwards from current string)
                    Address functionEnd = findFunctionEnd(memory, functionStart, currentStringAddr);

                    // Skip if the range seems too small or invalid
                    if (functionEnd.subtract(functionStart) < 4) {
                        println("[WARNING] Skipping potential function at " + functionStart +
                               " (too small: " + functionEnd.subtract(functionStart) + " bytes)");
                        continue;
                    }

                    println("[INFO] Potential function before string \"" + currentString + "\": " +
                           functionStart + " to " + functionEnd);

                    // Check if a function already exists at this start address
                    Function existingFunction = currentProgram.getFunctionManager().getFunctionAt(functionStart);

                    if (existingFunction == null) {
                        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

                        // Disassemble the range first
                        AddressSet addressSet = new AddressSet(functionStart, functionEnd);
                        DisassembleCommand disasmCmd = new DisassembleCommand(addressSet, null, true);
                        disasmCmd.applyTo(currentProgram, monitor);

                        // Create the function
                        CreateFunctionCmd createFuncCmd = new CreateFunctionCmd(functionStart);
                        if (createFuncCmd.applyTo(currentProgram, monitor)) {
                            println("[SUCCESS] Created function: " + functionStart + " to " + functionEnd +
                                   " (before string \"" + currentString + "\")");
                        } else {
                            println("[ERROR] Failed to create function: " + functionStart);
                        }
                    } else {
                        println("[WARNING] Function already exists at: " + functionStart);
                    }

                } catch (Exception e) {
                    println("[ERROR] Exception processing string at " + stringAddresses.get(i) + ": " + e.getMessage());
                }
            }
        }
    }
}