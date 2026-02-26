// Runs all M68k Mac analysis scripts in sequence.
// TODO: Replace this with a proper analyzer, but this seems to work okay for now.
// @category Analysis.M68k

import ghidra.app.script.GhidraScript;

public class RunAllM68kMacAnalysis extends GhidraScript {

    @Override
    protected void run() throws Exception {
        // Verify the processor.
        if (!currentProgram.getLanguage().getProcessor().toString().equals("68000")) {
            printf("Processor: %s", currentProgram.getLanguage().getProcessor().toString());
            popup("Processor must be 68000");
            return;
        }

        println("Starting M68k Mac analysis...");
        println("\nFinding functions from jumptable...");
        runScript("M68kMacJankLoader.java");

        println("\nFinding symbols...");
        runScript("M68kMacSymbols.java");

        println("\nPropagating A5 thunks...");
        runScript("M68kMacPropagateThunks.java");

        println("\nMarking up syscalls markup syscalls...");
        runScript("M68kMacSyscallScript.java");

        println("\nDemangling CodeWarrior symbols...");
        runScript("CodeWarriorDemanglerScript.java");
    }
}
