/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Automatically fills out all class structures in the program by finding
// all 'this' pointer parameters and applying the FillOutStructureCmd to each one.
// This assumes class names are already demangled and empty structures exist.
//
//@category Data Types

import org.apache.commons.lang3.StringUtils;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.util.FillOutStructureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.util.VariableLocation;
import ghidra.util.exception.CancelledException;

public class FillAllClassStructures extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            popup("Requires open program");
            return;
        }

        DecompileOptions decompileOptions =
            DecompilerUtils.getDecompileOptions(state.getTool(), currentProgram);

        println("Starting to fill out all class structures...");

        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int totalProcessed = 0;
        int totalFilled = 0;

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            monitor.setMessage("Processing function: " + function.getName());

            // Check each parameter for 'this' pointers
            Parameter[] parameters = function.getParameters();
            for (Parameter param : parameters) {
                if (isThisPointer(param)) {
                    totalProcessed++;

                    // Create a VariableLocation using the correct constructor
                    // VariableLocation(Program program, Variable var, int index, int charOffset)
                    VariableLocation location = new VariableLocation(currentProgram, param, 0, 0);

                    // Apply the FillOutStructureCmd (same as CreateStructure script)
                    FillOutStructureCmd cmd = new FillOutStructureCmd(location, decompileOptions);
                    if (cmd.applyTo(currentProgram, monitor)) {
                        totalFilled++;
                        printf("Filled structure for 'this' in %s::%s\n",
                               function.getName(), param.getName());
                    } else {
                        String detail = "";
                        String msg = cmd.getStatusMsg();
                        if (!StringUtils.isBlank(msg)) {
                            detail = ": " + msg;
                        }
                        printf("Failed to fill structure for %s::%s%s\n",
                               function.getName(), param.getName(), detail);
                    }
                }
            }
        }

        printf("Completed! Processed %d 'this' pointers, successfully filled %d structures.\n",
               totalProcessed, totalFilled);
    }

    private boolean isThisPointer(Parameter param) {
        String paramName = param.getName().toLowerCase();

        // Check for explicit 'this' parameter names
        return paramName.equals("this") || paramName.equals("__this") || paramName.startsWith("this");
    }
}