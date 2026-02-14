// Ghidra headless script: Decompile a function and print pseudo-C to stdout.
//
// Usage with analyzeHeadless:
//   analyzeHeadless <project_dir> <project_name> \
//     -import <binary_path> \
//     -postScript DecompileFunction.java <function_name> \
//     -deleteProject
//
// If function_name is "__all__", decompiles all functions (limited output).
// Output is printed to stdout between markers for easy parsing.
//
// @category Wairz
// @author Wairz AI

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.address.Address;

public class DecompileFunction extends GhidraScript {

    private static final int DECOMPILE_TIMEOUT = 120; // seconds

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: Function name argument required");
            println("Usage: -postScript DecompileFunction.java <function_name>");
            return;
        }

        String targetFunction = args[0];

        // Set up the decompiler
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);

        if (!decompiler.openProgram(currentProgram)) {
            println("ERROR: Failed to open program in decompiler");
            return;
        }

        try {
            FunctionManager funcManager = currentProgram.getFunctionManager();

            if (targetFunction.equals("__all__")) {
                // Decompile all functions (used for full analysis caching)
                decompileAllFunctions(decompiler, funcManager);
            } else {
                // Decompile a specific function
                decompileNamedFunction(decompiler, funcManager, targetFunction);
            }
        } finally {
            decompiler.dispose();
        }
    }

    private void decompileNamedFunction(DecompInterface decompiler,
                                         FunctionManager funcManager,
                                         String targetFunction) {
        Function func = findFunction(funcManager, targetFunction);

        if (func == null) {
            println("ERROR: Function '" + targetFunction + "' not found");
            println("Available functions (first 50):");
            FunctionIterator iter = funcManager.getFunctions(true);
            int count = 0;
            while (iter.hasNext() && count < 50) {
                Function f = iter.next();
                println("  " + f.getName() + " @ " + f.getEntryPoint());
                count++;
            }
            return;
        }

        DecompileResults results = decompiler.decompileFunction(func, DECOMPILE_TIMEOUT, monitor);

        // Use markers so the backend can parse the output reliably
        println("===DECOMPILE_START===");
        println("// Function: " + func.getName());
        println("// Address:  " + func.getEntryPoint());
        println("// Size:     " + func.getBody().getNumAddresses() + " bytes");
        println("");

        if (results.getDecompiledFunction() != null) {
            String decompiledCode = results.getDecompiledFunction().getC();
            println(decompiledCode);
        } else {
            println("// Decompilation failed");
            if (results.getErrorMessage() != null && !results.getErrorMessage().isEmpty()) {
                println("// Error: " + results.getErrorMessage());
            }
        }

        println("===DECOMPILE_END===");
    }

    private void decompileAllFunctions(DecompInterface decompiler,
                                        FunctionManager funcManager) {
        FunctionIterator iter = funcManager.getFunctions(true);
        int count = 0;
        int maxFunctions = 200; // Safety limit

        while (iter.hasNext() && count < maxFunctions) {
            Function func = iter.next();

            // Skip thunks and tiny functions
            if (func.isThunk() || func.getBody().getNumAddresses() < 4) {
                continue;
            }

            DecompileResults results = decompiler.decompileFunction(func, DECOMPILE_TIMEOUT, monitor);

            println("===DECOMPILE_START===");
            println("// Function: " + func.getName());
            println("// Address:  " + func.getEntryPoint());

            if (results.getDecompiledFunction() != null) {
                println(results.getDecompiledFunction().getC());
            } else {
                println("// Decompilation failed");
            }

            println("===DECOMPILE_END===");
            count++;

            if (monitor.isCancelled()) {
                break;
            }
        }
    }

    private Function findFunction(FunctionManager funcManager, String target) {
        // Try exact name match first
        FunctionIterator iter = funcManager.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equals(target)) {
                return func;
            }
        }

        // Try address match (e.g., "0x08048000")
        if (target.startsWith("0x") || target.startsWith("0X")) {
            try {
                Address addr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace()
                    .getAddress(target);
                return funcManager.getFunctionAt(addr);
            } catch (Exception e) {
                // Not a valid address
            }
        }

        // Try partial/contains match as fallback
        iter = funcManager.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().contains(target)) {
                return func;
            }
        }

        return null;
    }
}
