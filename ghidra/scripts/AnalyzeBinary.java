// Ghidra headless script: Full binary analysis — extracts ALL data in one pass.
//
// Usage with analyzeHeadless:
//   analyzeHeadless <project_dir> <project_name> \
//     -import <binary_path> \
//     -postScript AnalyzeBinary.java \
//     -deleteProject
//
// Outputs a single JSON object between ===ANALYSIS_START=== / ===ANALYSIS_END===
// containing: binary_info, functions, imports, exports, xrefs, disassembly,
// decompilation, and main_detection results.
//
// @category Wairz
// @author Wairz AI

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.*;

public class AnalyzeBinary extends GhidraScript {

    private static final int MAX_FUNCTIONS = 500;
    private static final int MAX_INSTRUCTIONS_PER_FUNCTION = 500;
    private static final int MAX_XREFS_PER_FUNCTION = 100;
    private static final int MAX_DECOMPILED_FUNCTIONS = 200;
    private static final int DECOMPILE_TIMEOUT = 120; // seconds per function

    @Override
    public void run() throws Exception {
        println("===ANALYSIS_START===");

        StringBuilder json = new StringBuilder();
        json.append("{");

        // 1. Binary info
        json.append("\"binary_info\":");
        json.append(buildBinaryInfo());
        json.append(",");

        if (monitor.isCancelled()) { println("===ANALYSIS_END==="); return; }

        // 2. Collect functions (sorted by size desc, capped)
        FunctionManager funcManager = currentProgram.getFunctionManager();
        List<Function> allFunctions = collectFunctions(funcManager);

        // 3. Main detection
        json.append("\"main_detection\":");
        json.append(buildMainDetection(funcManager, allFunctions));
        json.append(",");

        if (monitor.isCancelled()) { println("===ANALYSIS_END==="); return; }

        // 4. Functions list
        json.append("\"functions\":");
        json.append(buildFunctionsList(allFunctions));
        json.append(",");

        if (monitor.isCancelled()) { println("===ANALYSIS_END==="); return; }

        // 5. Imports
        json.append("\"imports\":");
        json.append(buildImports());
        json.append(",");

        if (monitor.isCancelled()) { println("===ANALYSIS_END==="); return; }

        // 6. Exports
        json.append("\"exports\":");
        json.append(buildExports());
        json.append(",");

        if (monitor.isCancelled()) { println("===ANALYSIS_END==="); return; }

        // 7. Xrefs (per function)
        json.append("\"xrefs\":");
        json.append(buildXrefs(allFunctions));
        json.append(",");

        if (monitor.isCancelled()) { println("===ANALYSIS_END==="); return; }

        // 8. Disassembly (per function)
        json.append("\"disassembly\":");
        json.append(buildDisassembly(allFunctions));
        json.append(",");

        if (monitor.isCancelled()) { println("===ANALYSIS_END==="); return; }

        // 9. Decompilation (top N functions by size)
        json.append("\"decompilation\":");
        json.append(buildDecompilation(allFunctions));

        json.append("}");

        println(json.toString());
        println("===ANALYSIS_END===");
    }

    // -----------------------------------------------------------------------
    // Binary Info
    // -----------------------------------------------------------------------

    private String buildBinaryInfo() {
        Language lang = currentProgram.getLanguage();
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"arch\":").append(jsonStr(lang.getProcessor().toString())).append(",");
        sb.append("\"endian\":").append(jsonStr(lang.isBigEndian() ? "big" : "little")).append(",");
        sb.append("\"bits\":").append(lang.getDefaultSpace().getSize()).append(",");
        sb.append("\"format\":").append(jsonStr(currentProgram.getExecutableFormat())).append(",");
        sb.append("\"entry_point\":").append(jsonStr(
            currentProgram.getSymbolTable().getExternalEntryPointIterator().hasNext()
                ? currentProgram.getSymbolTable().getExternalEntryPointIterator().next().toString()
                : "unknown"
        )).append(",");

        // Linked libraries from external manager
        sb.append("\"libraries\":[");
        try {
            String[] extLibs = currentProgram.getExternalManager().getExternalLibraryNames();
            boolean first = true;
            for (String lib : extLibs) {
                if (lib.equals("<EXTERNAL>")) continue;
                if (!first) sb.append(",");
                sb.append(jsonStr(lib));
                first = false;
            }
        } catch (Exception e) {
            // ignore
        }
        sb.append("],");

        sb.append("\"compiler\":").append(jsonStr(currentProgram.getCompiler())).append(",");
        sb.append("\"image_base\":").append(jsonStr(currentProgram.getImageBase().toString()));
        sb.append("}");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Function collection
    // -----------------------------------------------------------------------

    private List<Function> collectFunctions(FunctionManager funcManager) {
        List<Function> funcs = new ArrayList<>();
        FunctionIterator iter = funcManager.getFunctions(true);
        while (iter.hasNext()) {
            funcs.add(iter.next());
        }

        // Sort by body size descending
        funcs.sort((a, b) -> Long.compare(
            b.getBody().getNumAddresses(),
            a.getBody().getNumAddresses()
        ));

        // Cap at MAX_FUNCTIONS
        if (funcs.size() > MAX_FUNCTIONS) {
            funcs = new ArrayList<>(funcs.subList(0, MAX_FUNCTIONS));
        }
        return funcs;
    }

    // -----------------------------------------------------------------------
    // Main detection
    // -----------------------------------------------------------------------

    private String buildMainDetection(FunctionManager funcManager, List<Function> allFunctions) {
        // Strategy 1: Check if a function named "main" already exists
        for (Function f : allFunctions) {
            if (f.getName().equals("main") && !f.isThunk()) {
                return "{\"found\":true,\"address\":" + jsonStr(f.getEntryPoint().toString())
                    + ",\"method\":\"symbol_name\"}";
            }
        }

        // Strategy 2: Find __libc_start_main calls, extract first argument as main address
        try {
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            for (Symbol sym : symbolTable.getSymbols("__libc_start_main")) {
                // Find references to __libc_start_main
                for (Reference ref : getReferencesTo(sym.getAddress())) {
                    Address callAddr = ref.getFromAddress();
                    Function callerFunc = funcManager.getFunctionContaining(callAddr);
                    if (callerFunc == null) continue;

                    // Walk backwards from the call site looking for the first argument setup
                    // In many architectures, the first argument is set up just before the call
                    Instruction insn = currentProgram.getListing().getInstructionAt(callAddr);
                    if (insn == null) continue;

                    // Check up to 10 instructions before the call for address loading
                    Instruction prev = insn;
                    for (int i = 0; i < 10 && prev != null; i++) {
                        prev = prev.getPrevious();
                        if (prev == null) break;

                        // Look for references from this instruction that point to a function
                        for (Reference prevRef : prev.getReferencesFrom()) {
                            Address targetAddr = prevRef.getToAddress();
                            Function targetFunc = funcManager.getFunctionAt(targetAddr);
                            if (targetFunc != null && !targetFunc.isThunk()
                                && !targetFunc.getName().equals("__libc_start_main")
                                && !targetFunc.getEntryPoint().equals(callerFunc.getEntryPoint())) {
                                // Found a candidate for main
                                String mainAddr = targetFunc.getEntryPoint().toString();
                                // Rename the function to "main" if it has an auto-generated name
                                if (targetFunc.getName().startsWith("FUN_")) {
                                    try {
                                        targetFunc.setName("main", SourceType.ANALYSIS);
                                    } catch (Exception e) {
                                        // name conflict, don't rename
                                    }
                                }
                                return "{\"found\":true,\"address\":" + jsonStr(mainAddr)
                                    + ",\"original_name\":" + jsonStr(targetFunc.getName())
                                    + ",\"method\":\"libc_start_main_arg\"}";
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Heuristic failed, that's ok
        }

        // Strategy 3: Look for entry point function and check if it references something main-like
        try {
            Address entryPoint = null;
            AddressIterator entryIter = currentProgram.getSymbolTable().getExternalEntryPointIterator();
            if (entryIter.hasNext()) {
                entryPoint = entryIter.next();
            }
            if (entryPoint != null) {
                Function entryFunc = funcManager.getFunctionAt(entryPoint);
                if (entryFunc != null && entryFunc.getName().equals("main")) {
                    return "{\"found\":true,\"address\":" + jsonStr(entryPoint.toString())
                        + ",\"method\":\"entry_point\"}";
                }
            }
        } catch (Exception e) {
            // ignore
        }

        return "{\"found\":false}";
    }

    // -----------------------------------------------------------------------
    // Functions list
    // -----------------------------------------------------------------------

    private String buildFunctionsList(List<Function> functions) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        boolean first = true;
        for (Function f : functions) {
            if (monitor.isCancelled()) break;
            if (!first) sb.append(",");
            sb.append("{");
            sb.append("\"name\":").append(jsonStr(f.getName())).append(",");
            sb.append("\"address\":").append(jsonStr(f.getEntryPoint().toString())).append(",");
            sb.append("\"size\":").append(f.getBody().getNumAddresses()).append(",");
            sb.append("\"is_thunk\":").append(f.isThunk()).append(",");
            sb.append("\"calling_convention\":").append(
                jsonStr(f.getCallingConventionName() != null ? f.getCallingConventionName() : "unknown")
            );
            sb.append("}");
            first = false;
        }
        sb.append("]");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Imports
    // -----------------------------------------------------------------------

    private String buildImports() {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        boolean first = true;
        try {
            ExternalManager extManager = currentProgram.getExternalManager();
            for (String libName : extManager.getExternalLibraryNames()) {
                if (libName.equals("<EXTERNAL>")) {
                    // These are unresolved externals — still include them with null lib
                    Iterator<ExternalLocation> extIter = extManager.getExternalLocations(libName);
                    while (extIter.hasNext()) {
                        ExternalLocation extLoc = extIter.next();
                        if (extLoc.getFunction() != null || extLoc.isFunction()) {
                            if (!first) sb.append(",");
                            sb.append("{");
                            sb.append("\"name\":").append(jsonStr(extLoc.getLabel())).append(",");
                            sb.append("\"library\":null");
                            sb.append("}");
                            first = false;
                        }
                    }
                    continue;
                }
                Iterator<ExternalLocation> extIter = extManager.getExternalLocations(libName);
                while (extIter.hasNext()) {
                    ExternalLocation extLoc = extIter.next();
                    if (!first) sb.append(",");
                    sb.append("{");
                    sb.append("\"name\":").append(jsonStr(extLoc.getLabel())).append(",");
                    sb.append("\"library\":").append(jsonStr(libName));
                    sb.append("}");
                    first = false;
                }
            }
        } catch (Exception e) {
            // ignore
        }
        sb.append("]");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Exports
    // -----------------------------------------------------------------------

    private String buildExports() {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        boolean first = true;
        try {
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            AddressIterator iter = symbolTable.getExternalEntryPointIterator();
            while (iter.hasNext()) {
                Address addr = iter.next();
                Symbol[] symbols = symbolTable.getSymbols(addr);
                String name = (symbols.length > 0) ? symbols[0].getName() : addr.toString();
                if (!first) sb.append(",");
                sb.append("{");
                sb.append("\"name\":").append(jsonStr(name)).append(",");
                sb.append("\"address\":").append(jsonStr(addr.toString()));
                sb.append("}");
                first = false;
            }
        } catch (Exception e) {
            // ignore
        }
        sb.append("]");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Xrefs
    // -----------------------------------------------------------------------

    private String buildXrefs(List<Function> functions) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        boolean first = true;
        ReferenceManager refManager = currentProgram.getReferenceManager();
        FunctionManager funcManager = currentProgram.getFunctionManager();

        for (Function f : functions) {
            if (monitor.isCancelled()) break;

            if (!first) sb.append(",");
            sb.append(jsonStr(f.getName())).append(":{");

            // Xrefs TO this function
            sb.append("\"to\":[");
            Reference[] refsTo = getReferencesTo(f.getEntryPoint());
            int countTo = 0;
            boolean firstTo = true;
            for (Reference ref : refsTo) {
                if (countTo >= MAX_XREFS_PER_FUNCTION) break;
                if (!firstTo) sb.append(",");
                sb.append("{");
                sb.append("\"from\":").append(jsonStr(ref.getFromAddress().toString())).append(",");
                sb.append("\"type\":").append(jsonStr(ref.getReferenceType().getName()));
                // Try to find the containing function name
                Function caller = funcManager.getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    sb.append(",\"from_func\":").append(jsonStr(caller.getName()));
                }
                sb.append("}");
                firstTo = false;
                countTo++;
            }
            sb.append("],");

            // Xrefs FROM this function
            sb.append("\"from\":[");
            Set<String> seenFrom = new HashSet<>();
            AddressSetView body = f.getBody();
            int countFrom = 0;
            boolean firstFrom = true;

            for (Address addr : body.getAddresses(true)) {
                if (countFrom >= MAX_XREFS_PER_FUNCTION) break;
                if (monitor.isCancelled()) break;

                Reference[] refsFrom = refManager.getReferencesFrom(addr);
                for (Reference ref : refsFrom) {
                    if (countFrom >= MAX_XREFS_PER_FUNCTION) break;
                    Address toAddr = ref.getToAddress();
                    String key = toAddr.toString();
                    if (seenFrom.contains(key)) continue;
                    seenFrom.add(key);

                    // Only include references to known functions or external symbols
                    Function targetFunc = funcManager.getFunctionAt(toAddr);
                    if (targetFunc == null) {
                        Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(toAddr);
                        if (sym == null || sym.getSymbolType() == SymbolType.LABEL) continue;
                    }

                    if (!firstFrom) sb.append(",");
                    sb.append("{");
                    sb.append("\"to\":").append(jsonStr(toAddr.toString())).append(",");
                    sb.append("\"type\":").append(jsonStr(ref.getReferenceType().getName()));
                    if (targetFunc != null) {
                        sb.append(",\"to_func\":").append(jsonStr(targetFunc.getName()));
                    }
                    sb.append("}");
                    firstFrom = false;
                    countFrom++;
                }
            }
            sb.append("]");

            sb.append("}");
            first = false;
        }

        sb.append("}");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Disassembly
    // -----------------------------------------------------------------------

    private String buildDisassembly(List<Function> functions) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        boolean first = true;
        Listing listing = currentProgram.getListing();

        for (Function f : functions) {
            if (monitor.isCancelled()) break;
            if (!first) sb.append(",");

            StringBuilder disasm = new StringBuilder();
            InstructionIterator instrIter = listing.getInstructions(f.getBody(), true);
            int count = 0;
            while (instrIter.hasNext() && count < MAX_INSTRUCTIONS_PER_FUNCTION) {
                Instruction insn = instrIter.next();
                disasm.append(insn.getAddress().toString());
                disasm.append("  ");
                disasm.append(insn.toString());
                disasm.append("\n");
                count++;
            }
            if (instrIter.hasNext()) {
                disasm.append("... (truncated at " + MAX_INSTRUCTIONS_PER_FUNCTION + " instructions)\n");
            }

            sb.append(jsonStr(f.getName())).append(":").append(jsonStr(disasm.toString()));
            first = false;
        }

        sb.append("}");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Decompilation
    // -----------------------------------------------------------------------

    private String buildDecompilation(List<Function> functions) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");

        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);

        if (!decompiler.openProgram(currentProgram)) {
            sb.append("}");
            return sb.toString();
        }

        try {
            boolean first = true;
            int decompCount = 0;

            for (Function f : functions) {
                if (monitor.isCancelled()) break;
                if (decompCount >= MAX_DECOMPILED_FUNCTIONS) break;

                // Skip thunks and tiny functions
                if (f.isThunk() || f.getBody().getNumAddresses() < 4) {
                    continue;
                }

                DecompileResults results = decompiler.decompileFunction(f, DECOMPILE_TIMEOUT, monitor);

                if (results.getDecompiledFunction() != null) {
                    String code = results.getDecompiledFunction().getC();
                    if (code != null && !code.isEmpty()) {
                        if (!first) sb.append(",");
                        sb.append(jsonStr(f.getName())).append(":").append(jsonStr(code));
                        first = false;
                        decompCount++;
                    }
                }
            }
        } finally {
            decompiler.dispose();
        }

        sb.append("}");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // JSON helpers
    // -----------------------------------------------------------------------

    private String jsonStr(String value) {
        if (value == null) return "null";
        StringBuilder sb = new StringBuilder();
        sb.append("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }
}
