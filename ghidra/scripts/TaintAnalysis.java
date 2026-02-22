// Ghidra headless script: Intraprocedural source-to-sink dataflow analysis.
//
// Usage with analyzeHeadless:
//   analyzeHeadless <project_dir> <project_name> \
//     -import <binary_path> \
//     -postScript TaintAnalysis.java <sources_csv> <sinks_csv> \
//     -deleteProject
//
// Args:
//   sources_csv: comma-separated source function names (e.g. "getenv,recv,read")
//   sinks_csv:   comma-separated sink function names (e.g. "system,popen,strcpy")
//
// Algorithm:
//   For each function in the binary, find calls to source and sink functions.
//   If a source call appears before a sink call within the same function (by address),
//   report it as a potential tainted dataflow path.
//   Also performs interprocedural heuristic: if function A calls a source and also
//   calls function B which contains a sink, flag with lower confidence.
//
// Outputs JSON between ===TAINT_START=== / ===TAINT_END===
//
// @category Wairz
// @author Wairz AI

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.util.*;

public class TaintAnalysis extends GhidraScript {

    private static final int MAX_PATHS = 50;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("ERROR: Two arguments required: <sources_csv> <sinks_csv>");
            println("Usage: -postScript TaintAnalysis.java getenv,recv system,popen");
            return;
        }

        Set<String> sourceNames = new HashSet<>(Arrays.asList(args[0].split(",")));
        Set<String> sinkNames = new HashSet<>(Arrays.asList(args[1].split(",")));

        FunctionManager funcManager = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        ReferenceManager refManager = currentProgram.getReferenceManager();

        // Step 1: Build maps of which functions contain source/sink calls
        // For each function: list of (call_address, callee_name) for sources and sinks
        Map<Function, List<CallInfo>> funcSources = new LinkedHashMap<>();
        Map<Function, List<CallInfo>> funcSinks = new LinkedHashMap<>();
        // Track all functions called by each function (for interprocedural)
        Map<Function, Set<Function>> funcCallees = new LinkedHashMap<>();

        FunctionIterator funcIter = funcManager.getFunctions(true);
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) break;
            Function func = funcIter.next();

            // Iterate instructions in this function to find CALL references
            InstructionIterator insnIter = listing.getInstructions(func.getBody(), true);
            while (insnIter.hasNext()) {
                Instruction insn = insnIter.next();
                // Check outgoing references for calls
                Reference[] refs = insn.getReferencesFrom();
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isCall()) {
                        Address targetAddr = ref.getToAddress();
                        Function targetFunc = funcManager.getFunctionAt(targetAddr);
                        if (targetFunc == null) continue;

                        String calleeName = targetFunc.getName();
                        Address callSite = insn.getAddress();

                        // Track all callees for interprocedural
                        funcCallees.computeIfAbsent(func, k -> new LinkedHashSet<>()).add(targetFunc);

                        if (sourceNames.contains(calleeName)) {
                            funcSources.computeIfAbsent(func, k -> new ArrayList<>())
                                .add(new CallInfo(callSite, calleeName, targetFunc));
                        }
                        if (sinkNames.contains(calleeName)) {
                            funcSinks.computeIfAbsent(func, k -> new ArrayList<>())
                                .add(new CallInfo(callSite, calleeName, targetFunc));
                        }
                    }
                }
            }
        }

        List<Map<String, Object>> paths = new ArrayList<>();

        // Step 2: Intraprocedural — functions with both source and sink calls
        for (Map.Entry<Function, List<CallInfo>> entry : funcSources.entrySet()) {
            if (paths.size() >= MAX_PATHS) break;

            Function func = entry.getKey();
            List<CallInfo> sources = entry.getValue();
            List<CallInfo> sinks = funcSinks.get(func);
            if (sinks == null) continue;

            for (CallInfo src : sources) {
                for (CallInfo sink : sinks) {
                    if (paths.size() >= MAX_PATHS) break;
                    // Source must come before sink (by address)
                    if (src.callSite.compareTo(sink.callSite) < 0) {
                        Map<String, Object> path = new LinkedHashMap<>();
                        path.put("function", func.getName());
                        path.put("function_address", func.getEntryPoint().toString());
                        path.put("source_func", src.calleeName);
                        path.put("source_call_site", src.callSite.toString());
                        path.put("sink_func", sink.calleeName);
                        path.put("sink_call_site", sink.callSite.toString());
                        path.put("interprocedural", false);
                        path.put("confidence", "high");
                        paths.add(path);
                    }
                }
            }
        }

        // Step 3: Interprocedural heuristic — function A calls source, also calls B which has a sink
        for (Map.Entry<Function, List<CallInfo>> entry : funcSources.entrySet()) {
            if (paths.size() >= MAX_PATHS) break;

            Function callerFunc = entry.getKey();
            List<CallInfo> sources = entry.getValue();
            Set<Function> callees = funcCallees.getOrDefault(callerFunc, Collections.emptySet());

            for (Function callee : callees) {
                if (paths.size() >= MAX_PATHS) break;

                List<CallInfo> calleeSinks = funcSinks.get(callee);
                if (calleeSinks == null) continue;
                // Skip if callerFunc already has direct sinks (already reported above)
                if (funcSinks.containsKey(callerFunc)) continue;

                for (CallInfo src : sources) {
                    for (CallInfo sink : calleeSinks) {
                        if (paths.size() >= MAX_PATHS) break;
                        Map<String, Object> path = new LinkedHashMap<>();
                        path.put("function", callerFunc.getName());
                        path.put("function_address", callerFunc.getEntryPoint().toString());
                        path.put("source_func", src.calleeName);
                        path.put("source_call_site", src.callSite.toString());
                        path.put("sink_func", sink.calleeName);
                        path.put("sink_call_site", sink.callSite.toString());
                        path.put("sink_function", callee.getName());
                        path.put("interprocedural", true);
                        path.put("confidence", "medium");
                        paths.add(path);
                        break; // one path per callee is enough
                    }
                    if (paths.size() >= MAX_PATHS) break;
                }
            }
        }

        // Output JSON
        println("===TAINT_START===");
        println(toJson(paths));
        println("===TAINT_END===");
    }

    private static class CallInfo {
        final Address callSite;
        final String calleeName;
        final Function targetFunc;

        CallInfo(Address callSite, String calleeName, Function targetFunc) {
            this.callSite = callSite;
            this.calleeName = calleeName;
            this.targetFunc = targetFunc;
        }
    }

    // Simple JSON serializer
    private String toJson(List<Map<String, Object>> paths) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");

        for (int i = 0; i < paths.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("{");

            Map<String, Object> path = paths.get(i);
            List<String> fields = new ArrayList<>();
            for (Map.Entry<String, Object> e : path.entrySet()) {
                Object val = e.getValue();
                if (val instanceof Boolean) {
                    fields.add("\"" + e.getKey() + "\":" + val);
                } else {
                    fields.add("\"" + e.getKey() + "\":" + jsonString(val.toString()));
                }
            }
            sb.append(String.join(",", fields));
            sb.append("}");
        }

        sb.append("]");
        return sb.toString();
    }

    private String jsonString(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
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
