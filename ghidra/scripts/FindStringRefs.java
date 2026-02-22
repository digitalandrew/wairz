// Ghidra headless script: Find functions that reference strings matching a pattern.
//
// Usage with analyzeHeadless:
//   analyzeHeadless <project_dir> <project_name> \
//     -import <binary_path> \
//     -postScript FindStringRefs.java <regex_pattern> \
//     -deleteProject
//
// Outputs JSON between ===STRING_REFS_START=== / ===STRING_REFS_END===
// containing an array of {string_value, string_address, references: [{function, address, instruction}]}
//
// @category Wairz
// @author Wairz AI

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class FindStringRefs extends GhidraScript {

    private static final int MAX_STRINGS = 500;
    private static final int MAX_REFS_PER_STRING = 50;
    private static final int MAX_TOTAL_REFS = 200;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: Regex pattern argument required");
            println("Usage: -postScript FindStringRefs.java <regex_pattern>");
            return;
        }

        String patternStr = args[0];
        Pattern pattern;
        try {
            pattern = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            println("ERROR: Invalid regex pattern: " + e.getMessage());
            return;
        }

        Listing listing = currentProgram.getListing();
        ReferenceManager refManager = currentProgram.getReferenceManager();
        FunctionManager funcManager = currentProgram.getFunctionManager();

        // Find all defined strings matching the pattern
        List<Map<String, Object>> results = new ArrayList<>();
        int totalRefs = 0;

        DataIterator dataIter = listing.getDefinedData(true);
        int stringsChecked = 0;

        while (dataIter.hasNext() && stringsChecked < MAX_STRINGS && totalRefs < MAX_TOTAL_REFS) {
            Data data = dataIter.next();
            if (monitor.isCancelled()) break;

            // Check if this is a string data type
            if (!data.hasStringValue()) continue;

            String strValue;
            try {
                Object val = data.getValue();
                if (val == null) continue;
                strValue = val.toString();
            } catch (Exception e) {
                continue;
            }

            stringsChecked++;

            // Test against pattern
            if (!pattern.matcher(strValue).find()) continue;

            // Found a matching string — get references to it
            Address strAddr = data.getAddress();
            Reference[] refs = refManager.getReferencesTo(strAddr);

            if (refs.length == 0) continue;

            List<Map<String, String>> refList = new ArrayList<>();
            int refsForThis = 0;

            for (Reference ref : refs) {
                if (refsForThis >= MAX_REFS_PER_STRING || totalRefs >= MAX_TOTAL_REFS) break;

                Address fromAddr = ref.getFromAddress();
                Function containingFunc = funcManager.getFunctionContaining(fromAddr);
                if (containingFunc == null) continue;

                // Get the instruction at the reference site
                Instruction insn = listing.getInstructionAt(fromAddr);
                String insnStr = (insn != null) ? insn.toString() : "unknown";

                Map<String, String> refEntry = new LinkedHashMap<>();
                refEntry.put("function", containingFunc.getName());
                refEntry.put("function_address", containingFunc.getEntryPoint().toString());
                refEntry.put("ref_address", fromAddr.toString());
                refEntry.put("instruction", insnStr);

                refList.add(refEntry);
                refsForThis++;
                totalRefs++;
            }

            if (!refList.isEmpty()) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("string_value", strValue);
                entry.put("string_address", strAddr.toString());
                entry.put("references", refList);
                results.add(entry);
            }
        }

        // Output JSON
        println("===STRING_REFS_START===");
        println(toJson(results));
        println("===STRING_REFS_END===");
    }

    // Simple JSON serializer for our data structure
    private String toJson(List<Map<String, Object>> results) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");

        for (int i = 0; i < results.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("{");

            Map<String, Object> entry = results.get(i);
            sb.append("\"string_value\":").append(jsonString((String) entry.get("string_value"))).append(",");
            sb.append("\"string_address\":\"").append(entry.get("string_address")).append("\",");

            @SuppressWarnings("unchecked")
            List<Map<String, String>> refs = (List<Map<String, String>>) entry.get("references");
            sb.append("\"references\":[");

            for (int j = 0; j < refs.size(); j++) {
                if (j > 0) sb.append(",");
                Map<String, String> ref = refs.get(j);
                sb.append("{");
                sb.append("\"function\":").append(jsonString(ref.get("function"))).append(",");
                sb.append("\"function_address\":\"").append(ref.get("function_address")).append("\",");
                sb.append("\"ref_address\":\"").append(ref.get("ref_address")).append("\",");
                sb.append("\"instruction\":").append(jsonString(ref.get("instruction")));
                sb.append("}");
            }

            sb.append("]}");
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
