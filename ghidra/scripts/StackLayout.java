// Ghidra headless script: Extract annotated stack frame layout for a function.
//
// Usage with analyzeHeadless:
//   analyzeHeadless <project_dir> <project_name> \
//     -import <binary_path> \
//     -postScript StackLayout.java <function_name> \
//     -deleteProject
//
// Outputs JSON between ===STACK_LAYOUT_START=== / ===STACK_LAYOUT_END===
// containing: frame_size, variables (offset/size/name/type), saved_registers,
// and overflow_distances (buffer-to-return-address distances).
//
// @category Wairz
// @author Wairz AI

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.*;

import java.util.*;

public class StackLayout extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: Function name argument required");
            println("Usage: -postScript StackLayout.java <function_name>");
            return;
        }

        String targetFunction = args[0];

        FunctionManager funcManager = currentProgram.getFunctionManager();
        Function func = findFunction(funcManager, targetFunction);

        if (func == null) {
            println("ERROR: Function '" + targetFunction + "' not found");
            return;
        }

        StackFrame frame = func.getStackFrame();
        if (frame == null) {
            println("ERROR: No stack frame for function '" + targetFunction + "'");
            return;
        }

        int frameSize = frame.getFrameSize();
        Variable[] stackVars = frame.getStackVariables();

        // Sort by offset
        Arrays.sort(stackVars, (a, b) -> Integer.compare(
            a.getStackOffset(), b.getStackOffset()));

        // Classify variables
        List<Map<String, Object>> variables = new ArrayList<>();
        List<Map<String, Object>> savedRegisters = new ArrayList<>();
        int returnAddrOffset = Integer.MIN_VALUE;

        // Detect architecture for return address heuristic
        String arch = currentProgram.getLanguage().getProcessor().toString().toLowerCase();
        boolean isMips = arch.contains("mips");
        boolean isArm = arch.contains("arm") || arch.contains("aarch");
        boolean isX86 = arch.contains("x86") || arch.contains("386");

        for (Variable var : stackVars) {
            int offset = var.getStackOffset();
            int size = var.getLength();
            String name = var.getName();
            String typeName = var.getDataType().getDisplayName();

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("offset", offset);
            entry.put("size", size);
            entry.put("name", name);
            entry.put("type", typeName);

            // Detect return address / saved registers
            boolean isRetAddr = false;
            boolean isSavedReg = false;
            String regName = "";

            if (isMips) {
                // MIPS: saved $ra is typically at positive offset
                if (name.contains("ra") || name.contains("RA") ||
                    name.equals("local_res4") || name.equals("saved_ra")) {
                    isRetAddr = true;
                    regName = "ra";
                } else if (name.startsWith("saved_") || name.startsWith("local_res")) {
                    isSavedReg = true;
                    regName = name.replace("saved_", "").replace("local_res", "s");
                } else if (offset >= 0 && size == 4 && typeName.contains("undefined")) {
                    // Positive-offset 4-byte unknowns on MIPS are often saved regs
                    isSavedReg = true;
                    regName = "unknown_saved";
                }
            } else if (isArm) {
                if (name.contains("lr") || name.contains("LR")) {
                    isRetAddr = true;
                    regName = "lr";
                } else if (name.startsWith("saved_")) {
                    isSavedReg = true;
                    regName = name.replace("saved_", "");
                }
            } else if (isX86) {
                // x86: return address is typically at [ebp+4] or at top of frame
                if (name.equals("return_addr") || name.equals("ret_addr")) {
                    isRetAddr = true;
                    regName = "eip";
                }
            }

            if (isRetAddr) {
                entry.put("is_return_addr", true);
                returnAddrOffset = offset;

                Map<String, Object> regEntry = new LinkedHashMap<>();
                regEntry.put("offset", offset);
                regEntry.put("size", size);
                regEntry.put("name", name);
                regEntry.put("register", regName);
                savedRegisters.add(regEntry);
            } else if (isSavedReg) {
                Map<String, Object> regEntry = new LinkedHashMap<>();
                regEntry.put("offset", offset);
                regEntry.put("size", size);
                regEntry.put("name", name);
                regEntry.put("register", regName);
                savedRegisters.add(regEntry);
            }

            variables.add(entry);
        }

        // Calculate overflow distances for buffer/array variables
        List<Map<String, Object>> overflowDistances = new ArrayList<>();
        if (returnAddrOffset != Integer.MIN_VALUE) {
            for (Map<String, Object> var : variables) {
                int varOffset = (int) var.get("offset");
                int varSize = (int) var.get("size");
                String varType = (String) var.get("type");

                // Only consider arrays/buffers (size > 8 bytes or array types)
                boolean isBuffer = varSize > 8 ||
                    varType.contains("[") ||
                    varType.contains("char") ||
                    varType.contains("byte");

                if (isBuffer && varOffset < returnAddrOffset) {
                    int distance = returnAddrOffset - varOffset;
                    Map<String, Object> od = new LinkedHashMap<>();
                    od.put("buffer", var.get("name"));
                    od.put("buffer_offset", varOffset);
                    od.put("return_addr_offset", returnAddrOffset);
                    od.put("distance", distance);
                    overflowDistances.add(od);
                }
            }
        }

        // Build JSON output
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"function\":\"").append(escapeJson(func.getName())).append("\",");
        json.append("\"frame_size\":").append(frameSize).append(",");

        // Variables
        json.append("\"variables\":[");
        for (int i = 0; i < variables.size(); i++) {
            if (i > 0) json.append(",");
            json.append(mapToJson(variables.get(i)));
        }
        json.append("],");

        // Saved registers
        json.append("\"saved_registers\":[");
        for (int i = 0; i < savedRegisters.size(); i++) {
            if (i > 0) json.append(",");
            json.append(mapToJson(savedRegisters.get(i)));
        }
        json.append("],");

        // Overflow distances
        json.append("\"overflow_distances\":[");
        for (int i = 0; i < overflowDistances.size(); i++) {
            if (i > 0) json.append(",");
            json.append(mapToJson(overflowDistances.get(i)));
        }
        json.append("]");

        json.append("}");

        println("===STACK_LAYOUT_START===");
        println(json.toString());
        println("===STACK_LAYOUT_END===");
    }

    private Function findFunction(FunctionManager funcManager, String target) {
        // Exact match
        FunctionIterator iter = funcManager.getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            if (f.getName().equals(target)) return f;
        }
        // Address match
        if (target.startsWith("0x") || target.startsWith("0X")) {
            try {
                var addr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(target);
                return funcManager.getFunctionAt(addr);
            } catch (Exception e) { /* ignore */ }
        }
        // Partial match
        iter = funcManager.getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            if (f.getName().contains(target)) return f;
        }
        return null;
    }

    private String mapToJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(escapeJson(entry.getKey())).append("\":");
            Object val = entry.getValue();
            if (val instanceof String) {
                sb.append("\"").append(escapeJson((String) val)).append("\"");
            } else if (val instanceof Boolean) {
                sb.append(val.toString());
            } else {
                sb.append(val.toString());
            }
        }
        sb.append("}");
        return sb.toString();
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
