// Ghidra headless script: Map global variables in BSS/data sections around a target symbol.
//
// Usage with analyzeHeadless:
//   analyzeHeadless <project_dir> <project_name> \
//     -import <binary_path> \
//     -postScript GlobalLayout.java <symbol_name> \
//     -deleteProject
//
// Outputs JSON between ===GLOBAL_LAYOUT_START=== / ===GLOBAL_LAYOUT_END===
// containing: target symbol info, containing section, and neighboring data items.
//
// @category Wairz
// @author Wairz AI

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

import java.util.*;

public class GlobalLayout extends GhidraScript {

    private static final int MAX_NEIGHBORS = 20;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: Symbol name argument required");
            println("Usage: -postScript GlobalLayout.java <symbol_name>");
            return;
        }

        String targetName = args[0];

        // Find the target symbol
        SymbolTable symTable = currentProgram.getSymbolTable();
        Symbol targetSymbol = null;
        SymbolIterator symIter = symTable.getSymbols(targetName);
        while (symIter.hasNext()) {
            Symbol s = symIter.next();
            if (s.getName().equals(targetName)) {
                targetSymbol = s;
                break;
            }
        }

        if (targetSymbol == null) {
            // Try partial match
            SymbolIterator allSyms = symTable.getAllSymbols(true);
            while (allSyms.hasNext()) {
                Symbol s = allSyms.next();
                if (s.getName().contains(targetName) &&
                    s.getSymbolType() != SymbolType.FUNCTION) {
                    targetSymbol = s;
                    break;
                }
            }
        }

        if (targetSymbol == null) {
            println("ERROR: Symbol '" + targetName + "' not found");
            // List some data symbols as suggestions
            println("Available data symbols (first 30):");
            SymbolIterator allSyms = symTable.getAllSymbols(true);
            int count = 0;
            while (allSyms.hasNext() && count < 30) {
                Symbol s = allSyms.next();
                if (s.getSymbolType() == SymbolType.LABEL &&
                    !s.getName().startsWith("FUN_") &&
                    !s.getName().startsWith("LAB_") &&
                    !s.getName().startsWith("switchD_") &&
                    !s.getName().startsWith("caseD_")) {
                    println("  " + s.getName() + " @ " + s.getAddress());
                    count++;
                }
            }
            return;
        }

        Address targetAddr = targetSymbol.getAddress();
        Memory memory = currentProgram.getMemory();
        MemoryBlock block = memory.getBlock(targetAddr);

        if (block == null) {
            println("ERROR: Symbol address " + targetAddr + " not in any memory block");
            return;
        }

        // Get the section/block info
        String sectionName = block.getName();
        Address blockStart = block.getStart();
        Address blockEnd = block.getEnd();

        // Collect all labeled data items in this block
        Listing listing = currentProgram.getListing();
        List<DataItem> allItems = new ArrayList<>();

        // Scan for all defined data and labels in the block
        DataIterator dataIter = listing.getDefinedData(
            new AddressSet(blockStart, blockEnd), true);

        Set<Address> seenAddresses = new HashSet<>();
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            Address addr = data.getAddress();
            if (seenAddresses.contains(addr)) continue;
            seenAddresses.add(addr);

            String name = getSymbolName(addr);
            String typeName = data.getDataType().getDisplayName();
            int size = data.getLength();

            // Try to get initial value for .data/.rodata sections
            String initValue = "";
            if (!block.getName().toLowerCase().contains("bss")) {
                try {
                    if (size <= 8 && data.isPointer()) {
                        initValue = data.getValue().toString();
                    } else if (size <= 64) {
                        byte[] bytes = new byte[Math.min(size, 32)];
                        memory.getBytes(addr, bytes);
                        initValue = bytesToDisplayString(bytes, typeName);
                    }
                } catch (Exception e) {
                    // ignore
                }
            }

            allItems.add(new DataItem(
                addr, size, name, typeName, initValue,
                addr.equals(targetAddr)));
        }

        // Also scan for labels without defined data (common in BSS)
        SymbolIterator blockSyms = symTable.getSymbols(
            new AddressSet(blockStart, blockEnd), SymbolType.LABEL, true);
        while (blockSyms.hasNext()) {
            Symbol s = blockSyms.next();
            Address addr = s.getAddress();
            if (seenAddresses.contains(addr)) continue;
            seenAddresses.add(addr);

            // Estimate size from gap to next symbol/data
            int size = estimateSize(addr, blockEnd, seenAddresses);
            allItems.add(new DataItem(
                addr, size, s.getName(), "undefined",
                "", addr.equals(targetAddr)));
        }

        // Sort by address
        allItems.sort((a, b) -> a.address.compareTo(b.address));

        // Find the target's index and extract neighbors
        int targetIdx = -1;
        for (int i = 0; i < allItems.size(); i++) {
            if (allItems.get(i).isTarget) {
                targetIdx = i;
                break;
            }
        }

        // If target wasn't in the items list, add it
        if (targetIdx == -1) {
            Data targetData = listing.getDefinedDataAt(targetAddr);
            int targetSize = 4;
            String targetType = "undefined";
            if (targetData != null) {
                targetSize = targetData.getLength();
                targetType = targetData.getDataType().getDisplayName();
            }
            DataItem targetItem = new DataItem(
                targetAddr, targetSize, targetName, targetType, "", true);
            allItems.add(targetItem);
            allItems.sort((a, b) -> a.address.compareTo(b.address));
            for (int i = 0; i < allItems.size(); i++) {
                if (allItems.get(i).isTarget) {
                    targetIdx = i;
                    break;
                }
            }
        }

        // Extract ~MAX_NEIGHBORS centered on target
        int halfWindow = MAX_NEIGHBORS / 2;
        int startIdx = Math.max(0, targetIdx - halfWindow);
        int endIdx = Math.min(allItems.size(), startIdx + MAX_NEIGHBORS);
        if (endIdx - startIdx < MAX_NEIGHBORS && startIdx > 0) {
            startIdx = Math.max(0, endIdx - MAX_NEIGHBORS);
        }

        List<DataItem> neighbors = allItems.subList(startIdx, endIdx);

        // Build JSON output
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"target_symbol\":\"").append(escapeJson(targetName)).append("\",");
        json.append("\"target_address\":\"").append(targetAddr.toString()).append("\",");
        json.append("\"section\":\"").append(escapeJson(sectionName)).append("\",");
        json.append("\"section_range\":[\"").append(blockStart).append("\",\"")
            .append(blockEnd).append("\"],");

        json.append("\"neighbors\":[");
        boolean first = true;
        for (DataItem item : neighbors) {
            if (!first) json.append(",");
            first = false;
            json.append("{");
            json.append("\"address\":\"").append(item.address).append("\",");
            json.append("\"size\":").append(item.size).append(",");
            json.append("\"name\":\"").append(escapeJson(item.name)).append("\",");
            json.append("\"type\":\"").append(escapeJson(item.type)).append("\"");
            if (item.isTarget) {
                json.append(",\"is_target\":true");
            }
            if (!item.initValue.isEmpty()) {
                json.append(",\"init_value\":\"").append(escapeJson(item.initValue)).append("\"");
            }
            json.append("}");
        }
        json.append("]");

        json.append("}");

        println("===GLOBAL_LAYOUT_START===");
        println(json.toString());
        println("===GLOBAL_LAYOUT_END===");
    }

    private String getSymbolName(Address addr) {
        SymbolTable symTable = currentProgram.getSymbolTable();
        Symbol[] symbols = symTable.getSymbols(addr);
        for (Symbol s : symbols) {
            if (s.getSymbolType() == SymbolType.LABEL &&
                !s.getName().startsWith("DAT_") &&
                !s.getName().startsWith("LAB_")) {
                return s.getName();
            }
        }
        // Fall back to any non-default label
        for (Symbol s : symbols) {
            if (!s.isDynamic()) {
                return s.getName();
            }
        }
        // Fall back to auto-generated name
        return "DAT_" + addr.toString();
    }

    private int estimateSize(Address addr, Address blockEnd,
                             Set<Address> knownAddresses) {
        // Find the next known address after this one
        Address next = addr.add(1);
        int maxSearch = 4096;
        int size = 4; // default assumption

        for (Address known : knownAddresses) {
            if (known.compareTo(addr) > 0) {
                long gap = known.subtract(addr);
                if (gap > 0 && gap < maxSearch) {
                    size = (int) gap;
                    break;
                }
            }
        }
        return size;
    }

    private String bytesToDisplayString(byte[] bytes, String typeName) {
        if (typeName.contains("char") || typeName.contains("string")) {
            // Try to interpret as string
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                if (b == 0) break;
                if (b >= 32 && b < 127) {
                    sb.append((char) b);
                } else {
                    sb.append("\\x").append(String.format("%02x", b & 0xFF));
                }
            }
            return sb.toString();
        }
        // Hex representation for other types
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, 16); i++) {
            sb.append(String.format("%02x", bytes[i] & 0xFF));
        }
        if (bytes.length > 16) sb.append("...");
        return "0x" + sb.toString();
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // Helper class for data items
    private static class DataItem {
        Address address;
        int size;
        String name;
        String type;
        String initValue;
        boolean isTarget;

        DataItem(Address address, int size, String name, String type,
                 String initValue, boolean isTarget) {
            this.address = address;
            this.size = size;
            this.name = name;
            this.type = type;
            this.initValue = initValue;
            this.isTarget = isTarget;
        }
    }
}
