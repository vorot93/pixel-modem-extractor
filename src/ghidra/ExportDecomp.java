// ExportDecomp.java — Ghidra headless post-script for pixel-modem-extractor.
// Arg[0] = output directory. Writes decompiled.c, disasm.lst, functions.json.
//
// FIDELITY POSTURE (Phase 1+): this script intentionally does NOT call
// DecompInterface.setOptions(...). Ghidra's decompiler defaults are already a
// fiducial baseline, and setOptions *replaces* the program's "Decompiler"
// property sheet rather than merging with it, which would clobber user /
// environment defaults for zero benefit.
//
// The candidate readability knobs were reviewed and kept at Ghidra defaults:
//   - EliminateUnreachable: OFF. Can drop real firmware code reached via
//     jump tables, computed branches, or tail-call dispatch.
//   - Simplify: OFF. Extended simplification can elide semantically relevant
//     intermediate state.
//   - NoCasts: OFF (default). The alternative hides real type conversions.
//   - DisableDecompilerParameterNames: OFF (default). The alternative strips
//     parameter names.
//   - UseHexadecimal: TRUE (default). Display-only; matches disasm.lst.
//
// Pass 2 of `decompose` re-runs this script unchanged after ApplySymbols.java
// has renamed functions in the program — getC() then emits the regenerated C
// with names + plate comments baked in.
//@category PixelModem
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import java.util.Set;
import java.util.TreeSet;

public class ExportDecomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ExportDecomp: missing output directory argument");
            return;
        }
        File outDir = new File(args[0]);
        outDir.mkdirs();

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        // Entry-function fallback: a tiny anchorless blob may yield no functions.
        if (fm.getFunctionCount() == 0) {
            Address base = currentProgram.getImageBase();
            try {
                disassemble(base);
                createFunction(base, null);
            } catch (Exception e) {
                println("ExportDecomp: entry-function fallback failed: " + e.getMessage());
            }
        }

        writeFunctionsJson(new File(outDir, "functions.json"), fm, listing);
        writeDisassembly(new File(outDir, "disasm.lst"), listing);
        writeDecompiledC(new File(outDir, "decompiled.c"), fm);

        println("ExportDecomp: wrote export to " + outDir.getAbsolutePath());
    }

    // Minimal RFC 8259 string escaping: backslash, quote, and control chars.
    private static String jsonEscape(String s) {
        StringBuilder b = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': b.append("\\\\"); break;
                case '"': b.append("\\\""); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.toString();
    }

    private long functionEnd(Function fn) {
        long end = fn.getEntryPoint().getOffset();
        AddressRangeIterator ranges = fn.getBody().getAddressRanges();
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            long max = range.getMaxAddress().getOffset();
            if (max > end) {
                end = max;
            }
        }
        return end + 1;
    }

    private String dataRefsJson(Function fn) {
        Set<Long> refs = new TreeSet<Long>();
        AddressIterator addrs = fn.getBody().getAddresses(true);
        while (addrs.hasNext()) {
            Address from = addrs.next();
            Reference[] fromRefs = currentProgram.getReferenceManager().getReferencesFrom(from);
            for (Reference ref : fromRefs) {
                RefType type = ref.getReferenceType();
                if (type != null && type.isFlow()) {
                    continue;
                }
                Address to = ref.getToAddress();
                if (to == null || !to.isMemoryAddress()) {
                    continue;
                }
                refs.add(to.getOffset());
            }
        }
        StringBuilder out = new StringBuilder();
        out.append("[");
        boolean first = true;
        for (Long ref : refs) {
            if (!first) {
                out.append(", ");
            }
            first = false;
            out.append("\"");
            out.append(jsonEscape(String.format("0x%x", ref)));
            out.append("\"");
        }
        out.append("]");
        return out.toString();
    }

    private void writeFunctionsJson(File f, FunctionManager fm, Listing listing) throws Exception {
        try (PrintWriter w = new PrintWriter(new FileWriter(f))) {
            w.println("[");
            boolean first = true;
            for (Function fn : fm.getFunctions(true)) {
                if (!first) {
                    w.println(",");
                }
                first = false;
                String name = jsonEscape(fn.getName());
                long entry = fn.getEntryPoint().getOffset();
                long end = functionEnd(fn);
                w.print(String.format(
                    "  {\"name\": \"%s\", \"entry\": \"0x%x\", \"end\": \"0x%x\", \"size\": %d, \"data_refs\": %s}",
                    name, entry, end, fn.getBody().getNumAddresses(), dataRefsJson(fn)));
            }
            if (!first) {
                w.println();
            }
            w.println("]");
        }
    }

    private void writeDisassembly(File f, Listing listing) throws Exception {
        try (PrintWriter w = new PrintWriter(new FileWriter(f))) {
            InstructionIterator it = listing.getInstructions(true);
            while (it.hasNext()) {
                Instruction ins = it.next();
                // Format: "address: bytes  mnemonic operands" (spec §5.3).
                StringBuilder hex = new StringBuilder();
                try {
                    for (byte b : ins.getBytes()) {
                        hex.append(String.format("%02x", b & 0xff));
                    }
                } catch (Exception e) {
                    hex.append("??");
                }
                w.println(ins.getAddress().toString() + ": " + hex + "  " + ins.toString());
            }
        }
    }

    private void writeDecompiledC(File f, FunctionManager fm) throws Exception {
        DecompInterface dif = new DecompInterface();
        try {
            dif.openProgram(currentProgram);
            try (PrintWriter w = new PrintWriter(new FileWriter(f))) {
                for (Function fn : fm.getFunctions(true)) {
                    w.println("// " + fn.getName() + " @ " + fn.getEntryPoint());
                    DecompileResults res = dif.decompileFunction(fn, 60, monitor);
                    if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                        w.println(res.getDecompiledFunction().getC());
                    } else {
                        w.println("// <decompilation failed>");
                    }
                    w.println();
                }
            }
        } finally {
            dif.dispose();
        }
    }
}
