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
// Pass 2 of `decompose` re-runs this script unchanged after the applicable
// ApplySymbols.java and/or ApplyGlobals.java application — getC() then emits
// regenerated C with names + plate comments baked in.
//@category PixelModem
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
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
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import java.util.Set;
import java.util.TreeSet;

public class ExportDecomp extends GhidraScript {
    private static final long U32_END = 0x1_0000_0000L;
    private static final long U32_MAX = U32_END - 1L;

    private static class DecodeRange implements Comparable<DecodeRange> {
        final long start;
        long end;
        final String isa;

        DecodeRange(long start, long end, String isa) {
            this.start = start;
            this.end = end;
            this.isa = isa;
        }

        @Override
        public int compareTo(DecodeRange other) {
            int byStart = Long.compare(start, other.start);
            if (byStart != 0) return byStart;
            int byEnd = Long.compare(end, other.end);
            if (byEnd != 0) return byEnd;
            return isa.compareTo(other.isa);
        }
    }

    private static class DecodeError implements Comparable<DecodeError> {
        final String kind;
        final long address;
        final Long end;

        DecodeError(String kind, long address, Long end) {
            this.kind = kind;
            this.address = address;
            this.end = end;
        }

        @Override
        public int compareTo(DecodeError other) {
            int byAddress = Long.compare(address, other.address);
            if (byAddress != 0) return byAddress;
            int byKind = kind.compareTo(other.kind);
            if (byKind != 0) return byKind;
            if (end == null) return other.end == null ? 0 : -1;
            if (other.end == null) return 1;
            return Long.compare(end, other.end);
        }
    }

    private static class DecodeProjection {
        final List<DecodeRange> ranges;
        final List<DecodeError> errors;

        DecodeProjection(List<DecodeRange> ranges, List<DecodeError> errors) {
            this.ranges = ranges;
            this.errors = errors;
        }
    }

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

    private long functionEnd(Function fn) throws Exception {
        long end = u32ExclusiveEnd(fn.getEntryPoint());
        AddressRangeIterator ranges = fn.getBody().getAddressRanges();
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            u32Offset(range.getMinAddress());
            long exclusiveEnd = u32ExclusiveEnd(range.getMaxAddress());
            if (exclusiveEnd > end) {
                end = exclusiveEnd;
            }
        }
        return end;
    }

    private static long u32Offset(Address address) throws Exception {
        if (address == null || !address.isMemoryAddress()) {
            throw new Exception("unassignable non-memory producer address");
        }
        long offset = address.getOffset();
        if (offset < 0 || offset >= U32_END) {
            throw new Exception("unassignable producer address outside u32");
        }
        return offset;
    }

    private static long u32ExclusiveEnd(Address inclusiveEnd) throws Exception {
        long offset = u32Offset(inclusiveEnd);
        if (offset == U32_MAX) {
            throw new Exception("unassignable producer body exclusive end outside u32");
        }
        return offset + 1L;
    }

    private DecodeProjection decodeProjection(Function fn, Listing listing) throws Exception {
        long entry = u32Offset(fn.getEntryPoint());
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        List<DecodeRange> extents = new ArrayList<DecodeRange>();
        TreeSet<DecodeError> errors = new TreeSet<DecodeError>();
        InstructionIterator instructions = listing.getInstructions(fn.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            Address startAddress = instruction.getMinAddress();
            long start = u32Offset(startAddress);
            int length = instruction.getLength();
            Long end = null;
            if (length <= 0 || start > U32_MAX - length) {
                errors.add(new DecodeError("invalid_instruction_length", start, null));
            } else {
                end = start + length;
            }
            if (instruction.isLengthOverridden()) {
                errors.add(new DecodeError("overridden_instruction_length", start, end));
            }

            String isa = null;
            RegisterValue value = tMode == null ? null : instruction.getRegisterValue(tMode);
            if (value == null || !value.hasValue()) {
                errors.add(new DecodeError("missing_isa_context", start, end));
            } else {
                BigInteger unsigned = value.getUnsignedValue();
                if (BigInteger.ZERO.equals(unsigned)) {
                    isa = "arm";
                } else if (BigInteger.ONE.equals(unsigned)) {
                    isa = "thumb";
                } else {
                    errors.add(new DecodeError("invalid_isa_context", start, end));
                }
            }

            if (end == null) {
                continue;
            }
            Address endInclusive = startAddress.addNoWrap(length - 1L);
            if (!fn.getBody().contains(startAddress, endInclusive)) {
                errors.add(new DecodeError("extent_outside_function", start, end));
            }
            if (!currentProgram.getMemory().getLoadedAndInitializedAddressSet()
                    .contains(startAddress, endInclusive)) {
                errors.add(new DecodeError("extent_outside_image", start, end));
            }
            if (isa != null) {
                long alignment = isa.equals("arm") ? 4L : 2L;
                if (start % alignment != 0 || length % alignment != 0) {
                    errors.add(new DecodeError("misaligned_instruction", start, end));
                }
                extents.add(new DecodeRange(start, end, isa));
            }
        }

        Collections.sort(extents);
        DecodeRange maximalPrior = null;
        for (int index = 0; index < extents.size(); index++) {
            DecodeRange current = extents.get(index);
            if (index > 0) {
                DecodeRange previous = extents.get(index - 1);
                if (current.start == previous.start && current.end == previous.end) {
                    errors.add(new DecodeError("duplicate_extent", current.start, current.end));
                }
                if (maximalPrior != null && current.start < maximalPrior.end) {
                    errors.add(new DecodeError(
                        "overlapping_extent", maximalPrior.start, maximalPrior.end));
                    errors.add(new DecodeError(
                        "overlapping_extent", current.start, current.end));
                }
            }
            if (maximalPrior == null || current.end > maximalPrior.end) {
                maximalPrior = current;
            }
        }

        List<DecodeRange> ranges = new ArrayList<DecodeRange>();
        for (DecodeRange extent : extents) {
            if (!ranges.isEmpty()) {
                DecodeRange previous = ranges.get(ranges.size() - 1);
                if (previous.end == extent.start && previous.isa.equals(extent.isa)) {
                    previous.end = extent.end;
                    continue;
                }
            }
            ranges.add(new DecodeRange(extent.start, extent.end, extent.isa));
        }

        if (ranges.isEmpty()) {
            errors.add(new DecodeError("empty_projection", entry, null));
        } else {
            boolean entryStartsRange = false;
            boolean entryInsideRange = false;
            for (DecodeRange range : ranges) {
                entryStartsRange |= range.start == entry;
                entryInsideRange |= range.start < entry && entry < range.end;
            }
            if (!entryStartsRange) {
                errors.add(new DecodeError(
                    entryInsideRange ? "entry_not_range_start" : "missing_instruction_at_entry",
                    entry,
                    null));
            }
        }

        if (!errors.isEmpty()) {
            return new DecodeProjection(
                Collections.<DecodeRange>emptyList(),
                new ArrayList<DecodeError>(errors));
        }

        return new DecodeProjection(ranges, Collections.<DecodeError>emptyList());
    }

    private String decodeRangesJson(List<DecodeRange> ranges) {
        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        for (DecodeRange range : ranges) {
            if (!first) out.append(", ");
            first = false;
            out.append(String.format(
                "{\"isa\":\"%s\",\"start\":\"0x%x\",\"end\":\"0x%x\"}",
                range.isa,
                range.start,
                range.end));
        }
        out.append("]");
        return out.toString();
    }

    private String decodeErrorsJson(List<DecodeError> errors) {
        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        for (DecodeError error : errors) {
            if (!first) out.append(", ");
            first = false;
            out.append(String.format(
                "{\"kind\":\"%s\",\"address\":\"0x%x\",\"end\":",
                error.kind,
                error.address));
            if (error.end == null) {
                out.append("null");
            } else {
                out.append(String.format("\"0x%x\"", error.end));
            }
            out.append("}");
        }
        out.append("]");
        return out.toString();
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
                DecodeProjection projection = decodeProjection(fn, listing);
                w.print(String.format(
                    "  {\"name\": \"%s\", \"entry\": \"0x%x\", \"end\": \"0x%x\", \"size\": %d, \"decode_ranges\": %s, \"decode_range_errors\": %s, \"data_refs\": %s}",
                    name,
                    entry,
                    end,
                    fn.getBody().getNumAddresses(),
                    decodeRangesJson(projection.ranges),
                    decodeErrorsJson(projection.errors),
                    dataRefsJson(fn)));
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
