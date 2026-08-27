// ExportDecomp.java — Ghidra headless post-script for pixel-modem-extractor.
//
// Arg[0] = output directory.
// Arg[1] = canonical import-kit root.
// Arg[2] = expected image label.
// Arg[3] = expected PAL identity or "none".
// Arg[4] = canonical task manifest or "-" under the ApplyPalTasks rule.
// Arg[5] = canonical scatter manifest or "-" under the same rule.
// Arg[6] = canonical pass-1 symbol map or "-" for pass 1 and generated
//          single-pass kits.
// Arg[7] = expected lowercase symbol-map BLAKE3, or literal "none" with "-".
//
// A strict HeadlessScript: before any export output or marker is written it
// validates the retained map/properties through PalTasksSupport (a present
// PAL manifest re-authenticates the manifest, raw/scatter memory, and the
// complete applied state; identity none requires every PAL surface absent),
// derives the current execution identities from the current function bodies
// with per-range BLAKE3 over current program memory, and — in pass 2 —
// compares every current body to the retained pass-1 map exactly (a changed
// range boundary, ISA, byte, or hash fails). The verification walk runs under
// one 15-minute deadline and, for a present manifest, a 64-MiB aggregate
// task-function-body ceiling. Monitor-aware operations inherit headless
// cancellation and receive only the remaining deadline; every long operation
// is checked on return. Outputs are published atomically (temporary files moved
// into place) only after a direct deadline gate, and the exact three-line v3
// marker is replaced LAST under the same gate:
//
// pixel-modem-extractor-ghidra-export-v3
// pal_tasks=<identity-or-none>
// symbol_map=<lowercase-map-blake3-or-none>
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
// fixed-order ApplyThumbNames -> ApplySymbols -> ApplyGlobals ->
// ApplyGlobalTypes application; getC() then emits regenerated C with names +
// plate comments baked in.
//@category PixelModem
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.task.TimeoutTaskMonitor;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;

public class ExportDecomp extends HeadlessScript {
    private static final String COMPLETION_FORMAT = "pixel-modem-extractor-ghidra-export-v3";
    private static final long TASK_BODY_BYTES = PalTasksSupport.MAX_TASK_BODY_BYTES;
    private static final long VALIDATION_BUDGET_MS =
            PalTasksSupport.EXPORT_VALIDATION_BUDGET_MS;

    private static void fail(String message) {
        throw new PalTasksSupport.PalError(message);
    }

    private long deadline;
    private long taskBodyBytes;
    private TimeoutTaskMonitor deadlineTaskMonitor;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 8) {
            fail("expected exactly eight arguments: output directory, kit root, image label, "
                    + "PAL identity, task manifest, scatter manifest, pass-1 symbol map, "
                    + "expected map BLAKE3");
        }
        deadline = Math.addExact(System.currentTimeMillis(), VALIDATION_BUDGET_MS);
        File outDir = new File(args[0]);
        File kitRoot = new File(args[1]);
        String label = args[2];
        String palIdentity = args[3];
        File taskManifest = "-".equals(args[4]) ? null : new File(args[4]);
        File scatterManifest = "-".equals(args[5]) ? null : new File(args[5]);
        File mapFile = "-".equals(args[6]) ? null : new File(args[6]);
        String mapHash = args[7];

        File canonicalRoot = requireCanonicalDirectory(kitRoot);
        if (!label.equals(currentProgram.getName())) {
            fail("the expected image label does not match the current program name");
        }

        // PAL state: a present manifest is fully re-authenticated after
        // analysis; identity none requires every PAL surface absent.
        boolean palPresent = !PalTasksSupport.NONE_IDENTITY.equals(palIdentity);
        if (palPresent) {
            if (taskManifest == null) {
                fail("a present PAL identity requires the task manifest argument");
            }
            PalTasksSupport.PalManifest manifest =
                    PalTasksSupport.readPal(canonicalRoot, label, taskManifest, scatterManifest);
            checkDeadline();
            String identity = PalTasksSupport.expectedPalIdentity(manifest);
            if (!identity.equals(palIdentity)) {
                fail("the expected PAL identity does not match the manifest");
            }
            PalTasksSupport.validateApplied(currentProgram, manifest, identity);
            checkDeadline();
            chargeTaskBodies(manifest);
            checkDeadline();
        }
        else {
            if (taskManifest != null) {
                fail("identity none requires the literal '-' task manifest");
            }
            PalTasksSupport.validateAbsent(currentProgram);
            checkDeadline();
        }

        // Symbol map / pass-2 property contract.
        PalTasksSupport.SymbolMap map = null;
        String symbolMapArgument = "none";
        if (mapFile == null) {
            if (!"none".equals(mapHash)) {
                fail("an absent symbol map requires the literal 'none' hash");
            }
            String property = currentProgram.getOptions(
                    ghidra.program.model.listing.Program.PROGRAM_INFO)
                    .getString(PalTasksSupport.SYMBOL_PASS2_PROPERTY, null);
            if (property != null) {
                fail("a pass-1/single-pass export requires the SymbolPass2 property absent");
            }
        }
        else {
            if ("none".equals(mapHash)) {
                fail("a present symbol map requires its expected BLAKE3");
            }
            map = PalTasksSupport.readSymbolMapForExport(mapFile, mapHash);
            checkDeadline();
            if (!map.imageLabel.equals(label)) {
                fail("the symbol map was built for image " + map.imageLabel);
            }
            if (!palIdentity.equals(map.palIdentity)) {
                fail("the symbol map PAL identity does not match the invocation");
            }
            String expectedProperty = PalTasksSupport.expectedSymbolPass2Property(map);
            String property = currentProgram.getOptions(
                    ghidra.program.model.listing.Program.PROGRAM_INFO)
                    .getString(PalTasksSupport.SYMBOL_PASS2_PROPERTY, null);
            if (!expectedProperty.equals(property)) {
                fail("stale SymbolPass2 property: expected " + expectedProperty
                        + " but found " + property);
            }
            verifyBodiesAgainstMap(map);
            checkDeadline();
            symbolMapArgument = map.mapBlake3;
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        // Pass-1/single-pass entry fallback: a tiny anchorless blob may yield
        // no functions. A present map has already authenticated the exact
        // pass-2 function set, which this fallback must never mutate.
        if (map == null && fm.getFunctionCount() == 0) {
            Address base = currentProgram.getImageBase();
            try {
                disassemble(base);
                createFunction(base, null);
            }
            catch (Exception e) {
                fail("the entry-function fallback failed: " + e.getMessage());
            }
            checkDeadline();
        }

        outDir.mkdirs();
        List<File> temporaries = new ArrayList<File>();
        try {
            publish(outDir, "functions.json", temporaries,
                    (w) -> writeFunctionsJson(w, fm, listing));
            publish(outDir, "disasm.lst", temporaries, (w) -> writeDisassembly(w, listing));
            publish(outDir, "decompiled.c", temporaries, (w) -> writeDecompiledC(w, fm));
            writeCompletionMarker(outDir, palIdentity, symbolMapArgument);
        }
        finally {
            for (File temporary : temporaries) {
                Files.deleteIfExists(temporary.toPath());
            }
        }

        println("ExportDecomp: wrote export to " + outDir.getAbsolutePath());
    }

    private interface Writer {
        void write(PrintWriter writer) throws Exception;
    }

    private static File requireCanonicalDirectory(File file) throws IOException {
        File canonical = file == null ? null : file.getCanonicalFile();
        if (canonical == null || !file.isAbsolute() || !canonical.getPath().equals(file.getPath())
                || !canonical.isDirectory()) {
            fail("the import-kit root is not a canonical directory");
        }
        return canonical;
    }

    /** Charge each task function's current body bytes once against the cap. */
    private void chargeTaskBodies(PalTasksSupport.PalManifest manifest) throws Exception {
        FunctionManager functions = currentProgram.getFunctionManager();
        for (PalTasksSupport.PalApplication application : manifest.applications) {
            checkDeadline();
            Address entry = PalTasksSupport.programAddress(currentProgram, application.entry);
            Function function = functions.getFunctionAt(entry);
            if (function == null) {
                fail("a task application has no function at its entry " + entry);
            }
            long bytes = 0;
            AddressRangeIterator ranges = function.getBody().getAddressRanges();
            while (ranges.hasNext()) {
                checkDeadline();
                ghidra.program.model.address.AddressRange range = ranges.next();
                bytes = Math.addExact(bytes, range.getLength());
            }
            taskBodyBytes = Math.addExact(taskBodyBytes, bytes);
            if (taskBodyBytes > TASK_BODY_BYTES) {
                fail("the aggregate task-function-body bytes exceed the 64 MiB ceiling");
            }
        }
    }

    /**
     * Pass-2 identity comparison: every current function's authenticated
     * execution must appear in the retained map with the exact digest, and
     * every map execution must still exist — program drift fails closed.
     * Entries from the map's `creations` section have a separate identity:
     * current memory must still authenticate the producer ranges, and every
     * project-owned creation must retain its map/execution registry binding,
     * concrete function/symbol IDs, Ghidra execution digest, and accepted
     * Thumb projection. ApplyThumbNames passes the explicit returned
     * disassembly set to CreateFunctionCmd, and the final body must remain
     * wholly inside the authenticated producer ranges rather than expand
     * through open-ended flow.
     */
    private void verifyBodiesAgainstMap(PalTasksSupport.SymbolMap map) throws Exception {
        FunctionManager functions = currentProgram.getFunctionManager();
        Map<Long, String> expected = new HashMap<Long, String>();
        for (PalTasksSupport.MapExecution execution : map.executions) {
            checkDeadline();
            expected.put(execution.entry, execution.executionBlake3);
        }
        java.util.Set<Long> created = new java.util.HashSet<Long>();
        StringPropertyMap creationOwnership = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap(PalTasksSupport.THUMB_CREATION_OWNERSHIP_MAP);
        for (PalTasksSupport.MapCreation creation : map.creations) {
            withinDeadline((operationMonitor) -> {
                PalTasksSupport.validateThumbCreationExecution(
                        currentProgram, operationMonitor, creation);
                return null;
            });
            String owned = creationOwnership == null ? null
                    : creationOwnership.getString(
                            PalTasksSupport.programAddress(currentProgram, creation.entry));
            if (owned != null) {
                withinDeadline((operationMonitor) -> {
                    PalTasksSupport.validateOwnedThumbCreation(currentProgram, operationMonitor,
                            creationOwnership, map, creation);
                    return null;
                });
            }
            else {
                Function function = functions.getFunctionAt(
                        PalTasksSupport.programAddress(currentProgram, creation.entry));
                if (function != null && creation.finalPrimary.equals(function.getName())
                        && creation.finalSource.equals(PalTasksSupport.primarySource(
                                function.getSymbol().getSource()))) {
                    fail("an exact Thumb creation lacks ownership at "
                            + function.getEntryPoint());
                }
            }
            created.add(creation.entry);
        }
        if (creationOwnership != null) {
            AddressIterator owned = creationOwnership.getPropertyIterator();
            while (owned.hasNext()) {
                checkDeadline();
                Address address = owned.next();
                if (!address.getAddressSpace().equals(
                        currentProgram.getAddressFactory().getDefaultAddressSpace())) {
                    fail("the Thumb creation registry uses a non-default address space at "
                            + address);
                }
                if (!created.contains(address.getOffset())) {
                    fail("the Thumb creation registry has an entry absent from the map at "
                            + address);
                }
            }
        }
        FunctionIterator iterator = functions.getFunctions(true);
        int compared = 0;
        while (iterator.hasNext()) {
            checkDeadline();
            Function function = iterator.next();
            if (created.contains(function.getEntryPoint().getOffset())) {
                continue; // an owned ApplyThumbNames creation, revalidated above
            }
            PalTasksSupport.DecodeProjection projection =
                    withinDeadline((operationMonitor) -> PalTasksSupport.decodeProjection(
                            currentProgram, operationMonitor, function));
            if (!projection.errors.isEmpty()) {
                continue; // a quarantined record carries no execution identity
            }
            String digest = withinDeadline((operationMonitor) ->
                    PalTasksSupport.currentExecutionDigest(
                            currentProgram, operationMonitor, function));
            long entry = function.getEntryPoint().getOffset();
            String expectedDigest = expected.remove(entry);
            if (expectedDigest == null) {
                fail("a current function has no pass-1 execution identity at "
                        + function.getEntryPoint());
            }
            if (!expectedDigest.equals(digest)) {
                fail("the current body drifted from the pass-1 identity at "
                        + function.getEntryPoint());
            }
            compared++;
        }
        if (!expected.isEmpty() || compared != map.executions.size()) {
            fail("the current function set does not cover every pass-1 execution exactly once");
        }
        checkDeadline();
    }

    private interface DeadlineOperation<T> {
        T run(TimeoutTaskMonitor operationMonitor) throws Exception;
    }

    private long remainingDeadline() {
        long remaining = deadline - System.currentTimeMillis();
        if (remaining <= 0) {
            fail("the export verification deadline was exhausted");
        }
        if (monitor.isCancelled()) {
            fail("the export verification was cancelled");
        }
        return remaining;
    }

    private void checkDeadline() {
        remainingDeadline();
    }

    private void checkDeadline(TimeoutTaskMonitor operationMonitor) {
        if (operationMonitor.didTimeout() || System.currentTimeMillis() >= deadline) {
            fail("the export verification deadline was exhausted");
        }
        if (operationMonitor.isCancelled() || monitor.isCancelled()) {
            fail("the export verification was cancelled");
        }
    }

    private TimeoutTaskMonitor deadlineMonitor() {
        if (deadlineTaskMonitor == null) {
            // One timer enforces the absolute phase deadline. Completed
            // TimeoutTaskMonitors retain their timer, so one per function
            // would accumulate until the deadline on production inventories.
            deadlineTaskMonitor = TimeoutTaskMonitor.timeoutIn(
                    remainingDeadline(), TimeUnit.MILLISECONDS, monitor);
        }
        return deadlineTaskMonitor;
    }

    private <T> T withinDeadline(DeadlineOperation<T> operation) throws Exception {
        TimeoutTaskMonitor operationMonitor = deadlineMonitor();
        try {
            T result = operation.run(operationMonitor);
            checkDeadline(operationMonitor);
            return result;
        }
        catch (Exception error) {
            checkDeadline(operationMonitor);
            throw error;
        }
    }

    // ---------------------------------------------------------------------
    // Atomic publication
    // ---------------------------------------------------------------------

    /** Writes one output through a sibling temporary and moves it into place. */
    private void publish(File outDir, String name, List<File> temporaries, Writer writer)
            throws Exception {
        File temporary = File.createTempFile(name + ".", ".tmp", outDir);
        temporaries.add(temporary);
        PrintWriter w = new PrintWriter(new FileWriter(temporary));
        try (w) {
            writer.write(w);
        }
        checkWriter(w, temporary);
        File destination = new File(outDir, name);
        checkDeadline();
        Files.move(temporary.toPath(), destination.toPath(),
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        temporaries.remove(temporary);
    }

    private void writeCompletionMarker(File outDir, String palIdentity, String symbolMap)
            throws Exception {
        checkDeadline();
        File parent = outDir.getParentFile();
        if (parent == null) {
            throw new Exception("export directory has no parent for completion marker");
        }
        File marker = new File(parent, outDir.getName() + ".complete");
        File temporary = File.createTempFile(outDir.getName() + ".complete.", ".tmp", parent);
        try {
            try (FileWriter writer = new FileWriter(temporary, false)) {
                writer.write(COMPLETION_FORMAT + "\n");
                writer.write("pal_tasks=" + palIdentity + "\n");
                writer.write("symbol_map=" + symbolMap + "\n");
            }
            checkDeadline();
            Files.move(temporary.toPath(), marker.toPath(),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }
        finally {
            Files.deleteIfExists(temporary.toPath());
        }
    }

    // ---------------------------------------------------------------------
    // Export writers
    // ---------------------------------------------------------------------

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

    private String decodeRangesJson(List<PalTasksSupport.DecodeRange> ranges) {
        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        for (PalTasksSupport.DecodeRange range : ranges) {
            checkDeadline();
            if (!first) out.append(", ");
            first = false;
            out.append(String.format(
                "{\"isa\":\"%s\",\"start\":\"0x%x\",\"end\":\"0x%x\",\"blake3\":\"%s\"}",
                range.isa,
                range.start,
                range.end,
                range.blake3));
        }
        out.append("]");
        return out.toString();
    }

    private String decodeErrorsJson(List<PalTasksSupport.DecodeError> errors) {
        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        for (PalTasksSupport.DecodeError error : errors) {
            checkDeadline();
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
            checkDeadline();
            Address from = addrs.next();
            Reference[] fromRefs = currentProgram.getReferenceManager().getReferencesFrom(from);
            for (Reference ref : fromRefs) {
                checkDeadline();
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

    private static void checkWriter(PrintWriter writer, File file) throws IOException {
        if (writer.checkError()) {
            throw new IOException("ExportDecomp: failed to write " + file.getAbsolutePath());
        }
    }

    private void writeFunctionsJson(PrintWriter w, FunctionManager fm, Listing listing)
            throws Exception {
        w.println("[");
        boolean first = true;
        for (Function fn : fm.getFunctions(true)) {
            checkDeadline();
            if (!first) {
                w.println(",");
            }
            first = false;
            String name = jsonEscape(fn.getName());
            long entry = fn.getEntryPoint().getOffset();
            long end = PalTasksSupport.functionEnd(currentProgram, fn);
            PalTasksSupport.DecodeProjection projection =
                    withinDeadline((operationMonitor) -> PalTasksSupport.decodeProjection(
                            currentProgram, operationMonitor, fn));
            // Ghidra mirrors a referenced function's primary onto its thunks
            // whenever either is renamed, so pass-2 naming decisions must
            // know the thunk relation. External thunks (referenced symbol,
            // no in-program function) carry no relation.
            String thunkOf = "null";
            if (fn.isThunk()) {
                Function referenced = fn.getThunkedFunction(false);
                if (referenced != null && !referenced.isExternal()) {
                    thunkOf = String.format("\"0x%x\"",
                            referenced.getEntryPoint().getOffset());
                }
            }
            w.print(String.format(
                "  {\"name\": \"%s\", \"primary_source\": \"%s\", \"entry\": \"0x%x\", \"end\": \"0x%x\", \"size\": %d, \"decode_ranges\": %s, \"decode_range_errors\": %s, \"data_refs\": %s, \"thunk_of\": %s}",
                name,
                PalTasksSupport.primarySource(fn.getSymbol().getSource()),
                entry,
                end,
                fn.getBody().getNumAddresses(),
                decodeRangesJson(projection.ranges),
                decodeErrorsJson(projection.errors),
                dataRefsJson(fn),
                thunkOf));
            checkDeadline();
        }
        if (!first) {
            w.println();
        }
        w.println("]");
    }

    private void writeDisassembly(PrintWriter w, Listing listing) throws Exception {
        InstructionIterator it = listing.getInstructions(true);
        while (it.hasNext()) {
            checkDeadline();
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

    private void writeDecompiledC(PrintWriter w, FunctionManager fm) throws Exception {
        DecompInterface dif = new DecompInterface();
        try {
            dif.openProgram(currentProgram);
            for (Function fn : fm.getFunctions(true)) {
                checkDeadline();
                w.println("// " + fn.getName() + " @ " + fn.getEntryPoint());
                DecompileResults res = withinDeadline((operationMonitor) ->
                        dif.decompileFunction(fn, 60, operationMonitor));
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    String body = res.getDecompiledFunction().getC();
                    checkDeadline();
                    w.println(body);
                } else {
                    w.println("// <decompilation failed>");
                }
                w.println();
                checkDeadline();
            }
        }
        finally {
            dif.dispose();
        }
    }
}
