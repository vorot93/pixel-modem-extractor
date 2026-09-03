// ExportDecomp.java — Ghidra headless post-script for pixel-modem-extractor.
//
// Arg[0] = output directory.
// Arg[1] = canonical import-kit root.
// Arg[2] = expected image label.
// Arg[3] = expected exception-root identity or "none".
// Arg[4] = canonical exception-root manifest or "-".
// Arg[5] = expected PAL identity or "none".
// Arg[6] = canonical task manifest or "-" under the ApplyPalTasks rule.
// Arg[7] = expected startup-metadata identity or "none".
// Arg[8] = canonical startup-metadata manifest or "-".
// Arg[9] = canonical scatter manifest or "-" shared by the manifests.
// Arg[10] = canonical pass-1 symbol map or "-" for pass 1 and generated
//           single-pass kits.
// Arg[11] = expected lowercase symbol-map BLAKE3, or literal "none" with "-".
//
// A strict HeadlessScript: before any export output or marker is written it
// retains and validates exception roots through ExceptionRootsSupport and PAL
// map/properties through PalTasksSupport (a present PAL manifest keeps its
// manifest/raw/scatter handles open while re-authenticating the complete
// applied state; identity none requires every PAL surface absent),
// derives the current execution identities from the current function bodies
// with per-range BLAKE3 over current program memory, and — in pass 2 —
// compares every current body to the retained pass-1 map exactly (a changed
// range boundary, ISA, byte, or hash fails). The verification walk runs under
// one 15-minute deadline and, for a present manifest, a 64-MiB aggregate
// task-function-body ceiling. Monitor-aware operations inherit headless
// cancellation and receive only the remaining deadline; every long operation
// is checked on return. All three outputs remain sibling staging files until
// both states pass final postflight and their retained handles close. They are
// then moved into place, and the exact five-line v5 marker is replaced LAST
// under the same gate:
//
// pixel-modem-extractor-ghidra-export-v5
// exception_roots=<identity-or-none>
// pal_tasks=<identity-or-none>
// startup_metadata=<identity-or-none>
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
// fixed-order ApplyThumbNames -> ApplySymbols -> ApplyStartupMetadata ->
// ApplyGlobals -> ApplyGlobalTypes application; getC() then emits regenerated
// C with names + plate comments baked in.
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
    private static final String COMPLETION_FORMAT = "pixel-modem-extractor-ghidra-export-v5";
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
        if (args.length != 12) {
            fail("expected exactly twelve arguments: output directory, kit root, image label, "
                    + "exception-root identity, exception-root manifest, PAL identity, "
                    + "task manifest, startup identity, startup manifest, scatter manifest, "
                    + "pass-1 symbol map, expected map BLAKE3");
        }
        deadline = Math.addExact(System.currentTimeMillis(), VALIDATION_BUDGET_MS);
        File outDir = new File(args[0]);
        File kitRoot = new File(args[1]);
        String label = args[2];
        String exceptionIdentity = args[3];
        File exceptionManifest = "-".equals(args[4]) ? null : new File(args[4]);
        String palIdentity = args[5];
        File taskManifest = "-".equals(args[6]) ? null : new File(args[6]);
        String startupIdentity = args[7];
        File startupManifest = "-".equals(args[8]) ? null : new File(args[8]);
        String scatterArgument = args[9];
        File scatterManifest = "-".equals(scatterArgument) ? null : new File(scatterArgument);
        File mapFile = "-".equals(args[10]) ? null : new File(args[10]);
        String mapHash = args[11];

        File canonicalRoot = requireCanonicalDirectory(kitRoot);
        if (!label.equals(currentProgram.getName())) {
            fail("the expected image label does not match the current program name");
        }

        boolean exceptionPresent = !PalTasksSupport.NONE_IDENTITY.equals(exceptionIdentity);
        if (exceptionPresent && exceptionManifest == null) {
            fail("a present exception-root identity requires the manifest argument");
        }
        if (!exceptionPresent && exceptionManifest != null) {
            fail("exception identity none requires the literal '-' manifest");
        }
        boolean palPresent = !PalTasksSupport.NONE_IDENTITY.equals(palIdentity);
        if (palPresent && taskManifest == null) {
            fail("a present PAL identity requires the task manifest argument");
        }
        if (!palPresent && taskManifest != null) {
            fail("identity none requires the literal '-' task manifest");
        }
        boolean startupPresent = !PalTasksSupport.NONE_IDENTITY.equals(startupIdentity);
        if (startupPresent && startupManifest == null) {
            fail("a present startup-metadata identity requires the manifest argument");
        }
        if (!startupPresent && startupManifest != null) {
            fail("startup identity none requires the literal '-' manifest");
        }
        String symbolMapArgument = "none";
        List<StagedOutput> staged = new ArrayList<StagedOutput>();
        try {
            try (ExceptionRootsSupport.Validated roots = exceptionPresent
                    ? ExceptionRootsSupport.preflight(currentProgram, monitor, canonicalRoot,
                            label, exceptionManifest, scatterArgument, exceptionIdentity)
                    : null;
                    PalTasksSupport.ValidatedPal pal = palPresent
                            ? PalTasksSupport.retainPal(
                                    canonicalRoot, label, taskManifest, scatterManifest)
                            : null;
                    StartupMetadataSupport.Validated startup = startupPresent
                            ? StartupMetadataSupport.retainForExport(currentProgram, canonicalRoot,
                                    label, startupIdentity, startupManifest, scatterArgument)
                            : null) {
                if (mapFile == null && !"none".equals(mapHash)) {
                    fail("an absent symbol map requires the literal 'none' hash");
                }
                if (mapFile != null && "none".equals(mapHash)) {
                    fail("a present symbol map requires its expected BLAKE3");
                }
                try (ExceptionRootsSupport.Pass2MapState pass2State = mapFile == null
                        ? null
                        : ExceptionRootsSupport.retainTerminalPass2MapState(
                                currentProgram, deadlineMonitor(), label, exceptionIdentity,
                                roots, mapFile, mapHash)) {
                    validateExceptionState(roots);
                    validatePalState(pal, palIdentity);
                    validateStartupState(startup, startupIdentity);
                    if (pal != null) {
                        chargeTaskBodies(pal.manifest);
                        checkDeadline();
                    }

                    // Symbol map / pass-2 property contract.
                    PalTasksSupport.SymbolMap map = null;
                    if (mapFile == null) {
                        String property = currentProgram.getOptions(
                                ghidra.program.model.listing.Program.PROGRAM_INFO)
                                .getString(PalTasksSupport.SYMBOL_PASS2_PROPERTY, null);
                        if (property != null) {
                            fail("a pass-1/single-pass export requires the SymbolPass2 property absent");
                        }
                        if (roots != null) {
                            ExceptionRootsSupport.validatePass2Lineage(currentProgram);
                        }
                    }
                    else {
                        map = pass2State.map;
                        checkDeadline();
                        if (!palIdentity.equals(map.palIdentity)) {
                            fail("the symbol map PAL identity does not match the invocation");
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
                    PalTasksSupport.ThumbOwnershipState thumbOwnership = pass2State == null
                            ? null : pass2State.thumbOwnership();
                    stage(outDir, "functions.json", staged,
                            (w) -> writeFunctionsJson(w, fm, listing, thumbOwnership));
                    stage(outDir, "disasm.lst", staged,
                            (w) -> writeDisassembly(w, listing));
                    stage(outDir, "decompiled.c", staged, (w) -> writeDecompiledC(w, fm));
                    validateExceptionState(roots);
                    validatePalState(pal, palIdentity);
                    validateStartupState(startup, startupIdentity);
                    if (pass2State != null) {
                        pass2State.validate(ExceptionRootsSupport.Pass2MapPhase.TERMINAL);
                    }
                }
            }
            publishStaged(staged);
            writeCompletionMarker(outDir, exceptionIdentity, palIdentity, startupIdentity,
                    symbolMapArgument);
        }
        finally {
            for (StagedOutput output : staged) {
                Files.deleteIfExists(output.temporary.toPath());
            }
        }

        println("ExportDecomp: wrote export to " + outDir.getAbsolutePath());
    }

    private interface Writer {
        void write(PrintWriter writer) throws Exception;
    }

    private static final class StagedOutput {
        final File temporary;
        final File destination;

        StagedOutput(File temporary, File destination) {
            this.temporary = temporary;
            this.destination = destination;
        }
    }

    private static File requireCanonicalDirectory(File file) throws IOException {
        File canonical = file == null ? null : file.getCanonicalFile();
        if (canonical == null || !file.isAbsolute() || !canonical.getPath().equals(file.getPath())
                || !canonical.isDirectory()) {
            fail("the import-kit root is not a canonical directory");
        }
        return canonical;
    }

    private void validateExceptionState(ExceptionRootsSupport.Validated roots) throws Exception {
        if (roots == null) {
            ExceptionRootsSupport.validateAbsent(currentProgram);
        }
        else {
            ExceptionRootsSupport.validateApplied(currentProgram, roots.manifest, roots.identity);
            roots.verifyRetainedFiles();
        }
        checkDeadline();
    }

    private void validatePalState(PalTasksSupport.ValidatedPal pal, String expectedIdentity)
            throws Exception {
        if (pal == null) {
            PalTasksSupport.validateAbsent(currentProgram);
        }
        else {
            if (!pal.identity.equals(expectedIdentity)) {
                fail("the expected PAL identity does not match the manifest");
            }
            PalTasksSupport.validateApplied(currentProgram, pal.manifest, pal.identity);
            pal.verifyRetainedFiles();
        }
        checkDeadline();
    }

    private void validateStartupState(StartupMetadataSupport.Validated startup,
            String expectedIdentity) throws Exception {
        if (startup == null) {
            StartupMetadataSupport.validateAbsent(currentProgram);
        }
        else {
            if (!startup.identity.equals(expectedIdentity)) {
                fail("the expected startup-metadata identity does not match the manifest");
            }
            StartupMetadataSupport.validateApplied(currentProgram, startup.manifest,
                    startup.identity);
            startup.verifyRetainedFiles();
        }
        checkDeadline();
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
     * current memory must still authenticate the producer ranges. The shared
     * terminal validator has already required every Thumb ownership row to be
     * represented exactly once by either a current creation or an authenticated
     * execution; an execution-represented successor row continues through the
     * ordinary exact function-set comparison below.
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

    /** Writes and validates one sibling temporary without changing its destination. */
    private void stage(File outDir, String name, List<StagedOutput> staged, Writer writer)
            throws Exception {
        File temporary = File.createTempFile(name + ".", ".tmp", outDir);
        StagedOutput output = new StagedOutput(temporary, new File(outDir, name));
        staged.add(output);
        PrintWriter w = new PrintWriter(new FileWriter(temporary));
        try (w) {
            writer.write(w);
        }
        checkWriter(w, temporary);
        checkDeadline();
    }

    /** Publishes every fully generated output only after final state validation and close. */
    private void publishStaged(List<StagedOutput> staged) throws Exception {
        for (StagedOutput output : staged) {
            checkDeadline();
            Files.move(output.temporary.toPath(), output.destination.toPath(),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }
        checkDeadline();
    }

    private void writeCompletionMarker(File outDir, String exceptionIdentity,
            String palIdentity, String startupIdentity, String symbolMap) throws Exception {
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
                writer.write("exception_roots=" + exceptionIdentity + "\n");
                writer.write("pal_tasks=" + palIdentity + "\n");
                writer.write("startup_metadata=" + startupIdentity + "\n");
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

    private void writeFunctionsJson(PrintWriter w, FunctionManager fm, Listing listing,
            PalTasksSupport.ThumbOwnershipState thumbOwnership) throws Exception {
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
            PalTasksSupport.ThumbCreationOwnership owned = thumbOwnership == null
                    ? null : thumbOwnership.at(entry);
            String nomination = owned == null ? "" : String.format(
                    ", \"thumb_creation_producer_blake3\": \"%s\"",
                    owned.producerExecutionBlake3);
            w.print(String.format(
                "  {\"name\": \"%s\", \"primary_source\": \"%s\", \"entry\": \"0x%x\", \"end\": \"0x%x\", \"size\": %d, \"decode_ranges\": %s, \"decode_range_errors\": %s, \"data_refs\": %s, \"thunk_of\": %s%s}",
                name,
                PalTasksSupport.primarySource(fn.getSymbol().getSource()),
                entry,
                end,
                fn.getBody().getNumAddresses(),
                decodeRangesJson(projection.ranges),
                decodeErrorsJson(projection.errors),
                dataRefsJson(fn),
                thunkOf,
                nomination));
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
