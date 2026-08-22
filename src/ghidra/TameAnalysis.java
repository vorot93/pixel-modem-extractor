// TameAnalysis.java — Ghidra headless PRE-script for pixel-modem-extractor.
// Runs before auto-analysis as one strict HeadlessScript transaction.
//
//   arg[0] = mode: "tighten" (Phase 2+ default) or "datamark" (Phase-1
//             fallback, also used by --no-thumb-decompile).
//   arg[1] = expected PAL identity: "none" (every current caller until the
//             PAL task-inventory generation supplies a present one) or the
//             v1 present grammar. Validated through PalTasksSupport — this
//             script owns no second registry parser or digest.
//   arg[2..] = datamark only: sorted, non-overlapping "addrHex:lenHex"
//             regions (tighten accepts none).
//
// tighten mutates and verifies analyzer options only; it never data-marks
// or clears code. datamark snapshots the analyzer options, streams the
// existing code units and function bodies into the canonical preservation
// digests under fixed limits (4,194,304 units; 262,144 functions; 1,000,000
// streamed intervals/gaps/arrays; 64 MiB retained metadata), plans the
// maximal undefined gaps BEFORE any mutation, creates byte arrays of at
// most 16 MiB exactly partitioning those gaps, then rescans once: preserved
// units/count/digest identical, created arrays exact, total count additive,
// function digest identical, and the applied PAL state still valid. Any
// failure undoes the journaled mutations in reverse order, aborts the
// script transaction with end(false), and rethrows — no partial
// data-marking survives. Every argument and region check runs before the
// first mutation under one 15-minute phase deadline (there are no
// monitor-consuming commands here, so the deadline is checked directly in
// the loops instead of through a TimeoutTaskMonitor).
//
// Datamark success prints exactly one machine-readable summary line:
//
//   TameAnalysis: {"mode":"datamark","identity":<json>,"regions":<n>,
//     "region_bytes":<n>,"gaps":<n>,"gap_bytes":<n>,"arrays":<n>,
//     "units_before":<n>,"units_after":<n>,"code_units_digest":<hex>,
//     "functions_before":<n>,"function_digest":<hex>,
//     "gap_digests":[<hex>,...]}
//@category PixelModem
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import java.util.ArrayList;
import java.util.List;

public class TameAnalysis extends HeadlessScript {
    private static final long PHASE_BUDGET_MS = 15 * 60_000L;
    private static final int MAX_REGIONS = 4096;
    private static final long MAX_REGION_AGGREGATE_BYTES = 512L * 1024L * 1024L;
    private static final int MAX_STREAM_RECORDS = 1_000_000;
    private static final long MAX_METADATA_BYTES = 64L * 1024L * 1024L;
    private static final int MAX_ARRAY_BYTES = 16 * 1024 * 1024;

    private static final String[] DISABLE = {
        "ARM Aggressive Instruction Finder",
        "Aggressive Instruction Finder",
    };

    // Phase 2.1 `mode=tighten` body — sourced verbatim from the Phase-2.1 full-02_MAIN
    // investigation (2026-07-21-thumb-decompilation-phase2-1-findings.md). On the FULL
    // ~87 MB 02_MAIN (N_r2_full = 151411 across 5 dense-Thumb regions), disabling the
    // Aggressive Instruction Finder (shared DISABLE) PLUS the `Repair Flow Damage`
    // sub-option of `Non-Returning Functions - Discovered` caused Ghidra 12.1.2 to
    // converge in 1398 s (23.3 min) with 0 ClearFlowAndRepairCmd log lines and 71 %
    // radare2 coverage (N_ghidra = 107955). Phase 2's status quo (empty TIGHTEN_EXTRA)
    // spun on the same image: Surface B fired at ~28 min with >100k repair lines.
    // The dense-Thumb region is NOT data-marked in this mode.
    private static final String[] TIGHTEN_EXTRA = {
        "Non-Returning Functions - Discovered.Repair Flow Damage",
    };

    private static void fail(String message) {
        throw new PalTasksSupport.PalError(message);
    }

    private static void suppress(Throwable original, Throwable cleanupFailure) {
        if (cleanupFailure == original) {
            return;
        }
        try {
            original.addSuppressed(cleanupFailure);
        }
        catch (Throwable ignored) {
            // Preserve the original failure even if suppression is unavailable.
        }
    }

    private static void rethrow(Throwable failure) throws Exception {
        if (failure instanceof Exception) {
            throw (Exception) failure;
        }
        if (failure instanceof Error) {
            throw (Error) failure;
        }
        throw new RuntimeException(failure);
    }

    private long deadline;
    private long metadataBytes;

    @Override
    public void run() throws Exception {
        deadline = Math.addExact(System.currentTimeMillis(), PHASE_BUDGET_MS);
        Preflight preflight = preflight();
        Mutation mutation = new Mutation(preflight);
        try {
            mutation.run();
        }
        catch (Throwable failure) {
            mutation.rollback(failure);
            rethrow(failure);
        }
    }

    // ---------------------------------------------------------------------
    // Preflight: complete argument and state validation before any mutation
    // ---------------------------------------------------------------------

    private static final class Region {
        final long start;
        final long length;

        Region(long start, long length) {
            this.start = start;
            this.length = length;
        }
    }

    private final class Preflight {
        final String mode;
        final String identity;
        final List<Region> regions;
        final String codeUnitsDigest;
        final String functionDigest;
        final long unitsBefore;
        final long functionsBefore;

        Preflight(String mode, String identity, List<Region> regions, String codeUnitsDigest,
                String functionDigest, long unitsBefore, long functionsBefore) {
            this.mode = mode;
            this.identity = identity;
            this.regions = regions;
            this.codeUnitsDigest = codeUnitsDigest;
            this.functionDigest = functionDigest;
            this.unitsBefore = unitsBefore;
            this.functionsBefore = functionsBefore;
        }
    }

    private Preflight preflight() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            fail("expected the mode and PAL identity arguments");
        }
        String mode = args[0];
        if (!"tighten".equals(mode) && !"datamark".equals(mode)) {
            fail("unknown mode '" + mode + "' (expected 'tighten' or 'datamark')");
        }
        String identity = args[1];
        List<Region> regions = new ArrayList<>();
        if ("tighten".equals(mode)) {
            if (args.length != 2) {
                fail("tighten mode accepts no region arguments");
            }
        }
        else {
            if (args.length - 2 > MAX_REGIONS) {
                fail("the region count exceeds " + MAX_REGIONS);
            }
            long aggregate = 0;
            long previousStart = -1;
            long previousEnd = -1;
            for (int index = 2; index < args.length; index++) {
                Region region = parseRegion(args[index]);
                if (region.start < previousStart) {
                    fail("regions are not sorted by start address at 0x"
                            + Long.toHexString(region.start));
                }
                if (region.start < previousEnd) {
                    fail("regions overlap at 0x" + Long.toHexString(region.start));
                }
                previousStart = region.start;
                previousEnd = Math.addExact(region.start, region.length);
                aggregate = Math.addExact(aggregate, region.length);
                regions.add(region);
            }
            if (aggregate > MAX_REGION_AGGREGATE_BYTES) {
                fail("the aggregate region bytes exceed the limit");
            }
            requireMapped(regions);
        }

        // Exact PAL property/absence validation through the one shared
        // support class (PalTasksSupport owns the registry grammar).
        if (PalTasksSupport.NONE_IDENTITY.equals(identity)) {
            PalTasksSupport.validateAbsent(currentProgram);
        }
        else {
            PalTasksSupport.validateAppliedIdentity(currentProgram, identity);
        }

        if ("tighten".equals(mode)) {
            return new Preflight(mode, identity, regions, null, null, 0, 0);
        }
        checkDeadline();
        String codeUnitsDigest = PalTasksSupport.codeUnitsDigestHex(currentProgram, null);
        String functionDigest = PalTasksSupport.functionBodiesDigestHex(currentProgram);
        long unitsBefore = currentProgram.getListing().getNumCodeUnits();
        long functionsBefore = countFunctions();
        return new Preflight(mode, identity, regions, codeUnitsDigest, functionDigest,
                unitsBefore, functionsBefore);
    }

    private long countFunctions() {
        long count = 0;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            functions.next();
            count++;
        }
        return count;
    }

    private Region parseRegion(String arg) {
        int colon = arg.indexOf(':');
        if (colon <= 0 || colon != arg.lastIndexOf(':')) {
            fail("malformed region argument (expected addrHex:lenHex): " + arg);
        }
        long start = parseHex(arg.substring(0, colon), arg);
        long length = parseHex(arg.substring(colon + 1), arg);
        if (length == 0) {
            fail("the region length is zero: " + arg);
        }
        if (start > PalTasksSupport.UINT32_MAX || length > PalTasksSupport.UINT32_MAX
                || Math.addExact(start, length) > PalTasksSupport.UINT32_END) {
            fail("the region wraps the 32-bit address space: " + arg);
        }
        return new Region(start, length);
    }

    private long parseHex(String text, String arg) {
        if (text.isEmpty() || text.length() > 16) {
            fail("malformed region argument (expected addrHex:lenHex): " + arg);
        }
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            boolean hex = (character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f')
                    || (character >= 'A' && character <= 'F');
            if (!hex) {
                fail("malformed region argument (expected addrHex:lenHex): " + arg);
            }
        }
        try {
            return Long.parseUnsignedLong(text, 16);
        }
        catch (NumberFormatException error) {
            fail("malformed region argument (expected addrHex:lenHex): " + arg);
            return -1;
        }
    }

    private void requireMapped(List<Region> regions) {
        Memory memory = currentProgram.getMemory();
        for (Region region : regions) {
            Address cursor = toAddr(region.start);
            Address limit = toAddr(Math.addExact(region.start, region.length) - 1);
            while (cursor.compareTo(limit) <= 0) {
                MemoryBlock block = memory.getBlock(cursor);
                if (block == null || !block.isInitialized()) {
                    fail("the region is not fully inside initialized memory at " + cursor);
                }
                if (block.getEnd().compareTo(limit) >= 0) {
                    break;
                }
                cursor = block.getEnd().add(1);
            }
        }
    }

    // ---------------------------------------------------------------------
    // Bounded mutation
    // ---------------------------------------------------------------------

    @FunctionalInterface
    private interface Undo {
        void run() throws Exception;
    }

    private static final class Chunk {
        final long start;
        final long length;

        Chunk(long start, long length) {
            this.start = start;
            this.length = length;
        }
    }

    private static final class Gap {
        final long start;
        final long length;
        final String digest;
        final List<Chunk> chunks;

        Gap(long start, long length, String digest, List<Chunk> chunks) {
            this.start = start;
            this.length = length;
            this.digest = digest;
            this.chunks = chunks;
        }
    }

    private final class Mutation {
        private final Preflight preflight;
        private final List<Undo> undoJournal = new ArrayList<>();
        private final AddressSet createdRanges = new AddressSet();
        private final List<Gap> gaps = new ArrayList<>();
        private long streamedRecords;
        private int plannedChunks;
        private int arraysCreated;

        Mutation(Preflight preflight) {
            this.preflight = preflight;
        }

        private void journal(Undo step) {
            undoJournal.add(step);
        }

        void run() throws Exception {
            checkDeadline();
            Options opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
            if ("tighten".equals(preflight.mode)) {
                disable(opts, DISABLE);
                disable(opts, TIGHTEN_EXTRA);
                verifyDisabled(opts, DISABLE);
                verifyDisabled(opts, TIGHTEN_EXTRA);
                println("TameAnalysis: mode=tighten (Phase 2+)");
                return;
            }
            disable(opts, DISABLE);
            planGaps();
            createArrays();
            verifyRescan();
            println("TameAnalysis: mode=datamark (Phase-1 fallback)");
            printSummary();
        }

        private void disable(Options opts, String[] names) {
            for (String name : names) {
                if (!opts.contains(name)) {
                    continue;
                }
                final Options options = opts;
                final String optionName = name;
                final boolean priorValue = opts.getBoolean(name, true);
                journal(() -> options.setBoolean(optionName, priorValue));
                chargeMetadata();
                opts.setBoolean(name, false);
                println("TameAnalysis: disabled '" + name + "'");
            }
        }

        private void verifyDisabled(Options opts, String[] names) {
            for (String name : names) {
                if (opts.contains(name) && opts.getBoolean(name, true)) {
                    fail("the analyzer option could not be disabled: " + name);
                }
            }
        }

        /**
         * Streams each region's defined units in address order and records
         * the maximal runs of undefined addresses (the gaps) with their
         * pre-mutation content digests and array chunk plans — all before
         * the first mutation.
         */
        private void planGaps() throws Exception {
            Listing listing = currentProgram.getListing();
            for (Region region : preflight.regions) {
                checkDeadline();
                long regionEnd = Math.addExact(region.start, region.length);
                long cursor = region.start;
                // A defined unit starting before the region may extend into it.
                Instruction straddlingInstruction =
                        listing.getInstructionContaining(toAddr(cursor));
                if (straddlingInstruction != null) {
                    cursor = Math.max(cursor, definedEnd(straddlingInstruction));
                }
                Data straddlingData = listing.getDefinedDataContaining(toAddr(cursor));
                if (straddlingData != null) {
                    cursor = Math.max(cursor, definedEnd(straddlingData));
                }
                AddressSet view = new AddressSet(toAddr(region.start), toAddr(regionEnd - 1));
                InstructionIterator instructions = listing.getInstructions(view, true);
                DataIterator dataUnits = listing.getDefinedData(view, true);
                Instruction nextInstruction = instructions.hasNext() ? instructions.next() : null;
                Data nextData = dataUnits.hasNext() ? dataUnits.next() : null;
                while (cursor < regionEnd) {
                    while (nextInstruction != null && startsBefore(nextInstruction, cursor)) {
                        nextInstruction = instructions.hasNext() ? instructions.next() : null;
                    }
                    while (nextData != null && startsBefore(nextData, cursor)) {
                        nextData = dataUnits.hasNext() ? dataUnits.next() : null;
                    }
                    long instructionStart = nextInstruction == null ? Long.MAX_VALUE
                            : nextInstruction.getAddress().getOffset();
                    long dataStart = nextData == null ? Long.MAX_VALUE
                            : nextData.getAddress().getOffset();
                    CodeUnit next = null;
                    boolean nextIsInstruction = false;
                    if (instructionStart < regionEnd && instructionStart <= dataStart) {
                        next = nextInstruction;
                        nextIsInstruction = true;
                    }
                    else if (dataStart < regionEnd) {
                        next = nextData;
                    }
                    if (next == null) {
                        recordGap(cursor, regionEnd);
                        break;
                    }
                    if (++streamedRecords > MAX_STREAM_RECORDS) {
                        fail("the streamed code-unit interval count exceeds the limit");
                    }
                    long nextStart = next.getAddress().getOffset();
                    if (nextStart > cursor) {
                        recordGap(cursor, nextStart);
                    }
                    cursor = Math.max(cursor, definedEnd(next));
                    if (nextIsInstruction) {
                        nextInstruction = instructions.hasNext() ? instructions.next() : null;
                    }
                    else {
                        nextData = dataUnits.hasNext() ? dataUnits.next() : null;
                    }
                    checkDeadline();
                }
            }
        }

        private boolean startsBefore(CodeUnit unit, long address) {
            return unit.getAddress().getOffset() < address;
        }

        private long definedEnd(CodeUnit unit) {
            return Math.addExact(unit.getAddress().getOffset(), unit.getLength());
        }

        private void recordGap(long start, long endExclusive) {
            long length = endExclusive - start;
            if (length <= 0 || gaps.size() >= MAX_STREAM_RECORDS) {
                fail("the planned gap count exceeds the limit");
            }
            String digest = PalTasksSupport.memoryDigestHex(currentProgram, start, length);
            List<Chunk> chunks = new ArrayList<>();
            long offset = 0;
            while (offset < length) {
                long chunkLength = Math.min(length - offset, MAX_ARRAY_BYTES);
                if (plannedChunks >= MAX_STREAM_RECORDS) {
                    fail("the planned array count exceeds the limit");
                }
                chunks.add(new Chunk(Math.addExact(start, offset), chunkLength));
                plannedChunks++;
                chargeMetadata();
                offset = Math.addExact(offset, chunkLength);
            }
            gaps.add(new Gap(start, length, digest, chunks));
            chargeMetadata();
        }

        private void createArrays() throws Exception {
            Listing listing = currentProgram.getListing();
            for (Gap gap : gaps) {
                for (Chunk chunk : gap.chunks) {
                    checkDeadline();
                    Address chunkStart = toAddr(chunk.start);
                    Address chunkLast = toAddr(Math.addExact(chunk.start, chunk.length) - 1);
                    Data created;
                    try {
                        created = listing.createData(chunkStart,
                                new ArrayDataType(ByteDataType.dataType, (int) chunk.length, 1));
                    }
                    catch (CodeUnitInsertionException error) {
                        fail("the data-mark array could not be created at " + chunkStart + ": "
                                + error.getMessage());
                        return;
                    }
                    if (created == null || created.getLength() != (int) chunk.length) {
                        fail("the data-mark array is not exact at " + chunkStart);
                    }
                    createdRanges.addRange(chunkStart, chunkLast);
                    final Address clearStart = chunkStart;
                    final Address clearLast = chunkLast;
                    journal(() -> currentProgram.getListing()
                            .clearCodeUnits(clearStart, clearLast, true));
                    chargeMetadata();
                    arraysCreated++;
                }
            }
        }

        /**
         * One rescan before commit: the preserved units (everything outside
         * the created arrays) must reproduce the preflight digest and count,
         * every created array must be an exact byte array at its planned
         * range, the gap bytes must reproduce their pre-mutation digests,
         * the function bodies must be untouched, and the applied PAL state
         * must still validate.
         */
        private void verifyRescan() throws Exception {
            checkDeadline();
            if (!PalTasksSupport.codeUnitsDigestHex(currentProgram, createdRanges)
                    .equals(preflight.codeUnitsDigest)) {
                fail("the preserved code units changed during data-marking");
            }
            Listing listing = currentProgram.getListing();
            if (listing.getNumCodeUnits()
                    != Math.addExact(preflight.unitsBefore, arraysCreated)) {
                fail("the code-unit count is not the preflight count plus the created arrays");
            }
            for (Gap gap : gaps) {
                for (Chunk chunk : gap.chunks) {
                    Data array = listing.getDefinedDataAt(toAddr(chunk.start));
                    if (array == null || array.getLength() != (int) chunk.length
                            || !array.getDataType().isEquivalent(
                                    new ArrayDataType(ByteDataType.dataType,
                                            (int) chunk.length, 1))) {
                        fail("the data-mark array is not exact at " + toAddr(chunk.start));
                    }
                }
                if (!PalTasksSupport.memoryDigestHex(currentProgram, gap.start, gap.length)
                        .equals(gap.digest)) {
                    fail("the gap bytes changed during data-marking at " + toAddr(gap.start));
                }
            }
            if (!PalTasksSupport.functionBodiesDigestHex(currentProgram)
                    .equals(preflight.functionDigest)) {
                fail("the function bodies changed during data-marking");
            }
            if (PalTasksSupport.NONE_IDENTITY.equals(preflight.identity)) {
                PalTasksSupport.validateAbsent(currentProgram);
            }
            else {
                PalTasksSupport.validateAppliedIdentity(currentProgram, preflight.identity);
            }
        }

        private void printSummary() {
            long regionBytes = 0;
            for (Region region : preflight.regions) {
                regionBytes = Math.addExact(regionBytes, region.length);
            }
            long gapBytes = 0;
            StringBuilder gapDigests = new StringBuilder();
            for (Gap gap : gaps) {
                gapBytes = Math.addExact(gapBytes, gap.length);
                if (gapDigests.length() > 0) {
                    gapDigests.append(',');
                }
                gapDigests.append('"').append(gap.digest).append('"');
            }
            println("TameAnalysis: {\"mode\":\"datamark\",\"identity\":\"" + preflight.identity
                    + "\",\"regions\":" + preflight.regions.size() + ",\"region_bytes\":"
                    + regionBytes + ",\"gaps\":" + gaps.size() + ",\"gap_bytes\":" + gapBytes
                    + ",\"arrays\":" + arraysCreated + ",\"units_before\":"
                    + preflight.unitsBefore + ",\"units_after\":"
                    + currentProgram.getListing().getNumCodeUnits()
                    + ",\"code_units_digest\":\"" + preflight.codeUnitsDigest
                    + "\",\"functions_before\":" + preflight.functionsBefore
                    + ",\"function_digest\":\"" + preflight.functionDigest
                    + "\",\"gap_digests\":[" + gapDigests + "]}");
        }

        void rollback(Throwable original) {
            for (int index = undoJournal.size() - 1; index >= 0; index--) {
                try {
                    undoJournal.get(index).run();
                }
                catch (Throwable cleanupFailure) {
                    suppress(original, cleanupFailure);
                }
            }
            try {
                // Ghidra commits a failed script transaction; abort it so no
                // unreturned partial mutation survives executeNormal's end(true).
                end(false);
            }
            catch (Throwable abortFailure) {
                suppress(original, abortFailure);
            }
        }
    }

    private void checkDeadline() {
        if (System.currentTimeMillis() >= deadline) {
            fail("the TameAnalysis phase budget was exhausted");
        }
    }

    private void chargeMetadata() {
        metadataBytes = Math.addExact(metadataBytes, 16L);
        if (metadataBytes > MAX_METADATA_BYTES) {
            fail("the retained metadata exceeds the limit");
        }
    }
}
