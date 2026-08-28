// PalTasksSupport.java - the one shared strict PAL support class for
// pixel-modem-extractor Ghidra scripts. Package-private on purpose: every
// PAL-aware script in the generated kit (ApplyPalTasks, TameAnalysis,
// ApplySymbols, ExportDecomp) parses PAL manifests, the v3 symbol map,
// the ownership registry, and the domain-separated digest grammars through
// this single copy; no script may grow a second permissive parser or trust
// a summary/property in place of inspecting the concrete program state.
//
// Fail-closed posture: canonical regular files only, exact key order,
// exact lexical integers, strict UTF-8, printable-ASCII manifest strings,
// checked long arithmetic before every allocation/read/hash/counter, and
// every ownership decision re-derived from current symbols/comments rather
// than guessed from names or addresses. Registry function and primary
// symbol IDs are the current function-symbol ID: renaming or deleting the
// function symbol changes that ID and thereby fails the binding.
//@category PixelModem
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.bouncycastle.crypto.digests.Blake3Digest;

final class PalTasksSupport {
    static final String PAL_FORMAT = "pixel-modem-extractor-pal-tasks-v1";
    static final String SYMBOL_MAP_FORMAT = "pixel-modem-extractor-symbol-map-v4";
    static final String RESERVED_NAMESPACE = "PixelModemExtractor_PalTasks_v1";
    static final String OWNERSHIP_MAP = "PixelModemExtractor.PalTasks.v1.Ownership";
    static final String THUMB_CREATION_OWNERSHIP_MAP =
            "PixelModemExtractor.ThumbNames.v1.Ownership";
    static final String PAL_PROPERTY = "PixelModemExtractor.PalTasks";
    static final String SYMBOL_PASS2_PROPERTY = "PixelModemExtractor.SymbolPass2";
    static final String NONE_IDENTITY = "none";
    static final String IDENTITY_VERSION = "v1";
    static final String SEMANTIC_ADAPTER = "pixel-modem-extractor-arm32-v1";
    static final String BACKEND_CRATE = "scaleservers-arm32-assembly";
    static final String CAPACITY_GUARD_RELATION = "count_ge_capacity";

    static final byte[] EXECUTION_DOMAIN = ascii("pixel-modem-extractor-execution-v1\0");
    static final byte[] LABELS_DOMAIN = ascii("pixel-modem-extractor-pal-labels-v1\0");
    static final byte[] PRIMARY_DOMAIN = ascii("pixel-modem-extractor-pal-primary-v1\0");
    static final byte[] COMMENT_DOMAIN = ascii("pixel-modem-extractor-pal-comment-v1\0");
    static final byte[] CODE_UNITS_DOMAIN = ascii("pixel-modem-extractor-code-units-v1\0");
    static final byte[] FUNCTION_BODIES_DOMAIN =
            ascii("pixel-modem-extractor-function-bodies-v1\0");

    static final String COMMENT_OPEN_MARKER = "[[pixel-modem-extractor:pal-tasks:v1]]";
    static final String COMMENT_CLOSE_MARKER = "[[/pixel-modem-extractor:pal-tasks:v1]]";
    static final String TASK_LABEL_PREFIX = "pal_TaskEntry_";
    static final String SHARED_PRIMARY_INFIX = "shared_";

    static final int MAX_PAL_MANIFEST_BYTES = 4 * 1024 * 1024;
    static final int MAX_SYMBOL_MAP_BYTES = 256 * 1024 * 1024;
    static final int MAX_TABLE_CAPACITY = 4096;
    static final int MAX_TABLE_STRIDE = 64 * 1024;
    static final int MAX_SYMBOL_LEAF_CHARS = 2000;
    static final int MAX_EXECUTIONS = 262_144;
    static final int MAX_EXECUTION_RANGES_TOTAL = 1_048_576;
    static final int MAX_EXECUTION_RANGES_EACH = 65_536;
    static final long MAX_CHARGED_RANGE_BYTES = 512L * 1024L * 1024L;
    static final int MAX_ANNOTATIONS_PER_DECISION = 256;
    static final int MAX_ANNOTATION_UTF8_BYTES = 4096;
    static final long MAX_ANNOTATION_AGGREGATE_BYTES = 64L * 1024L * 1024L;
    /** Upper bound on creation entries in one pass-2 symbol map (the Rust
     * writer enforces the same bound before serialization). */
    static final int MAX_MAP_CREATIONS = 65_536;
    static final long DESCRIPTOR_PROJECTION_OFFSET = 0x24;
    static final int MAX_CODE_UNITS = 4_194_304;
    static final int MAX_FUNCTIONS = 262_144;
    /** Aggregate task-function-body bytes the export postflight may walk. */
    static final long MAX_TASK_BODY_BYTES = 64L * 1024L * 1024L;
    /** One deadline covering the export preflight/verification walk;
     * overridable for acceptance-scale corpora (see budgetMsOverride). */
    static final long EXPORT_VALIDATION_BUDGET_MS =
            budgetMsOverride("PME_EXPORT_VALIDATION_BUDGET_MS", 15 * 60_000L);
    /** Compact Java preflight metadata retained by ApplySymbols. */
    static final long MAX_APPLY_PREFLIGHT_METADATA = 128L * 1024L * 1024L;

    static final long UINT32_MAX = 0xffff_ffffL;
    static final long UINT32_END = 0x1_0000_0000L;
    private static final int HASH_BUFFER_SIZE = 64 * 1024;

    // -------------------------------------------------------------------------
    // Authenticated decode projection (shared by ApplySymbols and ExportDecomp)
    // -------------------------------------------------------------------------

    /** One authenticated decode range: ISA, u32 bounds, memory BLAKE3. */
    static final class DecodeRange implements Comparable<DecodeRange> {
        final long start;
        long end;
        final String isa;
        final String blake3;

        DecodeRange(long start, long end, String isa, String blake3) {
            this.start = start;
            this.end = end;
            this.isa = isa;
            this.blake3 = blake3;
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

    /** One canonical decode-range defect that quarantines a record. */
    static final class DecodeError implements Comparable<DecodeError> {
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

    /** The accepted authenticated ranges, or the canonical error list. */
    static final class DecodeProjection {
        final List<DecodeRange> ranges;
        final List<DecodeError> errors;

        DecodeProjection(List<DecodeRange> ranges, List<DecodeError> errors) {
            this.ranges = ranges;
            this.errors = errors;
        }
    }

    /**
     * Derives the authenticated decode projection for one function from the
     * current program: instruction extents under the TMode context, canonical
     * geometry checks, and per-range BLAKE3 over current program memory. The
     * domain-separated {@link #executionDigestHex} is then recomputed rather
     * than copied. Shared by the pass-2 apply map and both export passes; no
     * script may grow a second copy.
     */
    static DecodeProjection decodeProjection(Program program, TaskMonitor monitor, Function fn)
            throws Exception {
        Listing listing = program.getListing();
        long entry = checkedRange(fn.getEntryPoint().getOffset(), 0, UINT32_MAX,
                "function entry");
        Register tMode = program.getLanguage().getRegister("TMode");
        List<DecodeRange> extents = new ArrayList<DecodeRange>();
        TreeSet<DecodeError> errors = new TreeSet<DecodeError>();
        InstructionIterator instructions = listing.getInstructions(fn.getBody(), true);
        while (instructions.hasNext()) {
            if (monitor.isCancelled()) {
                throw new Exception("the decode projection walk was cancelled");
            }
            Instruction instruction = instructions.next();
            Address startAddress = instruction.getMinAddress();
            long start = checkedRange(startAddress.getOffset(), 0, UINT32_MAX,
                    "instruction address");
            int length = instruction.getLength();
            Long end = null;
            if (length <= 0 || start > UINT32_MAX - length) {
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
            if (!program.getMemory().getLoadedAndInitializedAddressSet()
                    .contains(startAddress, endInclusive)) {
                errors.add(new DecodeError("extent_outside_image", start, end));
            }
            if (isa != null) {
                long alignment = isa.equals("arm") ? 4L : 2L;
                if (start % alignment != 0 || length % alignment != 0) {
                    errors.add(new DecodeError("misaligned_instruction", start, end));
                }
                extents.add(new DecodeRange(start, end, isa, null));
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
            ranges.add(new DecodeRange(extent.start, extent.end, extent.isa, null));
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

        List<DecodeRange> authenticated = new ArrayList<DecodeRange>();
        for (DecodeRange range : ranges) {
            authenticated.add(new DecodeRange(
                range.start,
                range.end,
                range.isa,
                hashMemory(program, monitor, range.start, range.end)));
        }
        return new DecodeProjection(authenticated, Collections.<DecodeError>emptyList());
    }

    /**
     * Streaming BLAKE3 over the current program memory of
     * [start, start + length). Fails when any byte is unreadable.
     */
    static String hashMemory(Program program, TaskMonitor monitor, long start, long end)
            throws Exception {
        checkedRange(start, 0, UINT32_MAX, "memory hash start");
        checkedRange(end, start + 1, UINT32_END, "memory hash end");
        Blake3Digest digest = new Blake3Digest();
        byte[] bytes = new byte[HASH_BUFFER_SIZE];
        Address address = programAddress(program, start);
        long remaining = end - start;
        long offset = 0;
        try {
            while (remaining > 0) {
                if (monitor.isCancelled()) {
                    throw new Exception("the memory hash walk was cancelled");
                }
                int wanted = (int) Math.min(bytes.length, remaining);
                int read = program.getMemory().getBytes(
                    address.addNoWrap(offset), bytes, 0, wanted);
                if (read != wanted) {
                    throw new Exception("the execution range is not fully initialized");
                }
                digest.update(bytes, 0, read);
                offset += read;
                remaining -= read;
            }
        }
        catch (MemoryAccessException error) {
            throw new Exception("the execution range could not be read", error);
        }
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        StringBuilder text = new StringBuilder(output.length * 2);
        for (byte value : output) {
            text.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        }
        return text.toString();
    }

    /** The exclusive u32 end of a function body's address ranges. */
    static long functionEnd(Program program, Function fn) throws Exception {
        long end = checkedRange(fn.getEntryPoint().getOffset(), 0, UINT32_MAX,
                "function entry");
        AddressRangeIterator ranges = fn.getBody().getAddressRanges();
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            checkedRange(range.getMinAddress().getOffset(), 0, UINT32_MAX,
                    "function body start");
            long exclusiveEnd = checkedRange(range.getMaxAddress().getOffset() + 1, 1,
                    UINT32_END, "function body end");
            if (exclusiveEnd > end) {
                end = exclusiveEnd;
            }
        }
        return end;
    }

    /**
     * Computes the domain-separated execution digest for a function's current
     * accepted projection; a quarantined projection fails. Shared by
     * ApplySymbols' body verification and the pass-2 export comparison.
     */
    static String currentExecutionDigest(Program program, TaskMonitor monitor, Function fn)
            throws Exception {
        DecodeProjection projection = decodeProjection(program, monitor, fn);
        if (!projection.errors.isEmpty()) {
            fail("the current decode projection is quarantined at " + fn.getEntryPoint());
        }
        List<ExecutionRangeWire> wire = new ArrayList<ExecutionRangeWire>();
        for (DecodeRange range : projection.ranges) {
            wire.add(new ExecutionRangeWire(range.isa, range.start, range.end, range.blake3));
        }
        return executionDigestHex(
            checkedRange(fn.getEntryPoint().getOffset(), 0, UINT32_MAX, "function entry"), wire);
    }

    static String expectedSymbolPass2Property(SymbolMap map) {
        return "v2:" + map.mapBlake3 + ":" + map.functionsBlake3 + ":"
                + map.executions.size();
    }

    static String thumbCreationOwnershipValue(SymbolMap map, MapCreation creation,
            Function function, TaskMonitor monitor) throws Exception {
        return "v1:" + map.mapBlake3 + ":" + creation.executionBlake3 + ":"
                + function.getID() + ":" + function.getSymbol().getID() + ":"
                + currentExecutionDigest(function.getProgram(), monitor, function);
    }

    static ThumbCreationOwnership parseThumbCreationOwnership(String value) {
        if (value == null) {
            fail("Thumb creation ownership is missing");
        }
        String[] parts = value.split(":", -1);
        if (parts.length != 6 || !"v1".equals(parts[0])) {
            fail("Thumb creation ownership does not have the exact v1 grammar");
        }
        return new ThumbCreationOwnership(
                requireHashText(parts[1], "Thumb creation map BLAKE3"),
                requireHashText(parts[2], "Thumb creation producer execution BLAKE3"),
                requireNonNegative(parts[3], "Thumb creation function ID"),
                requireNonNegative(parts[4], "Thumb creation primary symbol ID"),
                requireHashText(parts[5], "Thumb creation Ghidra execution BLAKE3"));
    }

    static void validateThumbCreationOwnershipIdentity(String value, SymbolMap map,
            MapCreation creation) {
        ThumbCreationOwnership parsed = parseThumbCreationOwnership(value);
        if (!map.mapBlake3.equals(parsed.mapBlake3)
                || !creation.executionBlake3.equals(parsed.producerExecutionBlake3)) {
            fail("the Thumb creation ownership does not bind the current map execution");
        }
    }

    /** Re-authenticate the producer execution against current program memory. */
    static void validateThumbCreationExecution(Program program, TaskMonitor monitor,
            MapCreation creation) throws Exception {
        for (ExecutionRangeWire range : creation.decodeRanges) {
            if (!"thumb".equals(range.isa)) {
                fail("a creation decode range is not Thumb at "
                        + programAddress(program, creation.entry));
            }
            String actual = hashMemory(program, monitor, range.start, range.end);
            if (!range.blake3.equals(actual)) {
                fail("a creation decode range BLAKE3 changed at "
                        + programAddress(program, range.start));
            }
        }
        String actualExecution = executionDigestHex(creation.entry, creation.decodeRanges);
        if (!creation.executionBlake3.equals(actualExecution)) {
            fail("a creation execution digest does not match its authenticated ranges at "
                    + programAddress(program, creation.entry));
        }
    }

    /** Validate one registry-owned creation without trusting its current name. */
    static void validateOwnedThumbCreation(Program program, TaskMonitor monitor,
            StringPropertyMap ownership, SymbolMap map, MapCreation creation) throws Exception {
        Address entry = programAddress(program, creation.entry);
        if (ownership == null) {
            fail("the Thumb creation ownership changed at " + entry);
        }
        ThumbCreationOwnership parsed =
                parseThumbCreationOwnership(ownership.getString(entry));
        if (!map.mapBlake3.equals(parsed.mapBlake3)
                || !creation.executionBlake3.equals(parsed.producerExecutionBlake3)) {
            fail("the Thumb creation ownership changed at " + entry);
        }
        Function function = program.getFunctionManager().getFunctionAt(entry);
        if (function == null || !creation.finalPrimary.equals(function.getName())
                || !creation.finalSource.equals(primarySource(function.getSymbol().getSource()))) {
            fail("the owned Thumb creation changed at " + entry);
        }
        if (function.getID() != parsed.functionId
                || function.getSymbol().getID() != parsed.primarySymbolId) {
            fail("the owned Thumb creation identity changed at " + entry);
        }
        DecodeProjection projection = decodeProjection(program, monitor, function);
        if (!projection.errors.isEmpty()) {
            fail("the owned Thumb creation is quarantined at " + entry);
        }
        boolean entryStartsThumbRange = false;
        for (DecodeRange range : projection.ranges) {
            entryStartsThumbRange |= range.start == creation.entry && "thumb".equals(range.isa);
        }
        if (!entryStartsThumbRange) {
            fail("the owned Thumb creation has no Thumb range at its entry " + entry);
        }
        AddressSet authenticated = new AddressSet();
        for (ExecutionRangeWire range : creation.decodeRanges) {
            authenticated.add(programAddress(program, range.start),
                    programAddress(program, range.end - 1));
        }
        if (!authenticated.contains(function.getBody())) {
            fail("the owned Thumb creation body leaves authenticated memory at " + entry);
        }
        String currentDigest = currentExecutionDigest(program, monitor, function);
        if (!parsed.ghidraExecutionBlake3.equals(currentDigest)) {
            fail("the owned Thumb creation body changed at " + entry);
        }
    }

    private static final Pattern ADDRESS_TEXT = Pattern.compile("^0x[0-9a-f]{8}$");
    private static final Pattern HASH_TEXT = Pattern.compile("^[0-9a-f]{64}$");
    private static final Pattern SAFE_LABEL = Pattern.compile("^[A-Za-z0-9_.-]+$");
    private static final Pattern UNSIGNED_INTEGER = Pattern.compile("^(0|[1-9][0-9]*)$");
    private static final Pattern COLLISION_SUFFIX =
            Pattern.compile("^_pme_[0-9a-f]{8}_[0-9a-f]{8}_[0-9a-f]{8}$");

    private PalTasksSupport() {}

    static final class PalError extends RuntimeException {
        private static final long serialVersionUID = 1L;

        PalError(String message) {
            super(message);
        }
    }

    /** Wall-clock override in milliseconds from the environment; absent,
     * malformed, or non-positive handling follows budgetMsOverride. */
    static long budgetMsOverride(String variable, long fallback) {
        String value = System.getenv(variable);
        if (value == null) {
            return fallback;
        }
        long parsed;
        try {
            parsed = Long.parseLong(value.trim());
        }
        catch (NumberFormatException error) {
            throw new IllegalArgumentException(
                    variable + " is not a whole number of milliseconds: " + value);
        }
        if (parsed <= 0) {
            throw new IllegalArgumentException(variable + " must be positive: " + value);
        }
        return parsed;
    }

    private static void fail(String message) {
        throw new PalError(message);
    }

    private static byte[] ascii(String text) {
        return PmeScriptSupport.ascii(text);
    }

    // -------------------------------------------------------------------------
    // Wire types
    // -------------------------------------------------------------------------

    static final class PalSpan {
        final String kind;
        final long address;
        final long size;
        final Long scatterEntry;

        PalSpan(String kind, long address, long size, Long scatterEntry) {
            this.kind = kind;
            this.address = address;
            this.size = size;
            this.scatterEntry = scatterEntry;
        }

        boolean isZeroFill() {
            return "scatter_zero".equals(kind);
        }
    }

    static final class PalTask {
        final long index;
        final long slot;
        final String slotBlake3;
        final long namePointer;
        final String name;
        final String taskLabel;
        final long priority;
        final long stackSize;
        final long entryPointer;
        final long entry;
        final String isa;
        final long instructionSize;
        final String instructionBlake3;
        final long callback;
        final long unknownPointer;
        final List<PalSpan> slotStorage;
        final List<PalSpan> nameStorage;
        final List<PalSpan> entryStorage;

        PalTask(long index, long slot, String slotBlake3, long namePointer, String name,
                String taskLabel, long priority, long stackSize, long entryPointer, long entry,
                String isa, long instructionSize, String instructionBlake3, long callback,
                long unknownPointer, List<PalSpan> slotStorage, List<PalSpan> nameStorage,
                List<PalSpan> entryStorage) {
            this.index = index;
            this.slot = slot;
            this.slotBlake3 = slotBlake3;
            this.namePointer = namePointer;
            this.name = name;
            this.taskLabel = taskLabel;
            this.priority = priority;
            this.stackSize = stackSize;
            this.entryPointer = entryPointer;
            this.entry = entry;
            this.isa = isa;
            this.instructionSize = instructionSize;
            this.instructionBlake3 = instructionBlake3;
            this.callback = callback;
            this.unknownPointer = unknownPointer;
            this.slotStorage = slotStorage;
            this.nameStorage = nameStorage;
            this.entryStorage = entryStorage;
        }
    }

    static final class PalLabel {
        final String label;
        final List<Long> taskIndices;

        PalLabel(String label, List<Long> taskIndices) {
            this.label = label;
            this.taskIndices = taskIndices;
        }
    }

    static final class PalApplication {
        final long entry;
        final String isa;
        final String desiredPrimary;
        final List<Long> taskIndices;
        final List<PalLabel> labels;

        PalApplication(long entry, String isa, String desiredPrimary, List<Long> taskIndices,
                List<PalLabel> labels) {
            this.entry = entry;
            this.isa = isa;
            this.desiredPrimary = desiredPrimary;
            this.taskIndices = taskIndices;
            this.labels = labels;
        }
    }

    static final class PalManifest {
        final String imageLabel;
        final long imageBase;
        final long imageSize;
        final String imageBlake3;
        final String scatterLoadMapBlake3;
        final long slotBase;
        final long stride;
        final long capacity;
        final List<PalTask> tasks;
        final List<PalApplication> applications;
        final String manifestBlake3;
        final long taskRecords;
        final long distinctEntries;

        PalManifest(String imageLabel, long imageBase, long imageSize, String imageBlake3,
                String scatterLoadMapBlake3, long slotBase, long stride, long capacity,
                List<PalTask> tasks, List<PalApplication> applications, String manifestBlake3,
                long distinctEntries) {
            this.imageLabel = imageLabel;
            this.imageBase = imageBase;
            this.imageSize = imageSize;
            this.imageBlake3 = imageBlake3;
            this.scatterLoadMapBlake3 = scatterLoadMapBlake3;
            this.slotBase = slotBase;
            this.stride = stride;
            this.capacity = capacity;
            this.tasks = tasks;
            this.applications = applications;
            this.manifestBlake3 = manifestBlake3;
            this.taskRecords = tasks.size();
            this.distinctEntries = distinctEntries;
        }
    }

    /** A completely authenticated PAL input set whose exact files remain
     * open until the caller finishes its terminal validation. */
    static final class ValidatedPal implements AutoCloseable {
        final PalManifest manifest;
        final String identity;
        private final PmeScriptSupport.TrustedFile manifestFile;
        private final PmeScriptSupport.TrustedFile scatterFile;
        private final PmeScriptSupport.TrustedFile rawFile;
        private boolean closed;

        ValidatedPal(PalManifest manifest, String identity,
                PmeScriptSupport.TrustedFile manifestFile,
                PmeScriptSupport.TrustedFile scatterFile,
                PmeScriptSupport.TrustedFile rawFile) {
            this.manifest = manifest;
            this.identity = identity;
            this.manifestFile = manifestFile;
            this.scatterFile = scatterFile;
            this.rawFile = rawFile;
        }

        void verifyRetainedFiles() {
            manifestFile.verifyPathIdentity("task manifest");
            if (scatterFile != null) {
                scatterFile.verifyPathIdentity("scatter load map");
            }
            rawFile.verifyPathIdentity("raw image");
        }

        @Override
        public void close() throws Exception {
            if (closed) return;
            closed = true;
            Throwable failure = null;
            failure = closeRetained(rawFile, failure);
            failure = closeRetained(scatterFile, failure);
            failure = closeRetained(manifestFile, failure);
            if (failure != null) rethrow(failure);
        }
    }

    static final class ExecutionRangeWire {
        final String isa;
        final long start;
        final long end;
        final String blake3;

        ExecutionRangeWire(String isa, long start, long end, String blake3) {
            this.isa = isa;
            this.start = start;
            this.end = end;
            this.blake3 = blake3;
        }
    }

    static final class MapExecution {
        final String producer;
        final long entry;
        final String executionBlake3;
        final List<ExecutionRangeWire> decodeRanges;

        MapExecution(String producer, long entry, String executionBlake3,
                List<ExecutionRangeWire> decodeRanges) {
            this.producer = producer;
            this.entry = entry;
            this.executionBlake3 = executionBlake3;
            this.decodeRanges = decodeRanges;
        }
    }

    static final class MapDecision {
        final long execution;
        final String originalPrimary;
        final String originalSource;
        final String finalPrimary;
        final String finalSource;
        final String action;
        final List<String> annotations;
        final String exceptionTransitionAuthority;
        final boolean palTransition;

        MapDecision(long execution, String originalPrimary, String originalSource,
                String finalPrimary, String finalSource, String action, List<String> annotations,
                String exceptionTransitionAuthority, boolean palTransition) {
            this.execution = execution;
            this.originalPrimary = originalPrimary;
            this.originalSource = originalSource;
            this.finalPrimary = finalPrimary;
            this.finalSource = finalSource;
            this.action = action;
            this.annotations = annotations;
            this.exceptionTransitionAuthority = exceptionTransitionAuthority;
            this.palTransition = palTransition;
        }
    }

    /** One named producer-authenticated Thumb entry to create in the Ghidra
     * program during pass 2 (ApplyThumbNames). */
    static final class MapCreation {
        final long entry;
        final String executionBlake3;
        final List<ExecutionRangeWire> decodeRanges;
        final String finalPrimary;
        final String finalSource;

        MapCreation(long entry, String executionBlake3, List<ExecutionRangeWire> decodeRanges,
                String finalPrimary, String finalSource) {
            this.entry = entry;
            this.executionBlake3 = executionBlake3;
            this.decodeRanges = decodeRanges;
            this.finalPrimary = finalPrimary;
            this.finalSource = finalSource;
        }
    }

    static final class ThumbCreationOwnership {
        final String mapBlake3;
        final String producerExecutionBlake3;
        final long functionId;
        final long primarySymbolId;
        final String ghidraExecutionBlake3;

        ThumbCreationOwnership(String mapBlake3, String producerExecutionBlake3,
                long functionId, long primarySymbolId, String ghidraExecutionBlake3) {
            this.mapBlake3 = mapBlake3;
            this.producerExecutionBlake3 = producerExecutionBlake3;
            this.functionId = functionId;
            this.primarySymbolId = primarySymbolId;
            this.ghidraExecutionBlake3 = ghidraExecutionBlake3;
        }
    }

    static final class SymbolMap {
        final String imageLabel;
        final long imageBase;
        final long imageSize;
        final String imageBlake3;
        final String exceptionIdentity;
        final String exceptionManifestBlake3;
        final String palIdentity;
        final String manifestBlake3;
        final String scatterLoadMapBlake3;
        final String functionsBlake3;
        final List<MapExecution> executions;
        final List<MapDecision> decisions;
        final List<MapCreation> creations;
        final String mapBlake3;

        SymbolMap(String imageLabel, long imageBase, long imageSize, String imageBlake3,
                String exceptionIdentity, String exceptionManifestBlake3,
                String palIdentity, String manifestBlake3, String scatterLoadMapBlake3,
                String functionsBlake3, List<MapExecution> executions,
                List<MapDecision> decisions, List<MapCreation> creations, String mapBlake3) {
            this.imageLabel = imageLabel;
            this.imageBase = imageBase;
            this.imageSize = imageSize;
            this.imageBlake3 = imageBlake3;
            this.exceptionIdentity = exceptionIdentity;
            this.exceptionManifestBlake3 = exceptionManifestBlake3;
            this.palIdentity = palIdentity;
            this.manifestBlake3 = manifestBlake3;
            this.scatterLoadMapBlake3 = scatterLoadMapBlake3;
            this.functionsBlake3 = functionsBlake3;
            this.executions = executions;
            this.decisions = decisions;
            this.creations = creations;
            this.mapBlake3 = mapBlake3;
        }
    }

    static final class RegistryEntry {
        final String manifestBlake3;
        final String isa;
        final long functionId;
        final String functionDisposition;
        final String commentBlake3;
        final String primaryDisposition;
        final long primarySymbolId;
        final String primarySource;
        final String primaryNameBlake3;
        final long labelCount;
        final String labelsBlake3;

        RegistryEntry(String manifestBlake3, String isa, long functionId,
                String functionDisposition, String commentBlake3, String primaryDisposition,
                long primarySymbolId, String primarySource, String primaryNameBlake3,
                long labelCount, String labelsBlake3) {
            this.manifestBlake3 = manifestBlake3;
            this.isa = isa;
            this.functionId = functionId;
            this.functionDisposition = functionDisposition;
            this.commentBlake3 = commentBlake3;
            this.primaryDisposition = primaryDisposition;
            this.primarySymbolId = primarySymbolId;
            this.primarySource = primarySource;
            this.primaryNameBlake3 = primaryNameBlake3;
            this.labelCount = labelCount;
            this.labelsBlake3 = labelsBlake3;
        }
    }

    static final class LabelEntry {
        final long symbolId;
        final String leaf;

        LabelEntry(long symbolId, String leaf) {
            this.symbolId = symbolId;
            this.leaf = leaf;
        }
    }

    static final class AppliedState {
        final String identity;
        final int applications;
        final int createdFunctions;
        final int preexistingFunctions;
        final int palOwnedPrimaries;
        final int preservedPrimaries;
        final int pass2OwnedPrimaries;
        final int reservedLabels;

        AppliedState(String identity, int applications, int createdFunctions,
                int preexistingFunctions, int palOwnedPrimaries, int preservedPrimaries,
                int pass2OwnedPrimaries, int reservedLabels) {
            this.identity = identity;
            this.applications = applications;
            this.createdFunctions = createdFunctions;
            this.preexistingFunctions = preexistingFunctions;
            this.palOwnedPrimaries = palOwnedPrimaries;
            this.preservedPrimaries = preservedPrimaries;
            this.pass2OwnedPrimaries = pass2OwnedPrimaries;
            this.reservedLabels = reservedLabels;
        }
    }

    // -------------------------------------------------------------------------
    // Digest grammars
    // -------------------------------------------------------------------------

    static String blake3Hex(byte[] domain, byte[] payload) {
        return PmeScriptSupport.blake3Hex(domain, payload);
    }

    static String executionDigestHex(long entry, List<ExecutionRangeWire> ranges) {
        checkedRange(entry, 0, UINT32_MAX, "execution entry");
        if (ranges.size() > MAX_EXECUTION_RANGES_EACH) {
            fail("execution range count exceeds the per-execution limit");
        }
        Blake3Digest digest = new Blake3Digest();
        digest.update(EXECUTION_DOMAIN, 0, EXECUTION_DOMAIN.length);
        updateLeU32(digest, entry);
        updateLeU32(digest, ranges.size());
        for (ExecutionRangeWire range : ranges) {
            digest.update(isaByte(range.isa));
            updateLeU32(digest, range.start);
            updateLeU32(digest, range.end);
            byte[] rangeDigest = hexToBytes(range.blake3);
            if (rangeDigest.length != 32) {
                fail("execution range digest is not 32 BLAKE3 bytes");
            }
            digest.update(rangeDigest, 0, rangeDigest.length);
        }
        return finishHash(digest);
    }

    static String labelsDigestHex(List<LabelEntry> labels) {
        List<LabelEntry> ordered = new ArrayList<>(labels);
        ordered.sort(Comparator.comparing((LabelEntry entry) -> entry.leaf)
                .thenComparingLong(entry -> entry.symbolId));
        Blake3Digest digest = new Blake3Digest();
        digest.update(LABELS_DOMAIN, 0, LABELS_DOMAIN.length);
        updateLeU32(digest, ordered.size());
        for (LabelEntry label : ordered) {
            updateLeU64(digest, label.symbolId);
            byte[] leaf = asciiLeaf(label.leaf);
            updateLeU32(digest, leaf.length);
            digest.update(leaf, 0, leaf.length);
        }
        return finishHash(digest);
    }

    static String primaryDigestHex(String name) {
        Blake3Digest digest = new Blake3Digest();
        digest.update(PRIMARY_DOMAIN, 0, PRIMARY_DOMAIN.length);
        byte[] encoded = utf8NoSurrogates(name);
        updateLeU32(digest, encoded.length);
        digest.update(encoded, 0, encoded.length);
        return finishHash(digest);
    }

    static String commentDigestHex(String section) {
        Blake3Digest digest = new Blake3Digest();
        digest.update(COMMENT_DOMAIN, 0, COMMENT_DOMAIN.length);
        byte[] encoded = utf8NoSurrogates(section);
        updateLeU32(digest, encoded.length);
        digest.update(encoded, 0, encoded.length);
        return finishHash(digest);
    }

    // -------------------------------------------------------------------------
    // Preservation digests (TameAnalysis datamark)
    // -------------------------------------------------------------------------

    /**
     * Canonical preservation digest over every defined code unit (instructions
     * and defined data — Ghidra's listing iterators synthesize per-byte
     * undefined pseudo-units, which are not units and never enter the digest)
     * in address order: the domain, a little-endian u64 count, then per unit
     * the tag (0x00 instruction / 0x01 data), little-endian u32 address,
     * little-endian u32 byte length, exact bytes, and for data additionally
     * the little-endian u32 UTF-8 data-type-path length plus exact path bytes.
     * Units fully inside {@code exclude} (typically freshly data-marked gap
     * arrays) are skipped entirely, so a rescan over the exclusion set must
     * reproduce the preflight digest byte for byte.
     */
    static String codeUnitsDigestHex(Program program, AddressSetView exclude) throws Exception {
        Blake3Digest digest = new Blake3Digest();
        digest.update(CODE_UNITS_DOMAIN, 0, CODE_UNITS_DOMAIN.length);
        updateLeU64(digest, countDefinedUnits(program, exclude));
        DefinedUnitCursor units = new DefinedUnitCursor(program, exclude);
        while (units.hasNext()) {
            CodeUnit unit = units.next();
            boolean isData = unit instanceof Data;
            digest.update(isData ? (byte) 1 : (byte) 0);
            updateLeU32(digest,
                    checkedRange(unit.getAddress().getOffset(), 0, UINT32_MAX, "unit address"));
            int length = (int) checkedRange(unit.getLength(), 0, Integer.MAX_VALUE,
                    "unit length");
            updateLeU32(digest, length);
            byte[] bytes = new byte[length];
            try {
                if (length > 0 && program.getMemory().getBytes(unit.getAddress(), bytes)
                        != length) {
                    fail("a code unit's bytes could not be read at " + unit.getAddress());
                }
            }
            catch (MemoryAccessException error) {
                fail("a code unit's bytes could not be read at " + unit.getAddress());
            }
            digest.update(bytes, 0, length);
            if (isData) {
                byte[] path =
                        ((Data) unit).getDataType().getPathName().getBytes(StandardCharsets.UTF_8);
                updateLeU32(digest, path.length);
                digest.update(path, 0, path.length);
            }
        }
        return finishHash(digest);
    }

    /**
     * Canonical preservation digest over every function in entry-point order:
     * the domain, a little-endian u64 count, then per function the
     * non-negative ID as a little-endian u64, the entry as a u32, the body
     * range count as a u32, and each body range's start / exclusive-end u32
     * pair. Bodies must stay inside the 32-bit address domain.
     */
    static String functionBodiesDigestHex(Program program) throws Exception {
        FunctionIterator count = program.getFunctionManager().getFunctions(true);
        long functions = 0;
        while (count.hasNext()) {
            count.next();
            if (++functions > MAX_FUNCTIONS) {
                fail("the program exceeds the 262,144 function digest limit");
            }
        }
        Blake3Digest digest = new Blake3Digest();
        digest.update(FUNCTION_BODIES_DOMAIN, 0, FUNCTION_BODIES_DOMAIN.length);
        updateLeU64(digest, functions);
        FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            long id = function.getID();
            if (id < 0) {
                fail("a function carries a negative ID");
            }
            updateLeU64(digest, id);
            updateLeU32(digest, checkedRange(function.getEntryPoint().getOffset(), 0, UINT32_MAX,
                    "function entry"));
            AddressSetView body = function.getBody();
            long ranges = 0;
            for (AddressRange range : body) {
                if (++ranges > UINT32_MAX) {
                    fail("a function body carries too many ranges");
                }
            }
            updateLeU32(digest, ranges);
            for (AddressRange range : body) {
                long end = range.getMaxAddress().getOffset() + 1;
                if (range.getMinAddress().getOffset() < 0
                        || range.getMinAddress().getOffset() > UINT32_MAX
                        || end > UINT32_MAX) {
                    fail("a function body range leaves the 32-bit address domain");
                }
                updateLeU32(digest, range.getMinAddress().getOffset());
                updateLeU32(digest, end);
            }
        }
        return finishHash(digest);
    }

    /**
     * Streaming BLAKE3 over the raw memory bytes of [start, start + length).
     * TameAnalysis hashes each planned undefined gap before mutation and must
     * reproduce the exact hash after the gap is covered by byte arrays (array
     * creation never rewrites memory bytes).
     */
    static String memoryDigestHex(Program program, long start, long length) {
        checkedRange(start, 0, UINT32_MAX, "memory digest start");
        checkedRange(length, 1, UINT32_MAX, "memory digest length");
        Blake3Digest digest = new Blake3Digest();
        byte[] buffer = new byte[HASH_BUFFER_SIZE];
        Address cursor = programAddress(program, start);
        long remaining = length;
        try {
            while (remaining > 0) {
                int wanted = (int) Math.min(buffer.length, remaining);
                int read = program.getMemory().getBytes(cursor, buffer, 0, wanted);
                if (read != wanted) {
                    fail("the gap bytes could not be read at " + cursor);
                }
                digest.update(buffer, 0, read);
                remaining -= read;
                if (remaining > 0) {
                    cursor = cursor.add(read);
                }
            }
        }
        catch (MemoryAccessException | AddressOutOfBoundsException error) {
            fail("the gap bytes could not be read at " + cursor);
        }
        return finishHash(digest);
    }

    private static long countDefinedUnits(Program program, AddressSetView exclude) {
        long count = 0;
        DefinedUnitCursor units = new DefinedUnitCursor(program, exclude);
        while (units.hasNext()) {
            units.next();
            if (++count > MAX_CODE_UNITS) {
                fail("the program exceeds the 4,194,304 code-unit digest limit");
            }
        }
        return count;
    }

    /**
     * Merges the listing's instructions and defined-data iterators into one
     * address-ordered stream of defined units, skipping units fully inside
     * the exclusion set.
     */
    private static final class DefinedUnitCursor {
        private final InstructionIterator instructions;
        private final DataIterator dataUnits;
        private final AddressSetView exclude;
        private Instruction nextInstruction;
        private Data nextData;

        DefinedUnitCursor(Program program, AddressSetView exclude) {
            this.instructions = program.getListing().getInstructions(true);
            this.dataUnits = program.getListing().getDefinedData(true);
            this.exclude = exclude;
            advanceInstruction();
            advanceData();
        }

        private void advanceInstruction() {
            nextInstruction = null;
            while (instructions.hasNext()) {
                Instruction candidate = instructions.next();
                if (!excluded(candidate)) {
                    nextInstruction = candidate;
                    return;
                }
            }
        }

        private void advanceData() {
            nextData = null;
            while (dataUnits.hasNext()) {
                Data candidate = dataUnits.next();
                if (!excluded(candidate)) {
                    nextData = candidate;
                    return;
                }
            }
        }

        private boolean excluded(CodeUnit unit) {
            return exclude != null && exclude.contains(unit.getMinAddress(), unit.getMaxAddress());
        }

        boolean hasNext() {
            return nextInstruction != null || nextData != null;
        }

        CodeUnit next() {
            if (nextInstruction == null) {
                Data data = nextData;
                advanceData();
                return data;
            }
            if (nextData == null) {
                Instruction instruction = nextInstruction;
                advanceInstruction();
                return instruction;
            }
            if (nextInstruction.getAddress().compareTo(nextData.getAddress()) <= 0) {
                Instruction instruction = nextInstruction;
                advanceInstruction();
                return instruction;
            }
            Data data = nextData;
            advanceData();
            return data;
        }
    }

    private static byte isaByte(String isa) {
        if ("arm".equals(isa)) {
            return 0;
        }
        if ("thumb".equals(isa)) {
            return 1;
        }
        fail("unknown ISA " + isa);
        return -1;
    }

    private static byte[] asciiLeaf(String leaf) {
        byte[] encoded = new byte[leaf.length()];
        for (int index = 0; index < leaf.length(); index++) {
            char character = leaf.charAt(index);
            if (character < 0x20 || character > 0x7e) {
                fail("label leaf contains a non-ASCII byte");
            }
            encoded[index] = (byte) character;
        }
        return encoded;
    }

    private static byte[] utf8NoSurrogates(String value) {
        return utf8NoSurrogates(value, "string");
    }

    private static byte[] utf8NoSurrogates(String value, String what) {
        if (value == null) {
            fail(what + " is missing");
        }
        for (int index = 0; index < value.length(); index++) {
            if (Character.isSurrogate(value.charAt(index))) {
                fail(what + " contains a surrogate code unit");
            }
        }
        try {
            return PmeScriptSupport.boundedUtf8(value, Integer.MAX_VALUE, what);
        }
        catch (PmeScriptSupport.SupportError error) {
            fail(error.getMessage());
            return null;
        }
    }

    private static void updateLeU32(Blake3Digest digest, long value) {
        byte[] encoded = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
                .putInt((int) checkedRange(value, 0, UINT32_MAX, "u32")).array();
        digest.update(encoded, 0, encoded.length);
    }

    private static void updateLeU64(Blake3Digest digest, long value) {
        byte[] encoded =
                ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array();
        digest.update(encoded, 0, encoded.length);
    }

    private static String finishHash(Blake3Digest digest) {
        return PmeScriptSupport.finishHash(digest);
    }

    private static byte[] hexToBytes(String text) {
        try {
            return PmeScriptSupport.hexToBytes(text, "hex string");
        }
        catch (PmeScriptSupport.SupportError error) {
            fail(error.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Task-name sanitization (identical to the Rust allocator rule)
    // -------------------------------------------------------------------------

    static String sanitizeTaskName(String name) {
        StringBuilder out = new StringBuilder();
        boolean pendingUnderscore = false;
        for (int index = 0; index < name.length(); index++) {
            char character = name.charAt(index);
            if ((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
                    || (character >= '0' && character <= '9') || character == '_') {
                if (pendingUnderscore) {
                    out.append('_');
                    pendingUnderscore = false;
                }
                out.append(character);
            }
            else {
                pendingUnderscore = true;
            }
        }
        if (pendingUnderscore) {
            out.append('_');
        }
        if (out.length() == 0) {
            return null;
        }
        if (out.charAt(0) >= '0' && out.charAt(0) <= '9') {
            out.insert(0, '_');
        }
        return out.toString();
    }

    // -------------------------------------------------------------------------
    // PAL manifest reader
    // -------------------------------------------------------------------------

    static ValidatedPal retainPal(File kitRoot, String label, File palFile, File scatterFile)
            throws Exception {
        assertGhidraSymbolLimit();
        File root = requireCanonicalDirectory(kitRoot, "import-kit root");
        if (!isSafeLabel(label)) {
            fail("expected image label is not a safe path component");
        }
        PmeScriptSupport.TrustedFile retainedManifest = null;
        PmeScriptSupport.TrustedFile retainedScatter = null;
        PmeScriptSupport.TrustedFile retainedRaw = null;
        try {
            byte[] bytes;
            String manifestBlake3;
            try {
                retainedManifest = PmeScriptSupport.openCanonicalContainedFile(
                        root, palFile, "task manifest");
                bytes = retainedManifest.readAll(MAX_PAL_MANIFEST_BYTES, "task manifest");
                manifestBlake3 = PmeScriptSupport.blake3Hex(bytes);
            }
            catch (IOException error) {
                throw new Exception(
                        "task manifest could not be read: " + error.getMessage(), error);
            }

            PalManifest manifest = parsePalManifest(bytes, label, manifestBlake3);
            if (manifest.scatterLoadMapBlake3 == null && scatterFile != null) {
                fail("scatter dependency nullability does not match the supplied load map");
            }
            if (manifest.scatterLoadMapBlake3 != null) {
                if (scatterFile == null) {
                    fail("scatter dependency nullability does not match the supplied load map");
                }
                retainedScatter = PmeScriptSupport.openCanonicalContainedFile(
                        root, scatterFile, "scatter load map");
                if (!manifest.scatterLoadMapBlake3.equals(
                        retainedScatter.blake3("scatter load map"))) {
                    fail("scatter load-map BLAKE3 does not match the manifest dependency");
                }
            }

            retainedRaw = PmeScriptSupport.openContainedChild(
                    root, "images/" + label, "raw image");
            if (retainedRaw.size() != manifest.imageSize) {
                fail("raw image size does not match the manifest");
            }
            if (!manifest.imageBlake3.equals(retainedRaw.blake3("raw image"))) {
                fail("image BLAKE3 does not match the raw image file");
            }
            ValidatedPal validated = new ValidatedPal(manifest, expectedPalIdentity(manifest),
                    retainedManifest, retainedScatter, retainedRaw);
            validated.verifyRetainedFiles();
            retainedManifest = null;
            retainedScatter = null;
            retainedRaw = null;
            return validated;
        }
        catch (Throwable error) {
            closeQuietly(retainedRaw, error);
            closeQuietly(retainedScatter, error);
            closeQuietly(retainedManifest, error);
            rethrow(error);
            return null;
        }
    }

    static PalManifest readPal(File kitRoot, String label, File palFile, File scatterFile)
            throws Exception {
        try (ValidatedPal retained = retainPal(kitRoot, label, palFile, scatterFile)) {
            return retained.manifest;
        }
    }

    static String expectedPalIdentity(PalManifest manifest) {
        return IDENTITY_VERSION + ":" + manifest.manifestBlake3 + ":" + manifest.taskRecords + ":"
                + manifest.distinctEntries;
    }

    // -------------------------------------------------------------------------
    // Ownership registry
    // -------------------------------------------------------------------------

    static String registryValue(RegistryEntry entry) {
        StringBuilder value = new StringBuilder();
        value.append(IDENTITY_VERSION).append(':');
        value.append(entry.manifestBlake3).append(':');
        value.append(entry.isa).append(':');
        value.append(entry.functionId).append(':');
        value.append(entry.functionDisposition).append(':');
        value.append(entry.commentBlake3).append(':');
        value.append(entry.primaryDisposition).append(':');
        value.append(entry.primarySymbolId).append(':');
        value.append(entry.primarySource).append(':');
        value.append(entry.primaryNameBlake3).append(':');
        value.append(entry.labelCount).append(':');
        value.append(entry.labelsBlake3);
        return value.toString();
    }

    static RegistryEntry parseRegistry(String value) {
        if (value == null) {
            fail("registry value is missing");
        }
        String[] parts = value.split(":", -1);
        if (parts.length != 12) {
            fail("registry value does not have the exact v1 field count");
        }
        if (!IDENTITY_VERSION.equals(parts[0])) {
            fail("registry value is not the v1 grammar");
        }
        String manifestBlake3 = requireHashText(parts[1], "registry manifest BLAKE3");
        String isa = requireIsa(parts[2]);
        long functionId = requireNonNegative(parts[3], "registry function ID");
        if (!"created".equals(parts[4]) && !"preexisting".equals(parts[4])) {
            fail("registry function disposition is not created or preexisting");
        }
        String commentBlake3 = requireHashText(parts[5], "registry comment BLAKE3");
        if (!"pal_owned".equals(parts[6]) && !"preserved".equals(parts[6])
                && !"pass2_owned".equals(parts[6])) {
            fail("registry primary disposition is not pal_owned, preserved, or pass2_owned");
        }
        long primarySymbolId = requireNonNegative(parts[7], "registry primary symbol ID");
        if (!"analysis".equals(parts[8]) && !"imported".equals(parts[8])
                && !"user_defined".equals(parts[8])) {
            fail("registry primary source is not analysis, imported, or user_defined");
        }
        String primaryNameBlake3 = requireHashText(parts[9], "registry primary-name BLAKE3");
        long labelCount = requireNonNegative(parts[10], "registry label count");
        String labelsBlake3 = requireHashText(parts[11], "registry labels BLAKE3");
        return new RegistryEntry(manifestBlake3, isa, functionId, parts[4], commentBlake3,
                parts[6], primarySymbolId, parts[8], primaryNameBlake3, labelCount, labelsBlake3);
    }

    static String primarySource(SourceType source) {
        if (source == SourceType.AI) {
            fail("unknown primary source " + source);
        }
        try {
            return PmeScriptSupport.primarySource(source);
        }
        catch (PmeScriptSupport.SupportError error) {
            fail(error.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Owned repeatable-comment section
    // -------------------------------------------------------------------------

    static String ownedCommentSection(String manifestBlake3, List<PalTask> tasks) {
        requireHashText(manifestBlake3, "owned comment manifest BLAKE3");
        List<PalTask> ordered = new ArrayList<>(tasks);
        ordered.sort(Comparator.comparingLong(task -> task.index));
        StringBuilder section = new StringBuilder();
        section.append(COMMENT_OPEN_MARKER).append('\n');
        section.append("manifest=").append(manifestBlake3).append(" tasks=")
                .append(ordered.size()).append('\n');
        for (PalTask task : ordered) {
            section.append("task index=").append(task.index).append(" name=")
                    .append(jsonString(task.name)).append(" slot=")
                    .append(String.format(Locale.ROOT, "0x%08x", task.slot))
                    .append(" priority=").append(task.priority).append(" stack=")
                    .append(task.stackSize).append('\n');
        }
        section.append(COMMENT_CLOSE_MARKER);
        return section.toString();
    }

    static String findOwnedSection(String repeatableComment) {
        if (repeatableComment == null) {
            return null;
        }
        int open = repeatableComment.indexOf(COMMENT_OPEN_MARKER);
        if (open < 0) {
            return null;
        }
        if (repeatableComment.indexOf(COMMENT_OPEN_MARKER, open + 1) >= 0) {
            fail("owned comment section has duplicate opening markers");
        }
        int close = repeatableComment.lastIndexOf(COMMENT_CLOSE_MARKER);
        if (close < open) {
            fail("owned comment section is unterminated");
        }
        if (repeatableComment.indexOf(COMMENT_CLOSE_MARKER,
                close + COMMENT_CLOSE_MARKER.length()) >= 0) {
            fail("owned comment section has duplicate closing markers");
        }
        return repeatableComment.substring(open, close + COMMENT_CLOSE_MARKER.length());
    }

    private static String jsonString(String value) {
        try {
            return PmeScriptSupport.jsonString(value);
        }
        catch (PmeScriptSupport.SupportError error) {
            fail(error.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Applied-state validation
    // -------------------------------------------------------------------------

    static AppliedState validateApplied(Program program, PalManifest manifest,
            String expectedIdentity) throws Exception {
        assertGhidraSymbolLimit();
        String identity = expectedPalIdentity(manifest);
        if (!identity.equals(expectedIdentity)) {
            fail("expected identity does not match the manifest");
        }
        requirePalProperty(program, identity);

        FunctionManager functions = program.getFunctionManager();
        StringPropertyMap registry = ownershipMap(program);

        Map<Address, List<Symbol>> reserved = reservedSymbolsByAddress(program);
        List<Address> commentAddresses = ownedCommentAddresses(program);
        Set<Address> registered = registryAddresses(registry);

        int created = 0;
        int preexisting = 0;
        int palOwned = 0;
        int preserved = 0;
        int pass2Owned = 0;
        int reservedLabels = 0;

        for (PalApplication application : manifest.applications) {
            Address entry = programAddress(program, application.entry);
            Function function = functions.getFunctionAt(entry);
            if (function == null) {
                fail("a task application has no function at its entry " + entry);
            }
            requireEntryIsa(program, entry, application.isa);
            RegistryEntry parsed = parseRegistry(registry.getString(entry));
            if (!parsed.manifestBlake3.equals(manifest.manifestBlake3)) {
                fail("registry entry binds a different manifest");
            }
            if (!parsed.isa.equals(application.isa)) {
                fail("registry entry ISA does not match the application");
            }
            Symbol primary = function.getSymbol();
            if (parsed.functionId != primary.getID()) {
                fail("registry entry does not bind the current function ID");
            }
            if ("created".equals(parsed.functionDisposition)) {
                created++;
            }
            else {
                preexisting++;
            }
            if (parsed.primarySymbolId != primary.getID()
                    || !parsed.primarySource.equals(primarySource(primary.getSource()))
                    || !parsed.primaryNameBlake3.equals(primaryDigestHex(primary.getName()))) {
                fail("primary symbol binding does not match the registry");
            }
            switch (parsed.primaryDisposition) {
                case "pal_owned":
                    palOwned++;
                    if (!primary.getName().equals(application.desiredPrimary)) {
                        fail("a pal_owned primary no longer carries the desired task name");
                    }
                    break;
                case "preserved":
                    preserved++;
                    break;
                case "pass2_owned":
                    pass2Owned++;
                    break;
                default:
                    fail("registry primary disposition is unknown");
            }

            List<Symbol> labels = reserved.containsKey(entry) ? reserved.get(entry) : List.of();
            List<LabelEntry> digestInput = new ArrayList<>();
            for (Symbol label : labels) {
                if (label.getSource() != SourceType.ANALYSIS) {
                    fail("a reserved label does not carry ANALYSIS source");
                }
                digestInput.add(new LabelEntry(label.getID(), label.getName()));
            }
            if (parsed.labelCount != digestInput.size()
                    || !parsed.labelsBlake3.equals(labelsDigestHex(digestInput))) {
                fail("the reserved label set does not match the registry");
            }
            Set<String> actualLeaves = new HashSet<>();
            for (Symbol label : labels) {
                actualLeaves.add(label.getName());
            }
            Set<String> expectedLeaves = new HashSet<>();
            for (PalLabel label : application.labels) {
                expectedLeaves.add(label.label);
            }
            if (!actualLeaves.equals(expectedLeaves)) {
                fail("the reserved label set does not match the serialized application");
            }

            String section = findOwnedSection(function.getRepeatableComment());
            if (section == null) {
                fail("an owned comment section is missing from a task function");
            }
            if (!parsed.commentBlake3.equals(commentDigestHex(section))) {
                fail("the owned comment digest does not match the registry");
            }
            List<PalTask> attached = new ArrayList<>();
            for (long index : application.taskIndices) {
                attached.add(manifest.tasks.get((int) index));
            }
            if (!section.equals(ownedCommentSection(manifest.manifestBlake3, attached))) {
                fail("the owned comment section does not match the manifest tasks");
            }
            reservedLabels += digestInput.size();
        }

        Set<Address> applicationAddresses = new HashSet<>();
        for (PalApplication application : manifest.applications) {
            applicationAddresses.add(programAddress(program, application.entry));
        }
        if (!registered.equals(applicationAddresses)) {
            fail("the ownership registry is not the exact application bijection");
        }
        if (!new HashSet<>(commentAddresses).equals(applicationAddresses)) {
            fail("owned comments exist outside the application set");
        }
        Set<Address> reservedAddresses = new HashSet<>();
        for (Map.Entry<Address, List<Symbol>> entry : reserved.entrySet()) {
            if (!entry.getValue().isEmpty()) {
                reservedAddresses.add(entry.getKey());
            }
        }
        if (!reservedAddresses.equals(applicationAddresses)) {
            fail("an unregistered reserved label is stale state");
        }

        return new AppliedState(identity, manifest.applications.size(), created, preexisting,
                palOwned, preserved, pass2Owned, reservedLabels);
    }

    static AppliedState validateAppliedIdentity(Program program, String expectedIdentity)
            throws Exception {
        assertGhidraSymbolLimit();
        String[] identity = parsePalIdentity(expectedIdentity);
        requirePalProperty(program, expectedIdentity);

        FunctionManager functions = program.getFunctionManager();
        StringPropertyMap registry = ownershipMap(program);
        Map<Address, List<Symbol>> reserved = reservedSymbolsByAddress(program);
        List<Address> commentAddresses = ownedCommentAddresses(program);

        Set<Address> registered = registryAddresses(registry);
        int created = 0;
        int preexisting = 0;
        int palOwned = 0;
        int preserved = 0;
        int pass2Owned = 0;
        int reservedLabels = 0;
        for (Address entry : registered) {
            RegistryEntry parsed = parseRegistry(registry.getString(entry));
            if (!parsed.manifestBlake3.equals(identity[1])) {
                fail("registry entry binds a different manifest than the identity");
            }
            Function function = functions.getFunctionAt(entry);
            if (function == null) {
                fail("a registry entry has no function at its address " + entry);
            }
            requireEntryIsa(program, entry, parsed.isa);
            Symbol primary = function.getSymbol();
            if (parsed.functionId != primary.getID()
                    || parsed.primarySymbolId != primary.getID()
                    || !parsed.primarySource.equals(primarySource(primary.getSource()))
                    || !parsed.primaryNameBlake3.equals(primaryDigestHex(primary.getName()))) {
                fail("primary symbol binding does not match the registry");
            }
            if ("created".equals(parsed.functionDisposition)) {
                created++;
            }
            else if ("preexisting".equals(parsed.functionDisposition)) {
                preexisting++;
            }
            else {
                fail("registry function disposition is unknown");
            }
            switch (parsed.primaryDisposition) {
                case "pal_owned": palOwned++; break;
                case "preserved": preserved++; break;
                case "pass2_owned": pass2Owned++; break;
                default: fail("registry primary disposition is unknown");
            }
            List<Symbol> labels = reserved.containsKey(entry) ? reserved.get(entry) : List.of();
            List<LabelEntry> digestInput = new ArrayList<>();
            for (Symbol label : labels) {
                if (label.getSource() != SourceType.ANALYSIS) {
                    fail("a reserved label does not carry ANALYSIS source");
                }
                digestInput.add(new LabelEntry(label.getID(), label.getName()));
            }
            if (parsed.labelCount != digestInput.size()
                    || !parsed.labelsBlake3.equals(labelsDigestHex(digestInput))) {
                fail("the reserved label set does not match the registry");
            }
            reservedLabels += digestInput.size();
            String section = findOwnedSection(function.getRepeatableComment());
            if (section == null) {
                fail("an owned comment section is missing from a registered function");
            }
            if (!parsed.commentBlake3.equals(commentDigestHex(section))) {
                fail("the owned comment digest does not match the registry");
            }
        }
        if (registered.isEmpty()) {
            fail("a present PAL identity requires a non-empty ownership registry");
        }

        if (!new HashSet<>(commentAddresses).equals(registered)) {
            fail("owned comments exist outside the registry");
        }
        for (Map.Entry<Address, List<Symbol>> entry : reserved.entrySet()) {
            if (!entry.getValue().isEmpty() && !registered.contains(entry.getKey())) {
                fail("an unregistered reserved label is stale state");
            }
        }
        return new AppliedState(expectedIdentity, registered.size(), created, preexisting,
                palOwned, preserved, pass2Owned, reservedLabels);
    }

    static void validateAbsent(Program program) throws Exception {
        assertGhidraSymbolLimit();
        String property = program.getOptions(Program.PROGRAM_INFO).getString(PAL_PROPERTY, null);
        if (property != null && !NONE_IDENTITY.equals(property)) {
            fail("the PAL property is not absent or none");
        }
        StringPropertyMap registry = program.getUsrPropertyManager()
                .getStringPropertyMap(OWNERSHIP_MAP);
        if (registry != null && registry.getSize() > 0) {
            fail("the ownership registry is not empty");
        }
        Namespace namespace = program.getSymbolTable().getNamespace(RESERVED_NAMESPACE,
                program.getGlobalNamespace());
        if (namespace != null) {
            SymbolIterator symbols = program.getSymbolTable().getSymbols(namespace);
            while (symbols.hasNext()) {
                fail("the reserved namespace is not empty");
            }
        }
        if (!ownedCommentAddresses(program).isEmpty()) {
            fail("an owned comment marker survives");
        }
    }

    private static void requirePalProperty(Program program, String identity) {
        String property = program.getOptions(Program.PROGRAM_INFO).getString(PAL_PROPERTY, null);
        if (property == null || !property.equals(identity)) {
            fail("stale PAL property: expected " + identity + " but found " + property);
        }
    }

    private static String[] parsePalIdentity(String identity) {
        if (identity == null) {
            fail("PAL identity is missing");
        }
        String[] parts = identity.split(":", -1);
        if (parts.length != 4 || !IDENTITY_VERSION.equals(parts[0])) {
            fail("PAL identity is not the v1 grammar");
        }
        requireHashText(parts[1], "PAL identity manifest BLAKE3");
        requireNonNegative(parts[2], "PAL identity task records");
        requireNonNegative(parts[3], "PAL identity distinct entries");
        return parts;
    }

    private static String[] parseExceptionIdentity(String identity) {
        if (identity == null) {
            fail("exception identity is missing");
        }
        String[] parts = identity.split(":", -1);
        if (parts.length != 4 || !IDENTITY_VERSION.equals(parts[0])) {
            fail("exception identity is not the v1 grammar");
        }
        requireHashText(parts[1], "exception identity manifest BLAKE3");
        long tables = requireNonNegative(parts[2], "exception identity table count");
        long roots = requireNonNegative(parts[3], "exception identity root count");
        if (tables < 1 || tables > 2 || roots < 1 || roots > 16) {
            fail("exception identity counts leave the closed bounds");
        }
        return parts;
    }

    private static StringPropertyMap ownershipMap(Program program) {
        StringPropertyMap map =
                program.getUsrPropertyManager().getStringPropertyMap(OWNERSHIP_MAP);
        if (map == null) {
            fail("the ownership registry is missing");
        }
        return map;
    }

    private static Set<Address> registryAddresses(StringPropertyMap registry) {
        Set<Address> addresses = new HashSet<>();
        AddressIterator properties = registry.getPropertyIterator();
        while (properties.hasNext()) {
            if (!addresses.add(properties.next())) {
                fail("the ownership registry carries a duplicate entry");
            }
        }
        return addresses;
    }

    private static Map<Address, List<Symbol>> reservedSymbolsByAddress(Program program) {
        Map<Address, List<Symbol>> byAddress = new HashMap<>();
        Namespace namespace = program.getSymbolTable().getNamespace(RESERVED_NAMESPACE,
                program.getGlobalNamespace());
        if (namespace == null) {
            return byAddress;
        }
        SymbolIterator symbols = program.getSymbolTable().getSymbols(namespace);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            byAddress.computeIfAbsent(symbol.getAddress(), unused -> new ArrayList<>())
                    .add(symbol);
        }
        return byAddress;
    }

    private static List<Address> ownedCommentAddresses(Program program) {
        List<Address> addresses = new ArrayList<>();
        AddressIterator iterator = program.getListing()
                .getCommentAddressIterator(CommentType.REPEATABLE, program.getMemory(), true);
        while (iterator.hasNext()) {
            Address address = iterator.next();
            CodeUnit unit = program.getListing().getCodeUnitContaining(address);
            String comment = unit == null ? null : unit.getComment(CommentType.REPEATABLE);
            if (comment != null && comment.contains(COMMENT_OPEN_MARKER)) {
                addresses.add(address);
            }
        }
        return addresses;
    }

    private static void requireEntryIsa(Program program, Address entry, String isa) {
        Instruction instruction = program.getListing().getInstructionAt(entry);
        if (instruction == null) {
            fail("no instruction exists at the task entry " + entry);
        }
        Register tMode = program.getLanguage().getRegister("TMode");
        RegisterValue value = tMode == null ? null : instruction.getRegisterValue(tMode);
        BigInteger mode = value == null || !value.hasValue() ? null : value.getUnsignedValue();
        BigInteger expected = "thumb".equals(isa) ? BigInteger.ONE : BigInteger.ZERO;
        if (mode == null || !mode.equals(expected)) {
            fail("the entry ISA context does not match the declared " + isa);
        }
    }

    static Address programAddress(Program program, long value) {
        try {
            return PmeScriptSupport.programAddress(program, value);
        }
        catch (PmeScriptSupport.SupportError error) {
            fail(error.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Strict symbol-map v4 reader
    // -------------------------------------------------------------------------

    static SymbolMap readSymbolMap(File retainedFunctions, String functionsHash, File map,
            String mapHash) throws Exception {
        assertGhidraSymbolLimit();
        requireHashText(functionsHash, "expected functions.json BLAKE3");
        requireHashText(mapHash, "expected symbol map BLAKE3");
        SymbolMap parsed;
        try (PmeScriptSupport.TrustedFile mapFile =
                        PmeScriptSupport.openCanonicalFile(map, "symbol map");
                PmeScriptSupport.TrustedFile functionsFile =
                        PmeScriptSupport.openCanonicalFile(
                                retainedFunctions, "retained pass-1 functions.json")) {
            if (mapFile.size() > MAX_SYMBOL_MAP_BYTES) {
                fail("symbol map exceeds the 256 MiB ceiling");
            }
            String actualMapHash = mapFile.blake3("symbol map");
            if (!actualMapHash.equals(mapHash)) {
                fail("symbol map BLAKE3 does not match the expected value");
            }
            parsed = parseSymbolMap(mapFile.utf8Reader(), actualMapHash);
            if (!functionsHash.equals(functionsFile.blake3(
                    "retained pass-1 functions.json"))) {
                fail("functions.json BLAKE3 does not match the retained file");
            }
            mapFile.verifyPathIdentity("symbol map");
            functionsFile.verifyPathIdentity("retained pass-1 functions.json");
        }
        catch (IOException error) {
            throw new Exception("symbol map could not be read: " + error.getMessage(), error);
        }
        if (!parsed.functionsBlake3.equals(functionsHash)) {
            fail("functions.json BLAKE3 does not match the map dependency");
        }
        return parsed;
    }

    /**
     * The export-side map read: the map file itself is hashed from one
     * retained handle and strictly parsed. The retained pass-1
     * functions.json binding is not re-read here — ApplySymbols owns that
     * check, and the pass-2 export pins the map's own functions digest
     * through the exact SymbolPass2 property instead.
     */
    static SymbolMap readSymbolMapForExport(File map, String mapHash) throws Exception {
        assertGhidraSymbolLimit();
        requireHashText(mapHash, "expected symbol map BLAKE3");
        try (PmeScriptSupport.TrustedFile mapFile =
                PmeScriptSupport.openCanonicalFile(map, "symbol map")) {
            if (mapFile.size() > MAX_SYMBOL_MAP_BYTES) {
                fail("symbol map exceeds the 256 MiB ceiling");
            }
            String actualMapHash = mapFile.blake3("symbol map");
            if (!actualMapHash.equals(mapHash)) {
                fail("symbol map BLAKE3 does not match the expected value");
            }
            SymbolMap parsed = parseSymbolMap(mapFile.utf8Reader(), actualMapHash);
            mapFile.verifyPathIdentity("symbol map");
            return parsed;
        }
        catch (IOException error) {
            throw new Exception("symbol map could not be read: " + error.getMessage(), error);
        }
    }

    // -------------------------------------------------------------------------
    // Strict JSON cursor helpers
    // -------------------------------------------------------------------------

    private static void name(JsonReader reader, String expected)
            throws IOException {
        if (reader.peek() != JsonToken.NAME) {
            fail("expected key '" + expected + "' but the object ended early");
        }
        String found;
        try {
            found = reader.nextName();
        }
        catch (IOException | IllegalStateException error) {
            fail("expected key '" + expected + "' but could not be read: " + error.getMessage());
            return;
        }
        if (!found.equals(expected)) {
            fail("expected key '" + expected + "' but found '" + found + "'");
        }
    }

    private static void endObject(JsonReader reader, String lastExpected) throws IOException {
        try {
            if (reader.hasNext()) {
                fail("expected the last key '" + lastExpected + "' but found '"
                        + reader.nextName() + "'");
            }
            reader.endObject();
        }
        catch (IOException | IllegalStateException error) {
            fail("strict JSON object could not be closed: " + error.getMessage());
        }
    }

    private static boolean optionalName(JsonReader reader, String expected) throws IOException {
        try {
            if (!reader.hasNext()) {
                return false;
            }
            String found = reader.nextName();
            if (!found.equals(expected)) {
                fail("expected the optional key '" + expected + "' but found '" + found + "'");
            }
            return true;
        }
        catch (IOException | IllegalStateException error) {
            fail("optional key '" + expected + "' could not be read: " + error.getMessage());
            return false;
        }
    }

    private static void beginArray(JsonReader reader, String what) throws IOException {
        if (reader.peek() != JsonToken.BEGIN_ARRAY) {
            fail(what + " is not an array");
        }
        try {
            reader.beginArray();
        }
        catch (IOException | IllegalStateException error) {
            fail(what + " could not be opened: " + error.getMessage());
        }
    }

    private static void endArray(JsonReader reader, String what) throws IOException {
        if (reader.peek() != JsonToken.END_ARRAY) {
            fail(what + " has trailing content");
        }
        try {
            reader.endArray();
        }
        catch (IOException | IllegalStateException error) {
            fail(what + " could not be closed: " + error.getMessage());
        }
    }

    private static boolean arrayHasNext(JsonReader reader) throws IOException {
        return reader.peek() != JsonToken.END_ARRAY;
    }

    private static String stringValue(JsonReader reader, String what) throws IOException {
        if (reader.peek() != JsonToken.STRING) {
            fail(what + " is not a string");
        }
        try {
            String value = reader.nextString();
            for (int index = 0; index < value.length(); index++) {
                char character = value.charAt(index);
                if (character < 0x20 || character > 0x7e) {
                    fail(what + " contains a non-canonical byte");
                }
            }
            return value;
        }
        catch (IOException | IllegalStateException error) {
            fail(what + " could not be read: " + error.getMessage());
            return null;
        }
    }

    private static long unsignedValue(JsonReader reader, long maximum, String what)
            throws IOException {
        if (reader.peek() != JsonToken.NUMBER) {
            fail(what + " is not a canonical unsigned decimal");
        }
        String text;
        try {
            text = reader.nextString();
        }
        catch (IOException | IllegalStateException error) {
            fail(what + " could not be read: " + error.getMessage());
            return 0;
        }
        if (!UNSIGNED_INTEGER.matcher(text).matches()) {
            fail(what + " is not a canonical unsigned decimal");
        }
        long value;
        try {
            value = Long.parseLong(text);
        }
        catch (NumberFormatException error) {
            fail(what + " overflows the signed 64-bit domain");
            return 0;
        }
        if (value > maximum) {
            fail(what + " exceeds " + maximum);
        }
        return value;
    }

    private static long addressValue(JsonReader reader, String what) throws IOException {
        String text = stringValue(reader, what);
        if (!ADDRESS_TEXT.matcher(text).matches()) {
            fail(what + " is not a canonical address");
        }
        return Long.parseLong(text.substring(2), 16);
    }

    private static String hashValue(JsonReader reader, String what) throws IOException {
        return requireHashText(stringValue(reader, what), what);
    }

    private static boolean nullValue(JsonReader reader, String what) throws IOException {
        if (reader.peek() == JsonToken.NULL) {
            try {
                reader.nextNull();
            }
            catch (IOException | IllegalStateException error) {
                fail(what + " could not be read: " + error.getMessage());
            }
            return true;
        }
        return false;
    }

    private static String requireHashText(String text, String what) {
        if (text == null || !HASH_TEXT.matcher(text).matches()) {
            fail(what + " is not canonical lowercase BLAKE3");
        }
        return text;
    }

    private static String requireIsa(String text) {
        if (!"arm".equals(text) && !"thumb".equals(text)) {
            fail("unknown ISA " + text);
        }
        return text;
    }

    private static long requireNonNegative(String text, String what) {
        if (text == null || !UNSIGNED_INTEGER.matcher(text).matches()) {
            fail(what + " is not a canonical non-negative decimal");
        }
        try {
            return Long.parseLong(text);
        }
        catch (NumberFormatException error) {
            fail(what + " overflows the signed 64-bit domain");
            return 0;
        }
    }

    private static boolean isSafeLabel(String label) {
        return label != null && !label.isEmpty() && !".".equals(label) && !"..".equals(label)
                && SAFE_LABEL.matcher(label).matches();
    }

    // -------------------------------------------------------------------------
    // PAL manifest parsing
    // -------------------------------------------------------------------------

    private static PalManifest parsePalManifest(byte[] bytes, String expectedLabel,
            String manifestBlake3) throws Exception {
        String json;
        try {
            json = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes))
                    .toString();
        }
        catch (CharacterCodingException error) {
            throw new Exception("task manifest is not valid UTF-8", error);
        }
        try (JsonReader reader = new JsonReader(new StringReader(json))) {
            reader.setStrictness(Strictness.STRICT);
            ManifestWire wire = readManifestObject(reader, expectedLabel);
            if (reader.peek() != JsonToken.END_DOCUMENT) {
                fail("task manifest has trailing non-whitespace content");
            }
            return new PalManifest(wire.imageLabel, wire.imageBase, wire.imageSize,
                    wire.imageBlake3, wire.scatterLoadMapBlake3, wire.slotBase, wire.stride,
                    wire.capacity, wire.tasks, wire.applications, manifestBlake3,
                    wire.scatterEntriesUsed.size());
        }
        catch (PalError error) {
            throw new Exception(error.getMessage(), error);
        }
        catch (IOException | IllegalStateException error) {
            throw new Exception("task manifest is not strict JSON: " + error.getMessage(), error);
        }
    }

    private static final class ManifestWire {
        String imageLabel;
        long imageBase;
        long imageSize;
        String imageBlake3;
        String scatterLoadMapBlake3;
        long slotBase;
        long stride;
        long capacity;
        long nameOffset;
        long tableCount;
        long terminalSlot;
        List<PalSpan> terminalStorage = new ArrayList<>();
        List<Long> scatterEntriesUsed = new ArrayList<>();
        List<PalTask> tasks = new ArrayList<>();
        List<PalApplication> applications = new ArrayList<>();
    }

    private static ManifestWire readManifestObject(JsonReader reader, String expectedLabel)
            throws IOException {
        ManifestWire wire = new ManifestWire();
        if (reader.peek() != JsonToken.BEGIN_OBJECT) {
            fail("task manifest root is not an object");
        }
        reader.beginObject();
        name(reader, "format");
        if (!PAL_FORMAT.equals(stringValue(reader, "format"))) {
            fail("unexpected PAL task-manifest format");
        }
        name(reader, "schema_version");
        if (unsignedValue(reader, UINT32_MAX, "schema_version") != 1) {
            fail("unsupported PAL task-manifest schema_version");
        }
        name(reader, "tool_version");
        if (stringValue(reader, "tool_version").isEmpty()) {
            fail("task manifest tool_version is empty");
        }

        name(reader, "image");
        reader.beginObject();
        name(reader, "label");
        String label = stringValue(reader, "image label");
        if (!isSafeLabel(label) || !label.equals(expectedLabel)) {
            fail("image label does not match the expected label");
        }
        wire.imageLabel = label;
        name(reader, "base_addr");
        wire.imageBase = addressValue(reader, "image base_addr");
        name(reader, "size");
        wire.imageSize = unsignedValue(reader, UINT32_MAX, "image size");
        if (wire.imageSize == 0) {
            fail("image size is zero");
        }
        checkedEnd(wire.imageBase, wire.imageSize, "image");
        name(reader, "blake3");
        wire.imageBlake3 = hashValue(reader, "image blake3");
        endObject(reader, "blake3");

        name(reader, "runtime_view");
        reader.beginObject();
        name(reader, "scatter_load_map_blake3");
        wire.scatterLoadMapBlake3 =
                nullValue(reader, "scatter_load_map_blake3") ? null
                        : hashValue(reader, "scatter_load_map_blake3");
        name(reader, "scatter_entries_used");
        wire.scatterEntriesUsed = readSortedUnsignedArray(reader, "scatter_entries_used element",
                "scatter_entries_used");
        endObject(reader, "scatter_entries_used");

        name(reader, "decoder");
        reader.beginObject();
        name(reader, "semantic_adapter");
        if (!SEMANTIC_ADAPTER.equals(stringValue(reader, "semantic_adapter"))) {
            fail("decoder semantic_adapter does not match the compiled semantic adapter");
        }
        name(reader, "backend_crate");
        if (!BACKEND_CRATE.equals(stringValue(reader, "backend_crate"))) {
            fail("decoder backend_crate does not match the compiled decoder crate");
        }
        name(reader, "backend_version");
        if (stringValue(reader, "backend_version").isEmpty()) {
            fail("decoder backend_version is empty");
        }
        endObject(reader, "backend_version");

        name(reader, "initializer");
        readInitializer(reader, wire);

        name(reader, "table");
        readTable(reader, wire);

        name(reader, "tasks");
        beginArray(reader, "tasks");
        while (arrayHasNext(reader)) {
            wire.tasks.add(readTask(reader));
        }
        endArray(reader, "tasks");

        name(reader, "applications");
        beginArray(reader, "applications");
        while (arrayHasNext(reader)) {
            wire.applications.add(readApplication(reader));
        }
        endArray(reader, "applications");
        endObject(reader, "applications");

        crossCheckManifest(wire);
        return wire;
    }

    private static void readInitializer(JsonReader reader, ManifestWire wire) throws IOException {
        reader.beginObject();
        name(reader, "cfg_entry");
        addressValue(reader, "initializer cfg_entry");
        name(reader, "anchors");
        List<Long> anchors = new ArrayList<>();
        beginArray(reader, "anchors");
        while (arrayHasNext(reader)) {
            reader.beginObject();
            name(reader, "address");
            long anchorAddress = addressValue(reader, "anchor address");
            name(reader, "storage");
            List<PalSpan> storage = readSpans(reader, "anchor storage");
            endObject(reader, "storage");
            if (storage.isEmpty()) {
                fail("anchor storage is empty");
            }
            if (storage.stream().anyMatch(PalSpan::isZeroFill)) {
                fail("anchor storage contains virtual zero fill");
            }
            if (!anchors.isEmpty() && anchors.get(anchors.size() - 1) >= anchorAddress) {
                fail("anchors are not sorted by unique address");
            }
            anchors.add(anchorAddress);
        }
        endArray(reader, "anchors");
        if (anchors.isEmpty()) {
            fail("the anchors array is empty");
        }

        name(reader, "anchor_references");
        beginArray(reader, "anchor_references");
        long[] previousReference = null;
        while (arrayHasNext(reader)) {
            reader.beginObject();
            name(reader, "anchor");
            long anchor = addressValue(reader, "anchor reference anchor");
            name(reader, "address");
            long referenceAddress = addressValue(reader, "anchor reference address");
            name(reader, "kind");
            int kindRank = anchorKindRank(stringValue(reader, "anchor reference kind"));
            name(reader, "definitions");
            beginArray(reader, "definitions");
            boolean sawDefinition = false;
            while (arrayHasNext(reader)) {
                addressValue(reader, "anchor definition");
                sawDefinition = true;
            }
            endArray(reader, "definitions");
            if (!sawDefinition) {
                fail("an anchor reference has an empty definition chain");
            }
            name(reader, "call");
            long call = addressValue(reader, "anchor reference call");
            endObject(reader, "call");
            long[] key = {anchor, referenceAddress, kindRank, call};
            if (previousReference != null && compareKeys(previousReference, key) >= 0) {
                fail("anchor_references are not sorted by (anchor,address,kind,call)");
            }
            if (!anchors.contains(anchor)) {
                fail("an anchor reference names an unknown anchor");
            }
            previousReference = key;
        }
        endArray(reader, "anchor_references");

        name(reader, "code_storage");
        List<PalSpan> codeStorage = readSpans(reader, "code_storage");
        if (codeStorage.isEmpty()) {
            fail("the code_storage array is empty");
        }
        if (codeStorage.stream().anyMatch(PalSpan::isZeroFill)) {
            fail("code_storage contains virtual zero fill");
        }
        name(reader, "loop_start");
        addressValue(reader, "initializer loop_start");
        name(reader, "count_zero_definition");
        addressValue(reader, "initializer count_zero_definition");
        name(reader, "slot_definition");
        reader.beginObject();
        name(reader, "root");
        long root = addressValue(reader, "slot definition root");
        name(reader, "definitions");
        beginArray(reader, "slot definitions");
        boolean sawRoot = false;
        while (arrayHasNext(reader)) {
            long definition = addressValue(reader, "slot definition");
            if (!sawRoot) {
                if (definition != root) {
                    fail("slot definition chain does not begin at its root");
                }
                sawRoot = true;
            }
        }
        endArray(reader, "slot definitions");
        endObject(reader, "definitions");
        if (!sawRoot) {
            fail("slot definition chain does not begin at its root");
        }
        name(reader, "normal_exit");
        long normalExit = addressValue(reader, "initializer normal_exit");
        name(reader, "capacity_exit");
        long capacityExit = addressValue(reader, "initializer capacity_exit");
        if (normalExit == capacityExit) {
            fail("dual exits share one address");
        }
        name(reader, "capacity_guard");
        reader.beginObject();
        name(reader, "start");
        addressValue(reader, "capacity guard start");
        name(reader, "branch");
        addressValue(reader, "capacity guard branch");
        name(reader, "fallthrough");
        addressValue(reader, "capacity guard fallthrough");
        name(reader, "relation");
        if (!CAPACITY_GUARD_RELATION.equals(stringValue(reader, "capacity guard relation"))) {
            fail("unknown capacity guard relation");
        }
        endObject(reader, "relation");
        name(reader, "suffix_loop");
        addressValue(reader, "initializer suffix_loop");
        name(reader, "join");
        addressValue(reader, "initializer join");
        name(reader, "count_global");
        addressValue(reader, "initializer count_global");
        name(reader, "slot_base");
        wire.slotBase = addressValue(reader, "initializer slot_base");
        name(reader, "name_offset");
        wire.nameOffset = unsignedValue(reader, UINT32_MAX, "initializer name_offset");
        name(reader, "index_offset");
        long indexOffset = unsignedValue(reader, UINT32_MAX, "initializer index_offset");
        name(reader, "stride");
        wire.stride = unsignedValue(reader, UINT32_MAX, "initializer stride");
        name(reader, "capacity");
        wire.capacity = unsignedValue(reader, UINT32_MAX, "initializer capacity");
        endObject(reader, "capacity");
        if (wire.capacity == 0 || wire.capacity > MAX_TABLE_CAPACITY) {
            fail("capacity exceeds the descriptor-v1 table limit");
        }
        if (wire.stride == 0 || wire.stride > MAX_TABLE_STRIDE) {
            fail("stride exceeds the descriptor-v1 table limit");
        }
        if (checkedEnd(wire.nameOffset, 24, "name offset") > wire.stride
                || checkedEnd(indexOffset, 4, "index offset") > wire.stride) {
            fail("known descriptor fields do not fit inside the stride");
        }
    }

    private static void readTable(JsonReader reader, ManifestWire wire) throws IOException {
        reader.beginObject();
        name(reader, "count");
        wire.tableCount = unsignedValue(reader, UINT32_MAX, "table count");
        name(reader, "terminal_slot");
        wire.terminalSlot = addressValue(reader, "table terminal_slot");
        name(reader, "terminal_blake3");
        hashValue(reader, "table terminal_blake3");
        name(reader, "terminal_storage");
        wire.terminalStorage = readSpans(reader, "terminal_storage");
        if (wire.terminalStorage.isEmpty()) {
            fail("terminal storage is empty");
        }
        name(reader, "descriptor_projection_offset");
        long projection = unsignedValue(reader, UINT32_MAX, "table descriptor_projection_offset");
        name(reader, "priority_offset");
        long priorityOffset = unsignedValue(reader, UINT32_MAX, "table priority_offset");
        name(reader, "stack_size_offset");
        long stackSizeOffset = unsignedValue(reader, UINT32_MAX, "table stack_size_offset");
        name(reader, "entry_offset");
        long entryOffset = unsignedValue(reader, UINT32_MAX, "table entry_offset");
        name(reader, "callback_offset");
        long callbackOffset = unsignedValue(reader, UINT32_MAX, "table callback_offset");
        name(reader, "unknown_pointer_offset");
        long unknownPointerOffset =
                unsignedValue(reader, UINT32_MAX, "table unknown_pointer_offset");
        endObject(reader, "unknown_pointer_offset");
        if (wire.nameOffset < DESCRIPTOR_PROJECTION_OFFSET
                || projection != wire.nameOffset - DESCRIPTOR_PROJECTION_OFFSET) {
            fail("descriptor projection offset is not the projection");
        }
        long[] expected = {wire.nameOffset + 4, wire.nameOffset + 8, wire.nameOffset + 12,
                wire.nameOffset + 16, wire.nameOffset + 20};
        long[] actual =
                {priorityOffset, stackSizeOffset, entryOffset, callbackOffset, unknownPointerOffset};
        if (!Arrays.equals(expected, actual)) {
            fail("table field offsets do not follow the discovered name offset");
        }
    }

    private static int anchorKindRank(String kind) {
        switch (kind) {
            case "adr": return 0;
            case "literal": return 1;
            case "movw_movt": return 2;
            default: fail("unknown anchor reference kind " + kind); return -1;
        }
    }

    private static int compareKeys(long[] left, long[] right) {
        for (int index = 0; index < left.length; index++) {
            int comparison = Long.compare(left[index], right[index]);
            if (comparison != 0) {
                return comparison;
            }
        }
        return 0;
    }

    private static List<Long> readSortedUnsignedArray(JsonReader reader, String elementWhat,
            String arrayWhat) throws IOException {
        List<Long> values = new ArrayList<>();
        beginArray(reader, arrayWhat);
        while (arrayHasNext(reader)) {
            long value = unsignedValue(reader, UINT32_MAX, elementWhat);
            if (!values.isEmpty() && values.get(values.size() - 1) >= value) {
                fail(arrayWhat + " is not sorted with unique elements");
            }
            values.add(value);
        }
        endArray(reader, arrayWhat);
        return values;
    }

    private static List<PalSpan> readSpans(JsonReader reader, String what) throws IOException {
        List<PalSpan> spans = new ArrayList<>();
        beginArray(reader, what);
        while (arrayHasNext(reader)) {
            reader.beginObject();
            name(reader, "kind");
            String kind = stringValue(reader, "storage kind");
            if (!"raw".equals(kind) && !"scatter_bytes".equals(kind)
                    && !"scatter_zero".equals(kind)) {
                fail("unknown storage kind " + kind);
            }
            name(reader, "address");
            long address = addressValue(reader, "storage address");
            name(reader, "size");
            long size = unsignedValue(reader, UINT32_MAX, "storage size");
            Long scatterEntry = null;
            if (optionalName(reader, "scatter_entry")) {
                scatterEntry = unsignedValue(reader, UINT32_MAX, "scatter entry");
            }
            endObject(reader, "scatter_entry");
            if ("raw".equals(kind) && scatterEntry != null) {
                fail("raw storage span carries a scatter_entry it cannot have");
            }
            if (!"raw".equals(kind) && scatterEntry == null) {
                fail("scatter storage span lacks its required scatter_entry");
            }
            spans.add(new PalSpan(kind, address, size, scatterEntry));
        }
        endArray(reader, what);
        requireSpanGeometry(spans, what);
        return spans;
    }

    private static void requireSpanGeometry(List<PalSpan> spans, String what) {
        long previousEnd = -1;
        for (PalSpan span : spans) {
            if (span.size == 0) {
                fail(what + " contains a zero-size span");
            }
            long end = checkedEnd(span.address, span.size, what + " span");
            if (previousEnd != -1 && span.address < previousEnd) {
                fail(what + " spans are not sorted or overlap");
            }
            previousEnd = end;
        }
    }

    private static PalTask readTask(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "index");
        long index = unsignedValue(reader, UINT32_MAX, "task index");
        name(reader, "slot");
        long slot = addressValue(reader, "task slot");
        name(reader, "slot_blake3");
        String slotBlake3 = hashValue(reader, "task slot_blake3");
        name(reader, "name_pointer");
        long namePointer = addressValue(reader, "task name_pointer");
        name(reader, "name");
        String name = stringValue(reader, "task name");
        name(reader, "task_label");
        String taskLabel = stringValue(reader, "task task_label");
        name(reader, "priority");
        long priority = unsignedValue(reader, 0xff, "task priority");
        name(reader, "stack_size");
        long stackSize = unsignedValue(reader, UINT32_MAX, "task stack_size");
        name(reader, "entry_pointer");
        long entryPointer = addressValue(reader, "task entry_pointer");
        name(reader, "entry");
        long entry = addressValue(reader, "task entry");
        name(reader, "isa");
        String isa = requireIsa(stringValue(reader, "task isa"));
        name(reader, "instruction_size");
        long instructionSize = unsignedValue(reader, 0xff, "task instruction_size");
        name(reader, "instruction_blake3");
        String instructionBlake3 = hashValue(reader, "task instruction_blake3");
        name(reader, "callback");
        long callback = addressValue(reader, "task callback");
        name(reader, "unknown_pointer");
        long unknownPointer = addressValue(reader, "task unknown_pointer");
        name(reader, "slot_storage");
        List<PalSpan> slotStorage = readSpans(reader, "task slot_storage");
        name(reader, "name_storage");
        List<PalSpan> nameStorage = readSpans(reader, "task name_storage");
        name(reader, "entry_storage");
        List<PalSpan> entryStorage = readSpans(reader, "task entry_storage");
        endObject(reader, "entry_storage");

        if (slotStorage.isEmpty() || nameStorage.isEmpty() || entryStorage.isEmpty()) {
            fail("a task storage array is empty");
        }
        if (stackSize == 0 || stackSize % 4 != 0) {
            fail("task stack size is zero or not four-byte aligned");
        }
        if (name.length() < 2) {
            fail("task name is shorter than two characters");
        }
        boolean thumbPointer = (entryPointer & 1L) == 1L;
        if (thumbPointer != "thumb".equals(isa) || entry != (entryPointer & ~1L)) {
            fail("task entry does not match the normalized pointer");
        }
        if ("arm".equals(isa)) {
            if (entry % 4 != 0) {
                fail("ARM entry pointer is not word aligned");
            }
            if (instructionSize != 4) {
                fail("ARM entry instruction size is not four bytes");
            }
        }
        else if (instructionSize != 2 && instructionSize != 4) {
            fail("Thumb entry instruction size is not two or four bytes");
        }
        return new PalTask(index, slot, slotBlake3, namePointer, name, taskLabel, priority,
                stackSize, entryPointer, entry, isa, instructionSize, instructionBlake3, callback,
                unknownPointer, slotStorage, nameStorage, entryStorage);
    }

    private static PalApplication readApplication(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "entry");
        long entry = addressValue(reader, "application entry");
        name(reader, "isa");
        String isa = requireIsa(stringValue(reader, "application isa"));
        name(reader, "desired_primary");
        String desiredPrimary = stringValue(reader, "application desired_primary");
        name(reader, "task_indices");
        List<Long> taskIndices = readSortedUnsignedArray(reader, "application task index",
                "application task_indices");
        name(reader, "labels");
        List<PalLabel> labels = new ArrayList<>();
        beginArray(reader, "labels");
        while (arrayHasNext(reader)) {
            reader.beginObject();
            name(reader, "label");
            String label = stringValue(reader, "application label");
            name(reader, "task_indices");
            List<Long> labelIndices =
                    readSortedUnsignedArray(reader, "label task index", "label task_indices");
            endObject(reader, "task_indices");
            if (labelIndices.isEmpty()) {
                fail("an application label covers no task indices");
            }
            labels.add(new PalLabel(label, labelIndices));
        }
        endArray(reader, "labels");
        endObject(reader, "labels");
        if (taskIndices.isEmpty()) {
            fail("an application covers no task indices");
        }
        return new PalApplication(entry, isa, desiredPrimary, taskIndices, labels);
    }

    private static void crossCheckManifest(ManifestWire wire) {
        long taskCount = wire.tasks.size();
        if (wire.tableCount != taskCount) {
            fail("table task count does not match the serialized task records");
        }
        if (taskCount == 0 || taskCount >= wire.capacity) {
            fail("task count is outside 1..capacity");
        }
        long terminalAdvanced =
                checkedMultiply(taskCount, wire.stride, "terminal slot arithmetic");
        if (wire.terminalSlot != checkedEnd(wire.slotBase, terminalAdvanced, "terminal slot")) {
            fail("terminal slot is not the slot after the final task");
        }
        Set<Long> slots = new HashSet<>();
        for (int position = 0; position < wire.tasks.size(); position++) {
            PalTask task = wire.tasks.get(position);
            if (task.index != position) {
                fail("task indices are not the contiguous table order");
            }
            long advanced = checkedMultiply(task.index, wire.stride, "task slot arithmetic");
            if (task.slot != checkedEnd(wire.slotBase, advanced, "task slot")) {
                fail("task slot is not the slot_base geometry");
            }
            if (!slots.add(task.slot)) {
                fail("two tasks share one slot address");
            }
        }

        Set<Long> used = new HashSet<>();
        for (PalTask task : wire.tasks) {
            collectScatterEntries(task.slotStorage, used);
            collectScatterEntries(task.nameStorage, used);
            collectScatterEntries(task.entryStorage, used);
        }
        collectScatterEntries(wire.terminalStorage, used);
        if (!used.equals(new HashSet<>(wire.scatterEntriesUsed))) {
            fail("scatter_entries_used is not the exact storage union");
        }

        Set<Long> covered = new HashSet<>();
        for (PalApplication application : wire.applications) {
            if (!covered.addAll(application.taskIndices)) {
                fail("one task index appears in two applications");
            }
            for (long taskIndex : application.taskIndices) {
                if (taskIndex >= taskCount) {
                    fail("an application names an unknown task index");
                }
            }
            Set<Long> labelCovered = new HashSet<>();
            for (PalLabel label : application.labels) {
                if (!labelCovered.addAll(label.taskIndices)) {
                    fail("one task index appears in two labels");
                }
                String memberName = null;
                for (long taskIndex : label.taskIndices) {
                    PalTask member = wire.tasks.get((int) taskIndex);
                    if (memberName == null) {
                        memberName = member.name;
                    }
                    else if (!memberName.equals(member.name)) {
                        fail("one label covers tasks with different names");
                    }
                }
            }
            if (!labelCovered.equals(new HashSet<>(application.taskIndices))) {
                fail("labels do not partition one application");
            }
            for (long taskIndex : application.taskIndices) {
                PalTask member = wire.tasks.get((int) taskIndex);
                if (member.entry != application.entry || !member.isa.equals(application.isa)) {
                    fail("application membership does not share the normalized entry");
                }
                String covering = null;
                for (PalLabel label : application.labels) {
                    if (label.taskIndices.contains(taskIndex)) {
                        covering = label.label;
                        break;
                    }
                }
                if (covering == null || !covering.equals(member.taskLabel)) {
                    fail("a task label does not match its serialized application label");
                }
            }
        }
        if (!covered.equals(allIndices(taskCount))) {
            fail("applications do not partition the task indices");
        }

        long previousEntry = -1;
        String previousIsa = null;
        for (PalApplication application : wire.applications) {
            if (previousEntry == application.entry && previousIsa.equals(application.isa)) {
                fail("applications do not carry unique (entry, isa) groups");
            }
            if (previousEntry > application.entry
                    || (previousEntry == application.entry
                            && previousIsa.compareTo(application.isa) > 0)) {
                fail("applications are not sorted by (entry, isa)");
            }
            previousEntry = application.entry;
            previousIsa = application.isa;
        }
        verifyLeafPolicy(wire);
    }

    private static void collectScatterEntries(List<PalSpan> spans, Set<Long> used) {
        for (PalSpan span : spans) {
            if (span.scatterEntry != null) {
                used.add(span.scatterEntry);
            }
        }
    }

    private static Set<Long> allIndices(long taskCount) {
        Set<Long> indices = new HashSet<>();
        for (long index = 0; index < taskCount; index++) {
            indices.add(index);
        }
        return indices;
    }

    private static void verifyLeafPolicy(ManifestWire wire) {
        Map<String, Long> labelOccurrences = new HashMap<>();
        Map<String, Long> primaryOccurrences = new HashMap<>();
        for (PalApplication application : wire.applications) {
            primaryOccurrences.merge(primaryPreferred(wire, application), 1L, Long::sum);
            for (PalLabel label : application.labels) {
                labelOccurrences.merge(labelPreferred(wire, label), 1L, Long::sum);
            }
        }
        for (PalApplication application : wire.applications) {
            String preferred = primaryPreferred(wire, application);
            verifyAllocatedLeaf(application.desiredPrimary, preferred, application.entry,
                    application.taskIndices.get(0), primaryOccurrences.get(preferred));
            for (PalLabel label : application.labels) {
                String labelPreferred = labelPreferred(wire, label);
                verifyAllocatedLeaf(label.label, labelPreferred, application.entry,
                        label.taskIndices.get(0), labelOccurrences.get(labelPreferred));
            }
        }
    }

    private static String primaryPreferred(ManifestWire wire, PalApplication application) {
        Set<String> distinctNames = new HashSet<>();
        for (long taskIndex : application.taskIndices) {
            distinctNames.add(wire.tasks.get((int) taskIndex).name);
        }
        if (distinctNames.size() == 1) {
            return TASK_LABEL_PREFIX
                    + sanitized(wire.tasks.get(application.taskIndices.get(0).intValue()).name);
        }
        return TASK_LABEL_PREFIX + SHARED_PRIMARY_INFIX
                + String.format(Locale.ROOT, "%08x", application.entry);
    }

    private static String labelPreferred(ManifestWire wire, PalLabel label) {
        return TASK_LABEL_PREFIX
                + sanitized(wire.tasks.get(label.taskIndices.get(0).intValue()).name);
    }

    private static String sanitized(String name) {
        String sanitized = sanitizeTaskName(name);
        if (sanitized == null) {
            fail("task name sanitizes to an empty portion");
        }
        return sanitized;
    }

    private static void verifyAllocatedLeaf(String leaf, String preferred, long entry,
            long lowestIndex, long occurrences) {
        if (leaf.length() > MAX_SYMBOL_LEAF_CHARS) {
            fail("an allocated leaf exceeds the Ghidra symbol leaf limit");
        }
        if (occurrences == 1L) {
            if (!leaf.equals(preferred)) {
                fail("a unique preferred leaf was not allocated verbatim");
            }
            return;
        }
        if (!leaf.startsWith(preferred)) {
            fail("a colliding leaf does not extend its preferred leaf");
        }
        String suffix = leaf.substring(preferred.length());
        if (!COLLISION_SUFFIX.matcher(suffix).matches()) {
            fail("a colliding leaf does not carry the canonical suffix grammar");
        }
        String expectedPrefix =
                String.format(Locale.ROOT, "_pme_%08x_%08x_", entry, lowestIndex);
        if (!suffix.startsWith(expectedPrefix)) {
            fail("a colliding leaf suffix does not bind its entry and lowest index");
        }
    }

    // -------------------------------------------------------------------------
    // Symbol-map v4 parsing
    // -------------------------------------------------------------------------

    private static SymbolMap parseSymbolMap(Reader reader, String mapBlake3) throws Exception {
        try (JsonReader json = new JsonReader(reader)) {
            json.setStrictness(Strictness.STRICT);
            SymbolMapWire wire = readSymbolMapObject(json);
            if (json.peek() != JsonToken.END_DOCUMENT) {
                fail("symbol map has trailing non-whitespace content");
            }
            return new SymbolMap(wire.imageLabel, wire.imageBase, wire.imageSize,
                    wire.imageBlake3, wire.exceptionIdentity, wire.exceptionManifestBlake3,
                    wire.palIdentity, wire.manifestBlake3,
                    wire.scatterLoadMapBlake3, wire.functionsBlake3, wire.executions,
                    wire.decisions, wire.creations, mapBlake3);
        }
        catch (PalError error) {
            throw new Exception(error.getMessage(), error);
        }
        catch (IOException | IllegalStateException error) {
            throw new Exception("symbol map is not strict JSON: " + error.getMessage(), error);
        }
    }

    private static final class SymbolMapWire {
        String imageLabel;
        long imageBase;
        long imageSize;
        String imageBlake3;
        String exceptionIdentity;
        String exceptionManifestBlake3;
        String palIdentity;
        String manifestBlake3;
        String scatterLoadMapBlake3;
        String functionsBlake3;
        List<MapExecution> executions = new ArrayList<>();
        List<MapDecision> decisions = new ArrayList<>();
        List<MapCreation> creations = new ArrayList<>();
    }

    private static SymbolMapWire readSymbolMapObject(JsonReader reader) throws IOException {
        SymbolMapWire wire = new SymbolMapWire();
        if (reader.peek() != JsonToken.BEGIN_OBJECT) {
            fail("symbol map root is not an object");
        }
        reader.beginObject();
        name(reader, "format");
        if (!SYMBOL_MAP_FORMAT.equals(stringValue(reader, "format"))) {
            fail("unexpected symbol-map format");
        }
        name(reader, "image");
        reader.beginObject();
        name(reader, "label");
        String label = stringValue(reader, "symbol map image label");
        if (!isSafeLabel(label)) {
            fail("symbol map image label is not a safe path component");
        }
        wire.imageLabel = label;
        name(reader, "base_addr");
        wire.imageBase = addressValue(reader, "symbol map image base_addr");
        name(reader, "size");
        wire.imageSize = unsignedValue(reader, UINT32_MAX, "symbol map image size");
        if (wire.imageSize == 0) {
            fail("symbol map image size is zero");
        }
        checkedEnd(wire.imageBase, wire.imageSize, "symbol map image");
        name(reader, "blake3");
        wire.imageBlake3 = hashValue(reader, "symbol map image blake3");
        endObject(reader, "blake3");

        name(reader, "exception_roots");
        reader.beginObject();
        name(reader, "identity");
        String exceptionIdentity = stringValue(reader, "symbol map exception identity");
        if (NONE_IDENTITY.equals(exceptionIdentity)) {
            wire.exceptionIdentity = NONE_IDENTITY;
            name(reader, "manifest_blake3");
            if (!nullValue(reader, "manifest_blake3")) {
                fail("a none exception identity carries a manifest BLAKE3");
            }
        }
        else {
            String[] parts = parseExceptionIdentity(exceptionIdentity);
            wire.exceptionIdentity = exceptionIdentity;
            name(reader, "manifest_blake3");
            wire.exceptionManifestBlake3 = hashValue(
                    reader, "exception manifest_blake3");
            if (!wire.exceptionManifestBlake3.equals(parts[1])) {
                fail("exception identity does not bind its manifest BLAKE3");
            }
        }
        endObject(reader, "manifest_blake3");

        name(reader, "pal");
        reader.beginObject();
        name(reader, "identity");
        String identity = stringValue(reader, "symbol map pal identity");
        if (NONE_IDENTITY.equals(identity)) {
            wire.palIdentity = NONE_IDENTITY;
            name(reader, "manifest_blake3");
            if (!nullValue(reader, "manifest_blake3")) {
                fail("a none identity carries a manifest BLAKE3");
            }
            name(reader, "scatter_load_map_blake3");
            if (!nullValue(reader, "scatter_load_map_blake3")) {
                fail("a none identity carries a scatter BLAKE3");
            }
        }
        else {
            String[] parts = parsePalIdentity(identity);
            wire.palIdentity = identity;
            name(reader, "manifest_blake3");
            wire.manifestBlake3 = hashValue(reader, "manifest_blake3");
            if (!wire.manifestBlake3.equals(parts[1])) {
                fail("pal identity does not bind its manifest BLAKE3");
            }
            name(reader, "scatter_load_map_blake3");
            wire.scatterLoadMapBlake3 = hashValue(reader, "scatter_load_map_blake3");
        }
        endObject(reader, "scatter_load_map_blake3");

        name(reader, "functions_blake3");
        wire.functionsBlake3 = hashValue(reader, "functions_blake3");

        name(reader, "executions");
        beginArray(reader, "executions");
        long totalRanges = 0;
        long chargedBytes = 0;
        long previousEntry = -1;
        String previousIsa = null;
        String previousDigest = null;
        while (arrayHasNext(reader)) {
            if (wire.executions.size() >= MAX_EXECUTIONS) {
                fail("symbol map exceeds the execution limit");
            }
            reader.beginObject();
            name(reader, "producer");
            if (!"ghidra".equals(stringValue(reader, "producer"))) {
                fail("symbol map producer is not ghidra");
            }
            name(reader, "entry");
            long entry = addressValue(reader, "execution entry");
            name(reader, "execution_blake3");
            String executionBlake3 = hashValue(reader, "execution_blake3");
            name(reader, "decode_ranges");
            List<ExecutionRangeWire> ranges = new ArrayList<>();
            beginArray(reader, "decode_ranges");
            long previousEnd = -1;
            while (arrayHasNext(reader)) {
                if (ranges.size() >= MAX_EXECUTION_RANGES_EACH) {
                    fail("an execution exceeds its per-execution range limit");
                }
                if (++totalRanges > MAX_EXECUTION_RANGES_TOTAL) {
                    fail("symbol map exceeds the aggregate range limit");
                }
                reader.beginObject();
                name(reader, "isa");
                String isa = requireIsa(stringValue(reader, "decode range isa"));
                name(reader, "start");
                long start = addressValue(reader, "decode range start");
                name(reader, "end");
                long end = addressValue(reader, "decode range end");
                name(reader, "blake3");
                String blake3 = hashValue(reader, "decode range blake3");
                endObject(reader, "blake3");
                if (end <= start) {
                    fail("decode range end is not after its start");
                }
                if (previousEnd != -1 && start < previousEnd) {
                    fail("decode ranges are not sorted or overlap");
                }
                previousEnd = end;
                chargedBytes = checkedAdd(chargedBytes, end - start, "charged range bytes");
                if (chargedBytes > MAX_CHARGED_RANGE_BYTES) {
                    fail("symbol map exceeds the charged range-byte limit");
                }
                ranges.add(new ExecutionRangeWire(isa, start, end, blake3));
            }
            endArray(reader, "decode_ranges");
            endObject(reader, "decode_ranges");
            if (ranges.isEmpty()) {
                fail("an execution carries no decode ranges");
            }
            String firstIsa = ranges.get(0).isa;
            if (previousEntry != -1) {
                int byEntry = Long.compare(previousEntry, entry);
                if (byEntry > 0 || (byEntry == 0
                        && (previousIsa.compareTo(firstIsa) > 0
                                || (previousIsa.equals(firstIsa)
                                        && previousDigest.compareTo(executionBlake3) >= 0)))) {
                    fail("executions are not sorted by (entry, isa, execution_blake3)");
                }
            }
            previousEntry = entry;
            previousIsa = firstIsa;
            previousDigest = executionBlake3;
            wire.executions.add(new MapExecution("ghidra", entry, executionBlake3, ranges));
        }
        endArray(reader, "executions");

        name(reader, "symbols");
        beginArray(reader, "symbols");
        long annotationAggregate = 0;
        while (arrayHasNext(reader)) {
            reader.beginObject();
            name(reader, "execution");
            long execution = unsignedValue(reader, UINT32_MAX, "decision execution");
            if (execution != wire.decisions.size()) {
                fail("symbol decisions are not the exact execution order");
            }
            name(reader, "original_primary");
            String originalPrimary = mapString(reader, "original_primary");
            name(reader, "original_source");
            String originalSource = requireSourceName(stringValue(reader, "original_source"));
            name(reader, "final_primary");
            String finalPrimary = mapString(reader, "final_primary");
            name(reader, "final_source");
            String finalSource = requireSourceName(stringValue(reader, "final_source"));
            name(reader, "action");
            String action = stringValue(reader, "action");
            if (!"preserve".equals(action) && !"rename".equals(action)
                    && !"mirror".equals(action)) {
                fail("decision action is not preserve, rename, or mirror");
            }
            name(reader, "annotations");
            List<String> annotations = new ArrayList<>();
            beginArray(reader, "annotations");
            while (arrayHasNext(reader)) {
                if (annotations.size() >= MAX_ANNOTATIONS_PER_DECISION) {
                    fail("a decision exceeds its annotation count limit");
                }
                String annotation = mapString(reader, "annotation");
                long size = utf8NoSurrogates(annotation).length;
                if (size > MAX_ANNOTATION_UTF8_BYTES) {
                    fail("an annotation exceeds its UTF-8 byte limit");
                }
                annotationAggregate =
                        checkedAdd(annotationAggregate, size, "annotation aggregate bytes");
                if (annotationAggregate > MAX_ANNOTATION_AGGREGATE_BYTES) {
                    fail("symbol map exceeds the aggregate annotation limit");
                }
                annotations.add(annotation);
            }
            endArray(reader, "annotations");
            String exceptionTransitionAuthority = null;
            name(reader, "exception_transition");
            if (!nullValue(reader, "exception_transition")) {
                reader.beginObject();
                name(reader, "from");
                if (!"exception_owned".equals(
                        stringValue(reader, "exception_transition from"))) {
                    fail("exception_transition from is not exception_owned");
                }
                name(reader, "to");
                if (!"pass2_owned".equals(stringValue(reader, "exception_transition to"))) {
                    fail("exception_transition to is not pass2_owned");
                }
                name(reader, "authority");
                exceptionTransitionAuthority = stringValue(
                        reader, "exception_transition authority");
                if (!"func".equals(exceptionTransitionAuthority)
                        && !"registration".equals(exceptionTransitionAuthority)) {
                    fail("exception_transition authority is not func or registration");
                }
                endObject(reader, "authority");
            }
            boolean palTransition = false;
            name(reader, "pal_transition");
            if (!nullValue(reader, "pal_transition")) {
                reader.beginObject();
                name(reader, "from");
                if (!"pal_owned".equals(stringValue(reader, "pal_transition from"))) {
                    fail("pal_transition from is not pal_owned");
                }
                name(reader, "to");
                if (!"pass2_owned".equals(stringValue(reader, "pal_transition to"))) {
                    fail("pal_transition to is not pass2_owned");
                }
                endObject(reader, "to");
                palTransition = true;
            }
            endObject(reader, "pal_transition");
            if (exceptionTransitionAuthority != null && palTransition) {
                fail("a decision carries both exception and PAL transitions");
            }
            if (originalPrimary.length() > MAX_SYMBOL_LEAF_CHARS
                    || finalPrimary.length() > MAX_SYMBOL_LEAF_CHARS) {
                fail("a decision primary exceeds the Ghidra symbol leaf limit");
            }
            if ("preserve".equals(action)) {
                if (!originalPrimary.equals(finalPrimary)
                        || !originalSource.equals(finalSource)) {
                    fail("a preserve decision changes the primary");
                }
                if (exceptionTransitionAuthority != null || palTransition) {
                    fail("a preserve decision carries an ownership transition");
                }
            }
            else if ("mirror".equals(action)) {
                // Ghidra mirrors a referenced function's post-rename primary
                // onto its thunks; the mirror decision only verifies that
                // drift, so the source must stay the thunk's original and
                // no PAL transition may ride along.
                if (!originalSource.equals(finalSource)) {
                    fail("a mirror decision changes the primary source");
                }
                if (exceptionTransitionAuthority != null || palTransition) {
                    fail("a mirror decision carries an ownership transition");
                }
            }
            else if ("default".equals(finalSource)) {
                fail("a rename decision produces a default source");
            }
            if (exceptionTransitionAuthority != null && !"user_defined".equals(finalSource)) {
                fail("an exception transition does not produce a user_defined primary");
            }
            wire.decisions.add(new MapDecision(execution, originalPrimary, originalSource,
                    finalPrimary, finalSource, action, annotations,
                    exceptionTransitionAuthority, palTransition));
        }
         endArray(reader, "symbols");
         if (wire.decisions.size() != wire.executions.size()) {
             fail("symbol decisions do not cover every execution exactly once");
         }

         name(reader, "creations");
         beginArray(reader, "creations");
         java.util.HashSet<Long> creationEntries = new java.util.HashSet<>();
         java.util.HashSet<String> creationNames = new java.util.HashSet<>();
         long creationRangeTotal = totalRanges;
         long creationChargedTotal = chargedBytes;
         while (arrayHasNext(reader)) {
             if (wire.creations.size() >= MAX_MAP_CREATIONS) {
                 fail("symbol map exceeds the creation count limit");
             }
             reader.beginObject();
             name(reader, "entry");
             long entry = addressValue(reader, "creation entry");
             if ((entry & 1L) != 0) {
                 fail("creation entry carries the Thumb bit");
             }
             if (!creationEntries.add(entry)) {
                 fail("duplicate creation entry");
             }
             name(reader, "execution_blake3");
             String executionBlake3 = hashValue(reader, "creation execution_blake3");
             name(reader, "decode_ranges");
             beginArray(reader, "decode_ranges");
              List<ExecutionRangeWire> ranges = new ArrayList<>();
              long creationPreviousEnd = -1;
              long creationCharged = 0;
              while (arrayHasNext(reader)) {
                  if (ranges.size() >= MAX_EXECUTION_RANGES_EACH) {
                      fail("a creation exceeds the per-execution range limit");
                  }
                  if (creationRangeTotal >= MAX_EXECUTION_RANGES_TOTAL) {
                      fail("symbol map exceeds the aggregate creation range limit");
                  }
                  reader.beginObject();
                 name(reader, "isa");
                 String isa = requireIsa(stringValue(reader, "decode range isa"));
                 name(reader, "start");
                 long start = addressValue(reader, "decode range start");
                 name(reader, "end");
                 long end = addressValue(reader, "decode range end");
                 name(reader, "blake3");
                 String blake3 = hashValue(reader, "decode range blake3");
                 endObject(reader, "blake3");
                 if (end <= start) {
                     fail("decode range end is not after its start");
                 }
                 if (creationPreviousEnd != -1 && start < creationPreviousEnd) {
                     fail("decode ranges are not sorted or overlap");
                 }
                 creationPreviousEnd = end;
                  creationCharged =
                          checkedAdd(creationCharged, end - start, "charged range bytes");
                  if (creationCharged > MAX_CHARGED_RANGE_BYTES) {
                      fail("a creation exceeds the per-execution charged range limit");
                  }
                  creationChargedTotal = checkedAdd(creationChargedTotal, end - start,
                          "aggregate creation charged range bytes");
                  if (creationChargedTotal > MAX_CHARGED_RANGE_BYTES) {
                      fail("symbol map exceeds the aggregate creation range limit");
                  }
                  creationRangeTotal++;
                  ranges.add(new ExecutionRangeWire(isa, start, end, blake3));
             }
             endArray(reader, "decode_ranges");
             if (ranges.isEmpty()) {
                 fail("a creation carries no authenticated decode ranges");
             }
             if (ranges.get(0).start != entry) {
                 fail("a creation's first decode range does not start at its entry");
             }
             name(reader, "final_primary");
             String primary = mapString(reader, "creation final_primary");
             if (primary.length() > MAX_SYMBOL_LEAF_CHARS) {
                 fail("a creation primary exceeds the Ghidra symbol leaf limit");
             }
             if (!creationNames.add(primary)) {
                 fail("duplicate creation primary " + primary);
             }
             name(reader, "final_source");
             String source = requireSourceName(stringValue(reader, "final_source"));
             if ("default".equals(source)) {
                 fail("a creation produces a default source");
             }
             endObject(reader, "final_source");
             wire.creations.add(
                     new MapCreation(entry, executionBlake3, ranges, primary, source));
         }
         endArray(reader, "creations");
         endObject(reader, "creations");
         return wire;
    }

    private static String requireSourceName(String source) {
        if (!"default".equals(source) && !"analysis".equals(source)
                && !"imported".equals(source) && !"user_defined".equals(source)) {
            fail("unknown symbol source " + source);
        }
        return source;
    }

    private static String mapString(JsonReader reader, String what) throws IOException {
        if (reader.peek() != JsonToken.STRING) {
            fail(what + " is not a string");
        }
        try {
            String value = reader.nextString();
            if (value.indexOf('\0') >= 0) {
                fail(what + " contains a NUL byte");
            }
            try {
                utf8NoSurrogates(value, what);
            }
            catch (PmeScriptSupport.SupportError error) {
                fail(error.getMessage());
            }
            return value;
        }
        catch (IOException | IllegalStateException error) {
            fail(what + " could not be read: " + error.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // File identity helpers
    // -------------------------------------------------------------------------

    private static void assertGhidraSymbolLimit() {
        try {
            PmeScriptSupport.assertGhidraSymbolLimit();
        }
        catch (PmeScriptSupport.SupportError error) {
            fail(error.getMessage());
        }
    }

    private static File requireCanonicalDirectory(File file, String description) {
        try {
            return PmeScriptSupport.requireCanonicalDirectory(file, description);
        }
        catch (PmeScriptSupport.SupportError error) {
            fail(error.getMessage());
            return null;
        }
    }

    private static Throwable closeRetained(AutoCloseable closeable, Throwable failure) {
        if (closeable == null) return failure;
        try {
            closeable.close();
        }
        catch (Throwable closeFailure) {
            if (failure == null) return closeFailure;
            suppress(failure, closeFailure);
        }
        return failure;
    }

    private static void closeQuietly(AutoCloseable closeable, Throwable primary) {
        if (closeable == null) return;
        try {
            closeable.close();
        }
        catch (Throwable closeFailure) {
            suppress(primary, closeFailure);
        }
    }

    private static void suppress(Throwable primary, Throwable cleanupFailure) {
        if (primary == cleanupFailure) return;
        try {
            primary.addSuppressed(cleanupFailure);
        }
        catch (Throwable ignored) {
            // Preserve the original terminal failure.
        }
    }

    private static void rethrow(Throwable failure) throws Exception {
        if (failure instanceof Exception) throw (Exception) failure;
        if (failure instanceof Error) throw (Error) failure;
        throw new Exception(failure);
    }

    // -------------------------------------------------------------------------
    // Checked arithmetic
    // -------------------------------------------------------------------------

    private static long checkedEnd(long start, long size, String what) {
        if (start < 0 || start > UINT32_MAX || size < 0 || size > UINT32_MAX
                || start + size > UINT32_END) {
            fail(what + " range overflows the 32-bit address space");
        }
        return start + size;
    }

    private static long checkedMultiply(long left, long right, String what) {
        try {
            return Math.multiplyExact(left, right);
        }
        catch (ArithmeticException error) {
            fail(what + " wraps the integer domain");
            return 0;
        }
    }

    private static long checkedAdd(long left, long right, String what) {
        try {
            return Math.addExact(left, right);
        }
        catch (ArithmeticException error) {
            fail(what + " wraps the integer domain");
            return 0;
        }
    }

    private static long checkedRange(long value, long minimum, long maximum, String what) {
        if (value < minimum || value > maximum) {
            fail(what + " is outside [" + minimum + ", " + maximum + "]");
        }
        return value;
    }
}
