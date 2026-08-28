// ExceptionRootsSupport.java - strict parser, independent semantic preflight,
// and ownership/postflight support for architectural exception roots.
//@category PixelModem
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.bouncycastle.crypto.digests.Blake3Digest;

final class ExceptionRootsSupport {
    static final String FORMAT = "pixel-modem-extractor-exception-roots-v1";
    static final String IDENTITY_VERSION = "v1";
    static final String RESERVED_NAMESPACE = "PixelModemExtractor_ExceptionRoots_v1";
    static final String OWNERSHIP_MAP = "PixelModemExtractor.ExceptionRoots.v1.Ownership";
    static final String SEMANTIC_ADAPTER = "pixel-modem-extractor-arm32-v1";
    static final String BACKEND_CRATE = "scaleservers-arm32-assembly";
    static final String BACKEND_VERSION = "1.0.0";
    static final int MAX_MANIFEST_BYTES = 1024 * 1024;
    static final int MAX_TABLES = 2;
    static final int SLOTS_PER_TABLE = 8;
    static final int MAX_ROOTS = 16;
    static final int MAX_STORAGE_SPANS = 32;
    static final int MAX_SCATTER_ENTRIES = 256;
    static final int MAX_VBAR_WRITES = 64;
    static final int MAX_CFG_INSTRUCTIONS = 32_768;
    static final int MAX_CFG_BLOCKS = 4_096;
    static final long MAX_SCATTER_OUTPUT_BYTES = 512L * 1024L * 1024L;
    static final int MAX_REASON_UTF8_BYTES = 2048;
    static final int MAX_SYMBOL_UTF8_BYTES = 2000;

    private static final String[] ROLES = {
        "reset", "undefined_instruction", "supervisor_call", "prefetch_abort",
        "data_abort", "reserved", "irq", "fiq"
    };
    private static final String[] PRIMARIES = {
        "Reset", "UndefinedInstruction", "SupervisorCall", "PrefetchAbort",
        "DataAbort", "Reserved", "IRQ", "FIQ"
    };
    private static final Pattern HASH = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern ADDRESS = Pattern.compile("0x[0-9a-f]{8}");
    private static final Pattern DECIMAL = Pattern.compile("0|[1-9][0-9]*");

    private ExceptionRootsSupport() {}

    static final class RootError extends RuntimeException {
        private static final long serialVersionUID = 1L;

        RootError(String message) {
            super(message);
        }

        RootError(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static final class Image {
        final String label;
        final String tocName;
        final long base;
        final long size;
        final String blake3;

        Image(String label, String tocName, long base, long size, String blake3) {
            this.label = label;
            this.tocName = tocName;
            this.base = base;
            this.size = size;
            this.blake3 = blake3;
        }
    }

    static final class RuntimeInfo {
        final String scatterBlake3;
        final List<Long> scatterEntriesUsed;

        RuntimeInfo(String scatterBlake3, List<Long> scatterEntriesUsed) {
            this.scatterBlake3 = scatterBlake3;
            this.scatterEntriesUsed = scatterEntriesUsed;
        }
    }

    static final class StorageSpan {
        final String kind;
        final long address;
        final long size;
        final Long scatterEntry;

        StorageSpan(String kind, long address, long size, Long scatterEntry) {
            this.kind = kind;
            this.address = address;
            this.size = size;
            this.scatterEntry = scatterEntry;
        }

        boolean same(StorageSpan other) {
            return kind.equals(other.kind) && address == other.address && size == other.size
                    && java.util.Objects.equals(scatterEntry, other.scatterEntry);
        }
    }

    static final class Literal {
        final long address;
        final String blake3;
        final List<StorageSpan> storage;

        Literal(long address, String blake3, List<StorageSpan> storage) {
            this.address = address;
            this.blake3 = blake3;
            this.storage = storage;
        }
    }

    static final class Slot {
        final int index;
        final String role;
        final long address;
        final String form;
        final String slotBlake3;
        final List<StorageSpan> slotStorage;
        final Literal literal;
        final long entry;
        final String isa;
        final int instructionSize;
        final String instructionBlake3;
        final List<StorageSpan> instructionStorage;

        Slot(int index, String role, long address, String form, String slotBlake3,
                List<StorageSpan> slotStorage, Literal literal, long entry, String isa,
                int instructionSize, String instructionBlake3,
                List<StorageSpan> instructionStorage) {
            this.index = index;
            this.role = role;
            this.address = address;
            this.form = form;
            this.slotBlake3 = slotBlake3;
            this.slotStorage = slotStorage;
            this.literal = literal;
            this.entry = entry;
            this.isa = isa;
            this.instructionSize = instructionSize;
            this.instructionBlake3 = instructionBlake3;
            this.instructionStorage = instructionStorage;
        }
    }

    static final class Table {
        final String kind;
        final long address;
        final String blake3;
        final List<StorageSpan> storage;
        final List<Slot> slots;

        Table(String kind, long address, String blake3, List<StorageSpan> storage,
                List<Slot> slots) {
            this.kind = kind;
            this.address = address;
            this.blake3 = blake3;
            this.storage = storage;
            this.slots = slots;
        }
    }

    static final class Claim {
        final String tableKind;
        final long tableAddress;
        final long slotAddress;
        final String role;

        Claim(String tableKind, long tableAddress, long slotAddress, String role) {
            this.tableKind = tableKind;
            this.tableAddress = tableAddress;
            this.slotAddress = slotAddress;
            this.role = role;
        }

        boolean same(Claim other) {
            return tableKind.equals(other.tableKind) && tableAddress == other.tableAddress
                    && slotAddress == other.slotAddress && role.equals(other.role);
        }
    }

    static final class Root {
        final long entry;
        final String isa;
        final int instructionSize;
        final String instructionBlake3;
        final List<StorageSpan> storage;
        final List<Claim> claims;

        Root(long entry, String isa, int instructionSize, String instructionBlake3,
                List<StorageSpan> storage, List<Claim> claims) {
            this.entry = entry;
            this.isa = isa;
            this.instructionSize = instructionSize;
            this.instructionBlake3 = instructionBlake3;
            this.storage = storage;
            this.claims = claims;
        }
    }

    static final class Application {
        final long entry;
        final String isa;
        final String desiredPrimary;
        final List<Claim> claims;
        final List<String> roleLabels;

        Application(long entry, String isa, String desiredPrimary, List<Claim> claims,
                List<String> roleLabels) {
            this.entry = entry;
            this.isa = isa;
            this.desiredPrimary = desiredPrimary;
            this.claims = claims;
            this.roleLabels = roleLabels;
        }
    }

    static final class VbarEvidence {
        final long pc;
        final String isa;
        final int sourceRegister;
        final boolean conditional;
        final Long exactValue;
        final List<Long> definitions;
        final boolean dominatesHandoffs;

        VbarEvidence(long pc, String isa, int sourceRegister, boolean conditional,
                Long exactValue, List<Long> definitions, boolean dominatesHandoffs) {
            this.pc = pc;
            this.isa = isa;
            this.sourceRegister = sourceRegister;
            this.conditional = conditional;
            this.exactValue = exactValue;
            this.definitions = definitions;
            this.dominatesHandoffs = dominatesHandoffs;
        }

        boolean same(VbarEvidence other) {
            return pc == other.pc && isa.equals(other.isa)
                    && sourceRegister == other.sourceRegister
                    && conditional == other.conditional
                    && java.util.Objects.equals(exactValue, other.exactValue)
                    && definitions.equals(other.definitions)
                    && dominatesHandoffs == other.dominatesHandoffs;
        }
    }

    static final class HandoffEvidence {
        final long pc;
        final String kind;

        HandoffEvidence(long pc, String kind) {
            this.pc = pc;
            this.kind = kind;
        }
    }

    static final class Relocation {
        final String status;
        final VbarEvidence selected;
        final Long tableAddress;
        final List<VbarEvidence> observations;
        final List<HandoffEvidence> handoffs;
        final String reason;

        Relocation(String status, VbarEvidence selected, Long tableAddress,
                List<VbarEvidence> observations, List<HandoffEvidence> handoffs,
                String reason) {
            this.status = status;
            this.selected = selected;
            this.tableAddress = tableAddress;
            this.observations = observations;
            this.handoffs = handoffs;
            this.reason = reason;
        }
    }

    static final class Manifest {
        final String toolVersion;
        final Image image;
        final RuntimeInfo runtime;
        final Table initialTable;
        final Relocation relocation;
        final List<Table> tables;
        final List<Root> roots;
        final List<Application> applications;
        String manifestBlake3;

        Manifest(String toolVersion, Image image, RuntimeInfo runtime, Table initialTable,
                Relocation relocation, List<Table> tables, List<Root> roots,
                List<Application> applications) {
            this.toolVersion = toolVersion;
            this.image = image;
            this.runtime = runtime;
            this.initialTable = initialTable;
            this.relocation = relocation;
            this.tables = tables;
            this.roots = roots;
            this.applications = applications;
        }
    }

    static final class RegistryEntry {
        final String manifestBlake3;
        final long entry;
        final String isa;
        final String instructionBlake3;
        final long functionId;
        final String functionDisposition;
        final String primaryDisposition;
        final Long primaryId;
        final String primarySource;
        final String primaryNameBlake3;
        final String transitionAuthority;
        final String transitionOriginalPrimaryBlake3;
        final List<Long> labelIds;
        final String labelsBlake3;

        RegistryEntry(String manifestBlake3, long entry, String isa,
                String instructionBlake3, long functionId, String functionDisposition,
                String primaryDisposition, Long primaryId, String primarySource,
                String primaryNameBlake3, String transitionAuthority,
                String transitionOriginalPrimaryBlake3, List<Long> labelIds,
                String labelsBlake3) {
            this.manifestBlake3 = manifestBlake3;
            this.entry = entry;
            this.isa = isa;
            this.instructionBlake3 = instructionBlake3;
            this.functionId = functionId;
            this.functionDisposition = functionDisposition;
            this.primaryDisposition = primaryDisposition;
            this.primaryId = primaryId;
            this.primarySource = primarySource;
            this.primaryNameBlake3 = primaryNameBlake3;
            this.transitionAuthority = transitionAuthority;
            this.transitionOriginalPrimaryBlake3 = transitionOriginalPrimaryBlake3;
            this.labelIds = labelIds;
            this.labelsBlake3 = labelsBlake3;
        }
    }

    static final class Plan {
        final Application application;
        final Root root;
        final RegistryEntry prior;
        final String freshPrimaryDisposition;

        Plan(Application application, Root root, RegistryEntry prior,
                String freshPrimaryDisposition) {
            this.application = application;
            this.root = root;
            this.prior = prior;
            this.freshPrimaryDisposition = freshPrimaryDisposition;
        }
    }

    static final class ScatterEntry {
        final int index;
        final long source;
        final long destination;
        final long size;
        final String operation;
        final String materialization;
        final String outputBlake3;
        final PmeScriptSupport.TrustedFile payload;

        ScatterEntry(int index, long source, long destination, long size, String operation,
                String materialization, String outputBlake3,
                PmeScriptSupport.TrustedFile payload) {
            this.index = index;
            this.source = source;
            this.destination = destination;
            this.size = size;
            this.operation = operation;
            this.materialization = materialization;
            this.outputBlake3 = outputBlake3;
            this.payload = payload;
        }

        long end() {
            return destination + size;
        }
    }

    static final class ScatterMap implements AutoCloseable {
        final PmeScriptSupport.TrustedFile manifestFile;
        final List<ScatterEntry> entries;
        private boolean closed;

        ScatterMap(PmeScriptSupport.TrustedFile manifestFile, List<ScatterEntry> entries) {
            this.manifestFile = manifestFile;
            this.entries = entries;
        }

        ScatterEntry containing(long address) {
            for (ScatterEntry entry : entries) {
                if (!"none".equals(entry.materialization)
                        && address >= entry.destination && address < entry.end()) {
                    return entry;
                }
            }
            return null;
        }

        @Override
        public void close() throws Exception {
            if (closed) return;
            closed = true;
            Throwable failure = null;
            for (int index = entries.size() - 1; index >= 0; index--) {
                PmeScriptSupport.TrustedFile payload = entries.get(index).payload;
                if (payload == null) continue;
                try {
                    payload.close();
                }
                catch (Throwable error) {
                    if (failure == null) failure = error;
                    else suppress(failure, error);
                }
            }
            try {
                manifestFile.close();
            }
            catch (Throwable error) {
                if (failure == null) failure = error;
                else suppress(failure, error);
            }
            if (failure != null) rethrow(failure);
        }
    }

    static final class Validated implements AutoCloseable {
        final Manifest manifest;
        final String identity;
        final Register tMode;
        final List<Plan> plans;
        private final PmeScriptSupport.TrustedFile manifestFile;
        private final PmeScriptSupport.TrustedFile rawFile;
        private final ScatterMap scatterMap;
        private boolean closed;

        Validated(Manifest manifest, String identity, Register tMode, List<Plan> plans,
                PmeScriptSupport.TrustedFile manifestFile,
                PmeScriptSupport.TrustedFile rawFile, ScatterMap scatterMap) {
            this.manifest = manifest;
            this.identity = identity;
            this.tMode = tMode;
            this.plans = plans;
            this.manifestFile = manifestFile;
            this.rawFile = rawFile;
            this.scatterMap = scatterMap;
        }

        void verifyRetainedFiles() {
            manifestFile.verifyPathIdentity("exception-root manifest");
            rawFile.verifyPathIdentity("exception-root raw image");
            if (scatterMap != null) {
                scatterMap.manifestFile.verifyPathIdentity("exception-root scatter map");
                for (ScatterEntry entry : scatterMap.entries) {
                    if (entry.payload != null) {
                        entry.payload.verifyPathIdentity(
                                "exception-root scatter payload " + entry.index);
                    }
                }
            }
        }

        @Override
        public void close() throws Exception {
            if (closed) return;
            closed = true;
            Throwable failure = null;
            if (scatterMap != null) {
                try {
                    scatterMap.close();
                }
                catch (Throwable error) {
                    failure = error;
                }
            }
            try {
                rawFile.close();
            }
            catch (Throwable error) {
                if (failure == null) failure = error;
                else suppress(failure, error);
            }
            try {
                manifestFile.close();
            }
            catch (Throwable error) {
                if (failure == null) failure = error;
                else suppress(failure, error);
            }
            if (failure != null) rethrow(failure);
        }
    }

    static final class AppliedState {
        final int sharedEntries;

        AppliedState(int sharedEntries) {
            this.sharedEntries = sharedEntries;
        }
    }

    // ---------------------------------------------------------------------
    // Public strict-preflight boundary
    // ---------------------------------------------------------------------

    static Validated preflight(Program program, TaskMonitor monitor, File kitRootArgument,
            String expectedLabel, File manifestArgument, String scatterArgument,
            String expectedIdentity) throws Exception {
        PmeScriptSupport.assertGhidraSymbolLimit();
        File kitRoot = PmeScriptSupport.requireCanonicalDirectory(
                kitRootArgument, "exception-root kit root");
        PmeScriptSupport.TrustedFile manifestFile = null;
        PmeScriptSupport.TrustedFile rawFile = null;
        ScatterMap scatterMap = null;
        try {
            manifestFile = PmeScriptSupport.openCanonicalContainedFile(
                    kitRoot, manifestArgument, "exception-root manifest");
            byte[] manifestBytes = manifestFile.readAll(
                    MAX_MANIFEST_BYTES, "exception-root manifest");
            String text = PmeScriptSupport.decodeUtf8(manifestBytes, "exception-root manifest");
            Manifest manifest = parseManifest(text);
            byte[] canonical = PmeScriptSupport.canonicalJsonBytes(
                    text, "exception-root manifest");
            if (!Arrays.equals(canonical, manifestBytes)) {
                fail("exception-root manifest bytes are not in canonical field order or JSON spelling");
            }
            String manifestHash = PmeScriptSupport.blake3Hex(manifestBytes);
            manifest.manifestBlake3 = manifestHash;
            validateManifestSemantics(manifest);

            if (!expectedLabel.equals(manifest.image.label)
                    || !expectedLabel.equals(program.getName())) {
                fail("exception-root image label does not match the current program");
            }
            String identity = identity(manifest);
            if (!identity.equals(expectedIdentity)) {
                fail("exception-root identity does not match the expected current run");
            }
            rawFile = PmeScriptSupport.openContainedChild(kitRoot,
                    "images/" + expectedLabel, "exception-root raw image");
            if (rawFile.size() != manifest.image.size
                    || !rawFile.blake3("exception-root raw image").equals(manifest.image.blake3)) {
                fail("exception-root raw image identity does not match the manifest");
            }
            if (manifest.runtime.scatterBlake3 == null) {
                if (!"-".equals(scatterArgument)
                        || !manifest.runtime.scatterEntriesUsed.isEmpty()) {
                    fail("raw-only exception roots require the explicit '-' scatter sentinel");
                }
            }
            else {
                if ("-".equals(scatterArgument)) {
                    fail("scatter-backed exception roots require a scatter map argument");
                }
                scatterMap = readScatterMap(program, monitor, kitRoot,
                        new File(scatterArgument), manifest.runtime.scatterBlake3,
                        manifest.image, rawFile);
            }
            validateProgramImage(program, monitor, manifest, rawFile);
            validateRuntimeEvidence(program, manifest, rawFile, scatterMap);
            Register tMode = program.getLanguage().getRegister("TMode");
            if (tMode == null) {
                fail("the current language has no TMode register");
            }
            validatePseudoInstructions(program, manifest, rawFile, scatterMap, tMode);
            List<Plan> plans = preflightProgramState(program, manifest, tMode);
            manifestFile.verifyPathIdentity("exception-root manifest");
            rawFile.verifyPathIdentity("exception-root raw image");
            if (scatterMap != null) {
                scatterMap.manifestFile.verifyPathIdentity("exception-root scatter map");
            }
            return new Validated(manifest, identity, tMode, plans,
                    manifestFile, rawFile, scatterMap);
        }
        catch (Throwable error) {
            closeQuietly(scatterMap, error);
            closeQuietly(rawFile, error);
            closeQuietly(manifestFile, error);
            rethrow(error);
            return null;
        }
    }

    static String identity(Manifest manifest) {
        return IDENTITY_VERSION + ":" + manifest.manifestBlake3 + ":"
                + manifest.tables.size() + ":" + manifest.roots.size();
    }

    // ---------------------------------------------------------------------
    // Strict wire parser
    // ---------------------------------------------------------------------

    static Manifest parseManifest(String text) {
        try {
            JsonReader reader = new JsonReader(new StringReader(text));
            reader.setStrictness(Strictness.STRICT);
            reader.beginObject();
            name(reader, "format");
            exact(reader, FORMAT, "format");
            name(reader, "schema_version");
            exactLong(reader, 1, "schema_version");
            name(reader, "tool_version");
            String toolVersion = printable(stringValue(reader, "tool_version"),
                    128, "tool_version");
            name(reader, "image");
            Image image = readImage(reader);
            name(reader, "runtime");
            RuntimeInfo runtime = readRuntime(reader);
            name(reader, "decoder");
            readDecoder(reader);
            name(reader, "initial_table");
            Table initialTable = readTable(reader);
            name(reader, "relocation");
            Relocation relocation = readRelocation(reader);
            name(reader, "tables");
            List<Table> tables = readArray(reader, MAX_TABLES,
                    ExceptionRootsSupport::readTable, "tables");
            name(reader, "roots");
            List<Root> roots = readArray(reader, MAX_ROOTS,
                    ExceptionRootsSupport::readRoot, "roots");
            name(reader, "applications");
            List<Application> applications = readArray(reader, MAX_ROOTS,
                    ExceptionRootsSupport::readApplication, "applications");
            reader.endObject();
            if (reader.peek() != JsonToken.END_DOCUMENT) {
                fail("exception-root manifest has trailing JSON");
            }
            return new Manifest(toolVersion, image, runtime, initialTable, relocation,
                    tables, roots, applications);
        }
        catch (RootError error) {
            throw error;
        }
        catch (Exception error) {
            throw new RootError("malformed exception-root manifest", error);
        }
    }

    private static final class ScatterWire {
        final String label;
        final long base;
        final long size;
        final String imageBlake3;
        final long loader;
        final long literalPair;
        final long tableStart;
        final long tableEnd;
        final long nullHandler;
        final long copyHandler;
        final long decompressHandler;
        final long zeroHandler;
        final List<ScatterWireEntry> entries;

        ScatterWire(String label, long base, long size, String imageBlake3, long loader,
                long literalPair, long tableStart, long tableEnd, long nullHandler,
                long copyHandler, long decompressHandler, long zeroHandler,
                List<ScatterWireEntry> entries) {
            this.label = label;
            this.base = base;
            this.size = size;
            this.imageBlake3 = imageBlake3;
            this.loader = loader;
            this.literalPair = literalPair;
            this.tableStart = tableStart;
            this.tableEnd = tableEnd;
            this.nullHandler = nullHandler;
            this.copyHandler = copyHandler;
            this.decompressHandler = decompressHandler;
            this.zeroHandler = zeroHandler;
            this.entries = entries;
        }
    }

    private static final class ScatterWireEntry {
        final int index;
        final long source;
        final long destination;
        final long size;
        final long handler;
        final String operation;
        final Long compressedSize;
        final String outputBlake3;
        final String materialization;
        final String path;
        final Long materializedSize;

        ScatterWireEntry(int index, long source, long destination, long size, long handler,
                String operation, Long compressedSize, String outputBlake3,
                String materialization, String path, Long materializedSize) {
            this.index = index;
            this.source = source;
            this.destination = destination;
            this.size = size;
            this.handler = handler;
            this.operation = operation;
            this.compressedSize = compressedSize;
            this.outputBlake3 = outputBlake3;
            this.materialization = materialization;
            this.path = path;
            this.materializedSize = materializedSize;
        }
    }

    private static ScatterMap readScatterMap(Program program, TaskMonitor monitor, File kitRoot,
            File scatterArgument, String expectedBlake3, Image image,
            PmeScriptSupport.TrustedFile rawFile) throws Exception {
        PmeScriptSupport.TrustedFile mapFile = null;
        List<ScatterEntry> entries = new ArrayList<ScatterEntry>();
        List<PmeScriptSupport.TrustedFile> openedPayloads =
                new ArrayList<PmeScriptSupport.TrustedFile>();
        try {
            mapFile = PmeScriptSupport.openCanonicalContainedFile(
                    kitRoot, scatterArgument, "exception-root scatter map");
            byte[] mapBytes = mapFile.readAll(
                    4 * 1024 * 1024, "exception-root scatter map");
            if (!PmeScriptSupport.blake3Hex(mapBytes).equals(expectedBlake3)) {
                fail("exception-root scatter-map BLAKE3 does not match the manifest");
            }
            String text = PmeScriptSupport.decodeUtf8(
                    mapBytes, "exception-root scatter map");
            ScatterWire wire = parseScatterMap(text);
            if (!wire.label.equals(image.label) || wire.base != image.base
                    || wire.size != image.size || !wire.imageBlake3.equals(image.blake3)) {
                fail("exception-root scatter map names a different raw image");
            }
            requireInImage(image, wire.loader, 16, "scatter loader");
            requireInImage(image, wire.literalPair, 8, "scatter loader literal pair");
            if (wire.tableStart > wire.tableEnd
                    || wire.tableEnd - wire.tableStart != wire.entries.size() * 16L) {
                fail("scatter table bounds do not match the entry count");
            }
            requireInImage(image, wire.tableStart, wire.tableEnd - wire.tableStart,
                    "scatter descriptor table");
            Set<Long> handlers = new HashSet<Long>(Arrays.asList(wire.nullHandler,
                    wire.copyHandler, wire.decompressHandler, wire.zeroHandler));
            if (handlers.size() != 4) fail("scatter handlers are not four distinct addresses");
            for (long handler : handlers) {
                requireInImage(image, handler & 0xffff_fffeL, 1, "scatter handler");
            }

            File parent = PmeScriptSupport.requireCanonicalDirectory(
                    mapFile.path().getParentFile(), "exception-root scatter directory");
            long logicalOutput = 0;
            List<ScatterWireEntry> destinations = new ArrayList<ScatterWireEntry>();
            for (int position = 0; position < wire.entries.size(); position++) {
                ScatterWireEntry entry = wire.entries.get(position);
                if (entry.index != position) {
                    fail("scatter entry index does not match its array position");
                }
                long expectedHandler;
                switch (entry.operation) {
                    case "null": expectedHandler = wire.nullHandler; break;
                    case "copy": expectedHandler = wire.copyHandler; break;
                    case "decompress1": expectedHandler = wire.decompressHandler; break;
                    case "zero": expectedHandler = wire.zeroHandler; break;
                    default: fail("unknown scatter operation"); return null;
                }
                if (entry.handler != expectedHandler) {
                    fail("scatter entry handler does not match its operation");
                }
                byte[] descriptor = readRaw(rawFile, image,
                        wire.tableStart + position * 16L, 16);
                ByteBuffer words = ByteBuffer.wrap(descriptor).order(ByteOrder.LITTLE_ENDIAN);
                if (Integer.toUnsignedLong(words.getInt()) != entry.source
                        || Integer.toUnsignedLong(words.getInt()) != entry.destination
                        || Integer.toUnsignedLong(words.getInt()) != entry.size
                        || Integer.toUnsignedLong(words.getInt()) != entry.handler) {
                    fail("scatter entry does not match its authenticated raw descriptor");
                }

                PmeScriptSupport.TrustedFile payload = null;
                if ("null".equals(entry.operation)) {
                    if (entry.size != 0 || !"none".equals(entry.materialization)
                            || entry.outputBlake3 != null || entry.compressedSize != null) {
                        fail("null scatter entry has output state");
                    }
                }
                else {
                    if (entry.size == 0 || entry.destination == 0
                            || entry.destination > PmeScriptSupport.UINT32_END - entry.size) {
                        fail("scatter output range is empty or wraps");
                    }
                    logicalOutput = Math.addExact(logicalOutput, entry.size);
                    if (logicalOutput > MAX_SCATTER_OUTPUT_BYTES) {
                        fail("scatter logical output exceeds its limit");
                    }
                    destinations.add(entry);
                    if (entry.outputBlake3 == null) {
                        fail("non-null scatter entry has no output BLAKE3");
                    }
                    if ("decompress1".equals(entry.operation)) {
                        if (entry.compressedSize == null || entry.compressedSize == 0) {
                            fail("decompress scatter entry has no compressed size");
                        }
                        requireInImage(image, entry.source, entry.compressedSize,
                                "scatter compressed source");
                    }
                    else if (entry.compressedSize != null) {
                        fail("non-decompress scatter entry has a compressed size");
                    }
                    if ("copy".equals(entry.operation)) {
                        requireInImage(image, entry.source, entry.size,
                                "scatter copy source");
                    }
                    if (rangesOverlap(entry.destination, entry.destination + entry.size,
                            image.base, image.base + image.size)
                            && !"none".equals(entry.materialization)) {
                        fail("materialized scatter output overlaps the raw image");
                    }

                    if ("file".equals(entry.materialization)) {
                        if (entry.path == null || entry.materializedSize == null
                                || entry.materializedSize != entry.size
                                || !entry.path.matches("blocks/[A-Za-z0-9._-]+")) {
                            fail("scatter file materialization is not canonical");
                        }
                        payload = PmeScriptSupport.openContainedChild(
                                parent, entry.path, "exception-root scatter payload");
                        openedPayloads.add(payload);
                        if (payload.size() != entry.size
                                || !payload.blake3("exception-root scatter payload")
                                        .equals(entry.outputBlake3)) {
                            fail("scatter payload identity does not match the load map");
                        }
                        if ("copy".equals(entry.operation)) {
                            byte[] source = readRaw(rawFile, image, entry.source, (int) entry.size);
                            byte[] output = payload.readAll(
                                    entry.size, "exception-root scatter copy payload");
                            if (!Arrays.equals(source, output)) {
                                fail("scatter copy payload differs from its raw source");
                            }
                        }
                    }
                    else if ("zero_fill".equals(entry.materialization)) {
                        if (!"zero".equals(entry.operation)
                                && !"decompress1".equals(entry.operation)) {
                            fail("scatter zero-fill materialization has an invalid operation");
                        }
                        if (!hashZeros(entry.size).equals(entry.outputBlake3)) {
                            fail("scatter zero-fill BLAKE3 does not match its size");
                        }
                    }
                    else if ("none".equals(entry.materialization)) {
                        if (!"copy".equals(entry.operation)
                                || entry.source != entry.destination
                                || !PmeScriptSupport.blake3Hex(readRaw(rawFile, image,
                                        entry.source, (int) entry.size))
                                        .equals(entry.outputBlake3)) {
                            fail("scatter none materialization is not an exact self-copy");
                        }
                    }
                    else {
                        fail("unknown scatter materialization");
                    }
                }
                entries.add(new ScatterEntry(entry.index, entry.source, entry.destination,
                        entry.size, entry.operation, entry.materialization,
                        entry.outputBlake3, payload));
                if (!"null".equals(entry.operation)) {
                    String current = hashMemory(program, monitor,
                            PmeScriptSupport.programAddress(program, entry.destination),
                            entry.size, "scatter output memory");
                    if (!current.equals(entry.outputBlake3)) {
                        fail("current scatter output memory does not match the load map");
                    }
                }
            }
            destinations.sort(Comparator.comparingLong(entry -> entry.destination));
            for (int index = 1; index < destinations.size(); index++) {
                ScatterWireEntry previous = destinations.get(index - 1);
                ScatterWireEntry current = destinations.get(index);
                if (rangesOverlap(previous.destination, previous.destination + previous.size,
                        current.destination, current.destination + current.size)) {
                    fail("scatter destination ranges overlap");
                }
            }
            mapFile.verifyPathIdentity("exception-root scatter map");
            for (ScatterEntry entry : entries) {
                if (entry.payload != null) {
                    entry.payload.verifyPathIdentity(
                            "exception-root scatter payload " + entry.index);
                }
            }
            return new ScatterMap(mapFile, Collections.unmodifiableList(entries));
        }
        catch (Throwable error) {
            for (int index = openedPayloads.size() - 1; index >= 0; index--) {
                closeQuietly(openedPayloads.get(index), error);
            }
            closeQuietly(mapFile, error);
            rethrow(error);
            return null;
        }
    }

    private static ScatterWire parseScatterMap(String text) {
        try {
            JsonReader reader = new JsonReader(new StringReader(text));
            reader.setStrictness(Strictness.STRICT);
            reader.beginObject();
            name(reader, "format");
            exact(reader, "pixel-modem-extractor-scatter-load-v1", "scatter format");
            name(reader, "schema_version");
            exactLong(reader, 1, "scatter schema_version");
            name(reader, "tool_version");
            printable(stringValue(reader, "scatter tool_version"),
                    128, "scatter tool_version");
            name(reader, "image");
            reader.beginObject();
            name(reader, "label");
            String label = printable(stringValue(reader, "scatter image label"),
                    128, "scatter image label");
            name(reader, "base_addr");
            long base = addressValue(reader, "scatter image base");
            name(reader, "size");
            long size = unsignedValue(reader, PmeScriptSupport.UINT32_MAX,
                    "scatter image size");
            name(reader, "blake3");
            String imageHash = hashValue(reader, "scatter image BLAKE3");
            reader.endObject();
            name(reader, "loader");
            reader.beginObject();
            name(reader, "address");
            long loader = addressValue(reader, "scatter loader address");
            name(reader, "literal_pair");
            long literal = addressValue(reader, "scatter literal pair");
            reader.endObject();
            name(reader, "table");
            reader.beginObject();
            name(reader, "start");
            long tableStart = addressValue(reader, "scatter table start");
            name(reader, "end");
            long tableEnd = addressValue(reader, "scatter table end");
            name(reader, "entry_count");
            int entryCount = (int) unsignedValue(reader, MAX_SCATTER_ENTRIES,
                    "scatter table entry_count");
            name(reader, "handlers");
            reader.beginObject();
            name(reader, "null");
            long nullHandler = addressValue(reader, "scatter null handler");
            name(reader, "copy");
            long copyHandler = addressValue(reader, "scatter copy handler");
            name(reader, "decompress1");
            long decompressHandler = addressValue(reader, "scatter decompress handler");
            name(reader, "zero");
            long zeroHandler = addressValue(reader, "scatter zero handler");
            reader.endObject();
            reader.endObject();
            name(reader, "entries");
            List<ScatterWireEntry> entries = readArray(reader, MAX_SCATTER_ENTRIES,
                    ExceptionRootsSupport::readScatterEntry, "scatter entries");
            reader.endObject();
            if (reader.peek() != JsonToken.END_DOCUMENT || entryCount != entries.size()) {
                fail("scatter entry_count does not match the entries array");
            }
            return new ScatterWire(label, base, size, imageHash, loader, literal,
                    tableStart, tableEnd, nullHandler, copyHandler, decompressHandler,
                    zeroHandler, entries);
        }
        catch (RootError error) {
            throw error;
        }
        catch (Exception error) {
            throw new RootError("malformed exception-root scatter map", error);
        }
    }

    private static ScatterWireEntry readScatterEntry(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "index");
        int index = (int) unsignedValue(reader, MAX_SCATTER_ENTRIES - 1,
                "scatter entry index");
        name(reader, "source");
        long source = addressValue(reader, "scatter entry source");
        name(reader, "destination");
        long destination = addressValue(reader, "scatter entry destination");
        name(reader, "size");
        long size = unsignedValue(reader, PmeScriptSupport.UINT32_MAX,
                "scatter entry size");
        name(reader, "handler");
        long handler = addressValue(reader, "scatter entry handler");
        name(reader, "operation");
        String operation = oneOf(stringValue(reader, "scatter entry operation"),
                "scatter entry operation",
                "null", "copy", "decompress1", "zero");
        Long compressedSize = null;
        if ("decompress1".equals(operation)) {
            name(reader, "compressed_size");
            compressedSize = unsignedValue(reader, PmeScriptSupport.UINT32_MAX,
                    "scatter entry compressed_size");
        }
        String outputBlake3 = null;
        if (!"null".equals(operation)) {
            name(reader, "output_blake3");
            outputBlake3 = hashValue(reader, "scatter entry output_blake3");
        }
        name(reader, "materialization");
        reader.beginObject();
        name(reader, "kind");
        String materialization = oneOf(stringValue(reader, "scatter materialization kind"),
                "scatter materialization kind",
                "none", "zero_fill", "file");
        String path = null;
        Long materializedSize = null;
        if ("file".equals(materialization)) {
            name(reader, "path");
            path = printable(stringValue(reader, "scatter payload path"),
                    1024, "scatter payload path");
            name(reader, "size");
            materializedSize = unsignedValue(reader, PmeScriptSupport.UINT32_MAX,
                    "scatter materialized size");
        }
        reader.endObject();
        reader.endObject();
        return new ScatterWireEntry(index, source, destination, size, handler, operation,
                compressedSize, outputBlake3, materialization, path, materializedSize);
    }

    private static Image readImage(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "label");
        String label = printable(stringValue(reader, "image.label"), 128, "image.label");
        name(reader, "toc_name");
        String toc = printable(stringValue(reader, "image.toc_name"), 128, "image.toc_name");
        name(reader, "base_addr");
        long base = addressValue(reader, "image.base_addr");
        name(reader, "size");
        long size = unsignedValue(reader, PmeScriptSupport.UINT32_MAX, "image.size");
        name(reader, "blake3");
        String blake3 = hashValue(reader, "image.blake3");
        reader.endObject();
        return new Image(label, toc, base, size, blake3);
    }

    private static RuntimeInfo readRuntime(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "scatter_load_map_blake3");
        String scatter = nullableHash(reader, "runtime.scatter_load_map_blake3");
        name(reader, "scatter_entries_used");
        List<Long> entries = readLongArray(reader, 256,
                PmeScriptSupport.UINT32_MAX, "runtime.scatter_entries_used");
        reader.endObject();
        return new RuntimeInfo(scatter, entries);
    }

    private static void readDecoder(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "semantic_adapter");
        exact(reader, SEMANTIC_ADAPTER, "decoder.semantic_adapter");
        name(reader, "crate");
        exact(reader, BACKEND_CRATE, "decoder.crate");
        name(reader, "version");
        exact(reader, BACKEND_VERSION, "decoder.version");
        reader.endObject();
    }

    private static Table readTable(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "kind");
        String kind = oneOf(stringValue(reader, "table.kind"),
                "table.kind", "initial", "relocated");
        name(reader, "address");
        long address = addressValue(reader, "table.address");
        name(reader, "blake3");
        String blake3 = hashValue(reader, "table.blake3");
        name(reader, "storage");
        List<StorageSpan> storage = readStorage(reader, "table.storage");
        name(reader, "slots");
        List<Slot> slots = readArray(reader, SLOTS_PER_TABLE,
                ExceptionRootsSupport::readSlot, "table.slots");
        reader.endObject();
        return new Table(kind, address, blake3, storage, slots);
    }

    private static Slot readSlot(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "index");
        int index = (int) unsignedValue(reader, 7, "slot.index");
        name(reader, "role");
        String role = role(stringValue(reader, "slot.role"), "slot.role");
        name(reader, "address");
        long address = addressValue(reader, "slot.address");
        name(reader, "form");
        String form = oneOf(stringValue(reader, "slot.form"), "slot.form",
                "direct_branch", "literal_load");
        name(reader, "slot_blake3");
        String slotBlake3 = hashValue(reader, "slot.slot_blake3");
        name(reader, "slot_storage");
        List<StorageSpan> slotStorage = readStorage(reader, "slot.slot_storage");
        name(reader, "literal");
        Literal literal = readNullableLiteral(reader);
        name(reader, "entry");
        long entry = addressValue(reader, "slot.entry");
        name(reader, "isa");
        String isa = isa(stringValue(reader, "slot.isa"), "slot.isa");
        name(reader, "instruction_size");
        int instructionSize = (int) unsignedValue(reader, 4,
                "slot.instruction_size");
        name(reader, "instruction_blake3");
        String instructionBlake3 = hashValue(reader, "slot.instruction_blake3");
        name(reader, "instruction_storage");
        List<StorageSpan> instructionStorage = readStorage(
                reader, "slot.instruction_storage");
        reader.endObject();
        return new Slot(index, role, address, form, slotBlake3, slotStorage, literal,
                entry, isa, instructionSize, instructionBlake3, instructionStorage);
    }

    private static Literal readNullableLiteral(JsonReader reader) throws IOException {
        if (reader.peek() == JsonToken.NULL) {
            reader.nextNull();
            return null;
        }
        reader.beginObject();
        name(reader, "address");
        long address = addressValue(reader, "literal.address");
        name(reader, "blake3");
        String blake3 = hashValue(reader, "literal.blake3");
        name(reader, "storage");
        List<StorageSpan> storage = readStorage(reader, "literal.storage");
        reader.endObject();
        return new Literal(address, blake3, storage);
    }

    private static Relocation readRelocation(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "status");
        String status = oneOf(stringValue(reader, "relocation.status"),
                "relocation.status", "not_observed",
                "confirmed_initial", "relocated", "unresolved", "analysis_incomplete");
        name(reader, "selected");
        VbarEvidence selected = readNullableVbar(reader);
        name(reader, "table_address");
        Long tableAddress = nullableAddress(reader, "relocation.table_address");
        name(reader, "observations");
        List<VbarEvidence> observations = readArray(
                reader, MAX_VBAR_WRITES, ExceptionRootsSupport::readVbar,
                "relocation.observations");
        name(reader, "handoffs");
        List<HandoffEvidence> handoffs = readArray(
                reader, MAX_CFG_BLOCKS, ExceptionRootsSupport::readHandoff,
                "relocation.handoffs");
        name(reader, "reason");
        String reason = null;
        if (reader.peek() == JsonToken.NULL) {
            reader.nextNull();
        }
        else {
            reason = stringValue(reader, "relocation.reason");
            byte[] bytes = PmeScriptSupport.boundedUtf8(
                    reason, MAX_REASON_UTF8_BYTES, "relocation.reason");
            if (bytes.length == 0) fail("relocation.reason is empty");
            for (byte value : bytes) {
                int character = value & 0xff;
                if ((character != '\t' && (character < 0x20 || character > 0x7e))
                        || character == '/' || character == '\\') {
                    fail("relocation.reason is non-ASCII or path-bearing");
                }
            }
        }
        reader.endObject();
        return new Relocation(status, selected, tableAddress, observations, handoffs, reason);
    }

    private static VbarEvidence readVbar(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "pc");
        long pc = addressValue(reader, "vbar.pc");
        name(reader, "isa");
        String isa = isa(stringValue(reader, "vbar.isa"), "vbar.isa");
        name(reader, "source_register");
        int sourceRegister = (int) unsignedValue(reader, 15, "vbar.source_register");
        name(reader, "conditional");
        boolean conditional = booleanValue(reader, "vbar.conditional");
        name(reader, "exact_value");
        Long exactValue = nullableAddress(reader, "vbar.exact_value");
        name(reader, "definitions");
        List<Long> definitions = readAddressArray(
                reader, MAX_CFG_INSTRUCTIONS, "vbar.definitions");
        name(reader, "dominates_handoffs");
        boolean dominates = booleanValue(reader, "vbar.dominates_handoffs");
        reader.endObject();
        requireSortedUnique(definitions, "vbar.definitions");
        return new VbarEvidence(pc, isa, sourceRegister, conditional,
                exactValue, definitions, dominates);
    }

    private static VbarEvidence readNullableVbar(JsonReader reader) throws IOException {
        if (reader.peek() == JsonToken.NULL) {
            reader.nextNull();
            return null;
        }
        return readVbar(reader);
    }

    private static HandoffEvidence readHandoff(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "pc");
        long pc = addressValue(reader, "handoff.pc");
        name(reader, "kind");
        String kind = oneOf(stringValue(reader, "handoff.kind"),
                "handoff.kind", "call", "return",
                "exception_call", "indirect", "unmapped", "decode_failure");
        reader.endObject();
        return new HandoffEvidence(pc, kind);
    }

    private static Root readRoot(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "entry");
        long entry = addressValue(reader, "root.entry");
        name(reader, "isa");
        String isa = isa(stringValue(reader, "root.isa"), "root.isa");
        name(reader, "instruction_size");
        int size = (int) unsignedValue(reader, 4, "root.instruction_size");
        name(reader, "instruction_blake3");
        String hash = hashValue(reader, "root.instruction_blake3");
        name(reader, "storage");
        List<StorageSpan> storage = readStorage(reader, "root.storage");
        name(reader, "claims");
        List<Claim> claims = readArray(reader, 16,
                ExceptionRootsSupport::readClaim, "root.claims");
        reader.endObject();
        return new Root(entry, isa, size, hash, storage, claims);
    }

    private static Application readApplication(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "entry");
        long entry = addressValue(reader, "application.entry");
        name(reader, "isa");
        String isa = isa(stringValue(reader, "application.isa"), "application.isa");
        name(reader, "desired_primary");
        String desired = null;
        if (reader.peek() == JsonToken.NULL) reader.nextNull();
        else desired = PmeScriptSupport.requireSymbolLeaf(
                stringValue(reader, "application.desired_primary"),
                MAX_SYMBOL_UTF8_BYTES, "application.desired_primary");
        name(reader, "claims");
        List<Claim> claims = readArray(reader, 16,
                ExceptionRootsSupport::readClaim, "application.claims");
        name(reader, "role_labels");
        List<String> labels = readStringArray(reader, 16, "application.role_labels");
        reader.endObject();
        return new Application(entry, isa, desired, claims, labels);
    }

    private static Claim readClaim(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "table_kind");
        String kind = oneOf(stringValue(reader, "claim.table_kind"),
                "claim.table_kind", "initial", "relocated");
        name(reader, "table_address");
        long table = addressValue(reader, "claim.table_address");
        name(reader, "slot_address");
        long slot = addressValue(reader, "claim.slot_address");
        name(reader, "role");
        String role = role(stringValue(reader, "claim.role"), "claim.role");
        reader.endObject();
        return new Claim(kind, table, slot, role);
    }

    private static List<StorageSpan> readStorage(JsonReader reader, String what)
            throws IOException {
        return readArray(reader, MAX_STORAGE_SPANS, input -> {
            input.beginObject();
            name(input, "kind");
            String kind = oneOf(stringValue(input, what + ".kind"), what + ".kind",
                    "raw", "scatter_bytes", "scatter_zero");
            name(input, "address");
            long address = addressValue(input, what + ".address");
            name(input, "size");
            long size = unsignedValue(input, PmeScriptSupport.UINT32_MAX,
                    what + ".size");
            name(input, "scatter_entry");
            Long entry = nullableUnsigned(input, PmeScriptSupport.UINT32_MAX,
                    what + ".scatter_entry");
            input.endObject();
            if ("scatter_zero".equals(kind)) {
                fail(what + " uses zero-fill as byte evidence");
            }
            return new StorageSpan(kind, address, size, entry);
        }, what);
    }

    @FunctionalInterface
    private interface ReaderFn<T> {
        T read(JsonReader reader) throws IOException;
    }

    private static <T> List<T> readArray(JsonReader reader, int maximum,
            ReaderFn<T> read, String what) throws IOException {
        List<T> values = new ArrayList<T>();
        reader.beginArray();
        while (reader.hasNext()) {
            if (values.size() >= maximum) fail(what + " exceeds its element ceiling");
            values.add(read.read(reader));
        }
        reader.endArray();
        return Collections.unmodifiableList(values);
    }

    private static List<Long> readLongArray(JsonReader reader, int maximum,
            long maximumValue, String what) throws IOException {
        return readArray(reader, maximum,
                input -> unsignedValue(input, maximumValue, what), what);
    }

    private static List<Long> readAddressArray(JsonReader reader, int maximum, String what)
            throws IOException {
        return readArray(reader, maximum, input -> addressValue(input, what), what);
    }

    private static List<String> readStringArray(JsonReader reader, int maximum, String what)
            throws IOException {
        return readArray(reader, maximum, input -> PmeScriptSupport.requireSymbolLeaf(
                stringValue(input, what), MAX_SYMBOL_UTF8_BYTES, what), what);
    }

    // ---------------------------------------------------------------------
    // Semantic and runtime validation
    // ---------------------------------------------------------------------

    private static void validateManifestSemantics(Manifest manifest) {
        if (manifest.image.size == 0
                || manifest.image.base > PmeScriptSupport.UINT32_END - manifest.image.size) {
            fail("exception-root image range is empty or wraps");
        }
        if (manifest.tables.isEmpty() || manifest.roots.isEmpty()
                || manifest.roots.size() != manifest.applications.size()) {
            fail("exception-root tables, roots, and applications do not conserve");
        }
        Table first = manifest.tables.get(0);
        if (!"initial".equals(first.kind) || first.address != manifest.image.base
                || !sameTable(first, manifest.initialTable)) {
            fail("initial_table is not the canonical first table at image base");
        }
        long priorTable = -1;
        boolean relocatedSeen = false;
        Map<String, Root> derived = new LinkedHashMap<String, Root>();
        Map<Long, String> isaByEntry = new HashMap<Long, String>();
        Set<Long> tableAddresses = new HashSet<Long>();
        for (int tableIndex = 0; tableIndex < manifest.tables.size(); tableIndex++) {
            Table table = manifest.tables.get(tableIndex);
            if (!tableAddresses.add(table.address)) {
                fail("exception-root tables contain duplicate addresses");
            }
            if ((tableIndex == 0 && !"initial".equals(table.kind))
                    || (tableIndex != 0 && !"relocated".equals(table.kind))
                    || (table.address & 3) != 0) {
                fail("exception-root tables are not in canonical kind/alignment order");
            }
            int kindOrder = "initial".equals(table.kind) ? 0 : 1;
            long key = ((long) kindOrder << 32) | table.address;
            if (key <= priorTable) fail("exception-root tables are not canonically ordered");
            priorTable = key;
            if ("relocated".equals(table.kind)) {
                if (relocatedSeen) fail("more than one relocated vector table is present");
                relocatedSeen = true;
            }
            if (table.slots.size() != SLOTS_PER_TABLE) {
                fail("each exception vector table must have exactly eight slots");
            }
            for (int index = 0; index < table.slots.size(); index++) {
                Slot slot = table.slots.get(index);
                if (slot.index != index || !slot.role.equals(ROLES[index])
                        || slot.address != table.address + index * 4L) {
                    fail("exception vector slot geometry or role order is not canonical");
                }
                if (("arm".equals(slot.isa) && slot.instructionSize != 4)
                        || ("thumb".equals(slot.isa)
                                && slot.instructionSize != 2
                                && slot.instructionSize != 4)) {
                    fail("exception root instruction size does not match its ISA");
                }
                if (("arm".equals(slot.isa) && (slot.entry & 3) != 0)
                        || ("thumb".equals(slot.isa) && (slot.entry & 1) != 0)) {
                    fail("exception root entry alignment does not match its ISA");
                }
                String priorIsa = isaByEntry.putIfAbsent(slot.entry, slot.isa);
                if (priorIsa != null && !priorIsa.equals(slot.isa)) {
                    fail("exception roots contain cross-ISA aliases at "
                            + canonicalAddress(slot.entry));
                }
                Claim claim = new Claim(table.kind, table.address, slot.address, slot.role);
                String rootKey = rootKey(slot.entry, slot.isa);
                Root prior = derived.get(rootKey);
                if (prior == null) {
                    List<Claim> claims = new ArrayList<Claim>();
                    claims.add(claim);
                    derived.put(rootKey, new Root(slot.entry, slot.isa, slot.instructionSize,
                            slot.instructionBlake3, slot.instructionStorage, claims));
                }
                else {
                    if (prior.instructionSize != slot.instructionSize
                            || !prior.instructionBlake3.equals(slot.instructionBlake3)
                            || !sameSpans(prior.storage, slot.instructionStorage)) {
                        fail("shared exception root carries inconsistent execution identity");
                    }
                    prior.claims.add(claim);
                }
            }
        }
        List<Root> expectedRoots = new ArrayList<Root>(derived.values());
        expectedRoots.sort(rootComparator());
        validateRequestedInstructionSpans(expectedRoots);
        if (expectedRoots.size() != manifest.roots.size()) {
            fail("exception roots do not equal the unique table targets");
        }
        Map<String, Integer> roleTargetCounts = new HashMap<String, Integer>();
        Map<String, Set<String>> rolesToTargets = new HashMap<String, Set<String>>();
        for (Root root : expectedRoots) {
            for (Claim claim : root.claims) {
                rolesToTargets.computeIfAbsent(claim.role, unused -> new HashSet<String>())
                        .add(rootKey(root.entry, root.isa));
            }
        }
        for (Map.Entry<String, Set<String>> entry : rolesToTargets.entrySet()) {
            roleTargetCounts.put(entry.getKey(), entry.getValue().size());
        }
        Set<String> primaryLeaves = new HashSet<String>();
        for (int index = 0; index < expectedRoots.size(); index++) {
            Root expected = expectedRoots.get(index);
            Root actual = manifest.roots.get(index);
            if (!sameRoot(expected, actual)) {
                fail("exception roots are not the canonical projection of table slots");
            }
            Application application = manifest.applications.get(index);
            if (application.entry != expected.entry || !application.isa.equals(expected.isa)
                    || !sameClaims(application.claims, expected.claims)) {
                fail("exception applications do not partition roots canonically");
            }
            List<String> expectedLabels = new ArrayList<String>();
            for (Claim claim : expected.claims) {
                expectedLabels.add(roleLabel(claim));
            }
            if (!application.roleLabels.equals(expectedLabels)) {
                fail("exception role labels do not match the strict allocator");
            }
            String expectedPrimary = null;
            Set<String> claimedRoles = new HashSet<String>();
            for (Claim claim : expected.claims) claimedRoles.add(claim.role);
            if (claimedRoles.size() == 1) {
                String claimedRole = claimedRoles.iterator().next();
                if (roleTargetCounts.get(claimedRole).intValue() == 1) {
                    expectedPrimary = primaryForRole(claimedRole);
                }
            }
            if (!java.util.Objects.equals(expectedPrimary, application.desiredPrimary)) {
                fail("exception preferred primary does not match the strict allocator");
            }
            if (expectedPrimary != null && !primaryLeaves.add(expectedPrimary)) {
                fail("exception preferred primaries are not globally unique");
            }
        }
        validateRelocation(manifest.relocation);
        if ("relocated".equals(manifest.relocation.status)) {
            if (manifest.tables.size() != 2
                    || manifest.relocation.tableAddress == null
                    || manifest.relocation.tableAddress.longValue()
                            != manifest.tables.get(1).address
                    || manifest.relocation.selected.exactValue == null
                    || manifest.relocation.selected.exactValue.longValue()
                            != manifest.tables.get(1).address) {
                fail("relocated evidence does not bind the relocated table");
            }
        }
        else if (manifest.tables.size() != 1) {
            fail("non-relocated evidence published a relocated table");
        }
        if ("confirmed_initial".equals(manifest.relocation.status)
                && (manifest.relocation.selected.exactValue == null
                        || manifest.relocation.selected.exactValue.longValue()
                                != manifest.initialTable.address)) {
            fail("confirmed-initial evidence does not bind the initial table");
        }
        if ("not_observed".equals(manifest.relocation.status)
                && manifest.tables.size() != 1) {
            fail("not_observed relocation cannot publish a relocated table");
        }
        requireSortedUnique(manifest.runtime.scatterEntriesUsed,
                "runtime.scatter_entries_used");
    }

    private static void validateRelocation(Relocation relocation) {
        long priorPc = -1;
        for (VbarEvidence observation : relocation.observations) {
            if (observation.pc <= priorPc) {
                fail("relocation observations are not strictly ordered by PC");
            }
            priorPc = observation.pc;
        }
        long priorHandoffPc = -1;
        int priorHandoffKind = -1;
        for (HandoffEvidence handoff : relocation.handoffs) {
            int kind = handoffKindOrder(handoff.kind);
            if (handoff.pc < priorHandoffPc
                    || handoff.pc == priorHandoffPc && kind <= priorHandoffKind) {
                fail("relocation handoffs are not strictly ordered and unique");
            }
            priorHandoffPc = handoff.pc;
            priorHandoffKind = kind;
        }
        if (relocation.selected != null) {
            boolean found = false;
            for (VbarEvidence observation : relocation.observations) {
                if (observation.same(relocation.selected)) found = true;
            }
            if (!found) fail("selected VBAR evidence is absent from observations");
        }
        boolean valid;
        switch (relocation.status) {
            case "confirmed_initial":
                valid = relocation.selected != null && relocation.tableAddress == null
                        && relocation.handoffs.isEmpty() && relocation.reason == null;
                break;
            case "relocated":
                valid = relocation.selected != null && relocation.tableAddress != null
                        && relocation.handoffs.isEmpty() && relocation.reason == null;
                break;
            case "unresolved":
                valid = relocation.selected == null && relocation.tableAddress == null
                        && relocation.handoffs.isEmpty() && relocation.reason == null;
                break;
            case "not_observed":
                valid = relocation.selected == null && relocation.tableAddress == null
                        && relocation.observations.isEmpty() && relocation.handoffs.isEmpty()
                        && relocation.reason == null;
                break;
            case "analysis_incomplete":
                valid = relocation.selected == null && relocation.tableAddress == null;
                break;
            default:
                valid = false;
        }
        if (!valid) fail("relocation status and variant fields are inconsistent");
    }

    private static int handoffKindOrder(String kind) {
        switch (kind) {
            case "call": return 0;
            case "return": return 1;
            case "exception_call": return 2;
            case "indirect": return 3;
            case "unmapped": return 4;
            case "decode_failure": return 5;
            default: fail("unknown handoff kind"); return -1;
        }
    }

    private static void validateProgramImage(Program program, TaskMonitor monitor,
            Manifest manifest, PmeScriptSupport.TrustedFile rawFile) throws Exception {
        Address base = PmeScriptSupport.programAddress(program, manifest.image.base);
        Address end = PmeScriptSupport.programAddress(program,
                manifest.image.base + manifest.image.size - 1);
        MemoryBlock block = program.getMemory().getBlock(base);
        if (block == null || !block.getStart().equals(base) || !block.getEnd().equals(end)
                || !block.isInitialized()) {
            fail("current program does not contain the exact raw image block");
        }
        String memoryHash = hashMemory(program, monitor, base, manifest.image.size,
                "raw image memory");
        if (!memoryHash.equals(manifest.image.blake3)) {
            fail("current raw-image memory does not match the manifest");
        }
        rawFile.verifyPathIdentity("exception-root raw image");
    }

    private static void validateRuntimeEvidence(Program program, Manifest manifest,
            PmeScriptSupport.TrustedFile rawFile, ScatterMap scatterMap) {
        Set<Long> usedEntries = new HashSet<Long>();
        for (Table table : manifest.tables) {
            validateRange(program, manifest.image, rawFile, scatterMap, table.address, 32,
                    table.blake3, table.storage, usedEntries, "exception vector table");
            for (Slot slot : table.slots) {
                byte[] wordBytes = validateRange(program, manifest.image, rawFile, scatterMap,
                        slot.address, 4, slot.slotBlake3, slot.slotStorage,
                        usedEntries, "exception vector slot");
                long word = Integer.toUnsignedLong(ByteBuffer.wrap(wordBytes)
                        .order(ByteOrder.LITTLE_ENDIAN).getInt());
                DecodedSlot decoded = decodeSlot(slot.address, word);
                if (!decoded.form.equals(slot.form)) {
                    fail("exception vector slot does not decode to its declared root");
                }
                if (decoded.literalAddress == null) {
                    if (slot.literal != null) fail("direct branch carries a literal record");
                    if (decoded.entry != slot.entry || !decoded.isa.equals(slot.isa)) {
                        fail("direct exception vector does not target its declared root");
                    }
                }
                else {
                    if (slot.literal == null
                            || decoded.literalAddress.longValue() != slot.literal.address) {
                        fail("literal vector slot does not carry its decoded literal address");
                    }
                    byte[] literalBytes = validateRange(program, manifest.image, rawFile,
                            scatterMap,
                            slot.literal.address, 4,
                            slot.literal.blake3, slot.literal.storage,
                            usedEntries, "exception vector literal");
                    long pointer = Integer.toUnsignedLong(ByteBuffer.wrap(literalBytes)
                            .order(ByteOrder.LITTLE_ENDIAN).getInt());
                    String literalIsa = (pointer & 1) == 0 ? "arm" : "thumb";
                    long literalEntry = pointer & 0xffff_fffeL;
                    if (literalEntry != slot.entry || !literalIsa.equals(slot.isa)) {
                        fail("literal exception vector does not target its declared root");
                    }
                }
                validateRange(program, manifest.image, rawFile, scatterMap, slot.entry,
                        slot.instructionSize, slot.instructionBlake3,
                        slot.instructionStorage, usedEntries, "exception root instruction");
            }
        }
        List<Long> actualUsed = new ArrayList<Long>(usedEntries);
        Collections.sort(actualUsed);
        if (!actualUsed.equals(manifest.runtime.scatterEntriesUsed)) {
            fail("runtime.scatter_entries_used does not equal the storage projection");
        }
    }

    private static void validatePseudoInstructions(Program program, Manifest manifest,
            PmeScriptSupport.TrustedFile rawFile, ScatterMap scatterMap, Register tMode) {
        PseudoDisassembler pseudo = new PseudoDisassembler(program);
        pseudo.setRespectExecuteFlag(false);
        for (Root root : manifest.roots) {
            byte[] bytes = readRuntime(rawFile, scatterMap,
                    manifest.image, root.entry, root.instructionSize);
            PseudoDisassemblerContext context =
                    new PseudoDisassemblerContext(program.getProgramContext());
            context.setValue(tMode, PmeScriptSupport.programAddress(program, root.entry),
                    "thumb".equals(root.isa) ? BigInteger.ONE : BigInteger.ZERO);
            try {
                PseudoInstruction instruction = pseudo.disassemble(
                        PmeScriptSupport.programAddress(program, root.entry), bytes, context);
                if (instruction == null || instruction.getParsedLength() != root.instructionSize
                        || !Arrays.equals(bytes, instruction.getParsedBytes())) {
                    fail("exception root does not predecode to its authenticated instruction");
                }
            }
            catch (Exception error) {
                throw new RootError("exception root predecode failed at "
                        + canonicalAddress(root.entry), error);
            }
        }
    }

    private static byte[] validateRange(Program program, Image image,
            PmeScriptSupport.TrustedFile rawFile, ScatterMap scatterMap, long address, int size,
            String expectedHash, List<StorageSpan> storage, Set<Long> usedEntries, String what) {
        byte[] runtime = readRuntime(rawFile, scatterMap, image, address, size);
        String actualHash = PmeScriptSupport.blake3Hex(runtime);
        if (!actualHash.equals(expectedHash)) fail(what + " hash does not match runtime bytes");
        List<StorageSpan> expected = runtimeSpans(scatterMap, image, address, size);
        if (!sameSpans(expected, storage)) fail(what + " storage projection is not exact");
        for (StorageSpan span : storage) {
            if (span.scatterEntry != null) usedEntries.add(span.scatterEntry);
        }
        byte[] memory = new byte[size];
        try {
            int read = program.getMemory().getBytes(PmeScriptSupport.programAddress(program, address),
                    memory, 0, size);
            if (read != size || !Arrays.equals(memory, runtime)) {
                fail(what + " current memory differs from authenticated runtime bytes");
            }
        }
        catch (MemoryAccessException error) {
            throw new RootError(what + " is not readable in current memory", error);
        }
        return runtime;
    }

    private static byte[] readRaw(PmeScriptSupport.TrustedFile rawFile, Image image,
            long address, int size) {
        if (size <= 0 || address < image.base
                || address > image.base + image.size - size) {
            fail("authenticated runtime range leaves the raw image");
        }
        try {
            return rawFile.readRange(address - image.base, size, "exception-root raw image");
        }
        catch (IOException error) {
            throw new RootError("exception-root raw range could not be read", error);
        }
    }

    private static byte[] readRuntime(PmeScriptSupport.TrustedFile rawFile,
            ScatterMap scatterMap, Image image, long address, int size) {
        if (size <= 0 || address > PmeScriptSupport.UINT32_END - size) {
            fail("authenticated runtime range is empty or wraps");
        }
        byte[] output = new byte[size];
        int written = 0;
        long cursor = address;
        while (written < size) {
            ScatterEntry scatter = scatterMap == null ? null : scatterMap.containing(cursor);
            int chunk;
            byte[] bytes;
            if (scatter != null) {
                chunk = (int) Math.min(size - written, scatter.end() - cursor);
                if ("zero_fill".equals(scatter.materialization)) {
                    bytes = new byte[chunk];
                }
                else if (scatter.payload != null) {
                    try {
                        bytes = scatter.payload.readRange(cursor - scatter.destination, chunk,
                                "exception-root scatter payload " + scatter.index);
                    }
                    catch (IOException error) {
                        throw new RootError("exception-root scatter payload could not be read",
                                error);
                    }
                }
                else {
                    fail("exception runtime resolves through an unmaterialized scatter entry");
                    return null;
                }
            }
            else {
                requireInImage(image, cursor, 1, "runtime byte");
                long rawEnd = image.base + image.size;
                long next = rawEnd;
                if (scatterMap != null) {
                    for (ScatterEntry entry : scatterMap.entries) {
                        if (!"none".equals(entry.materialization)
                                && entry.destination > cursor) {
                            next = Math.min(next, entry.destination);
                        }
                    }
                }
                chunk = (int) Math.min(size - written, next - cursor);
                bytes = readRaw(rawFile, image, cursor, chunk);
            }
            System.arraycopy(bytes, 0, output, written, chunk);
            cursor += chunk;
            written += chunk;
        }
        return output;
    }

    private static List<StorageSpan> runtimeSpans(ScatterMap scatterMap, Image image,
            long address, int size) {
        List<StorageSpan> spans = new ArrayList<StorageSpan>();
        long cursor = address;
        long end = address + size;
        while (cursor < end) {
            ScatterEntry scatter = scatterMap == null ? null : scatterMap.containing(cursor);
            if (scatter != null) {
                long spanEnd = Math.min(end, scatter.end());
                String kind = "zero_fill".equals(scatter.materialization)
                        ? "scatter_zero" : "scatter_bytes";
                spans.add(new StorageSpan(kind, cursor, spanEnd - cursor,
                        Long.valueOf(scatter.index)));
                cursor = spanEnd;
            }
            else {
                requireInImage(image, cursor, 1, "runtime storage byte");
                long spanEnd = Math.min(end, image.base + image.size);
                if (scatterMap != null) {
                    for (ScatterEntry entry : scatterMap.entries) {
                        if (!"none".equals(entry.materialization)
                                && entry.destination > cursor) {
                            spanEnd = Math.min(spanEnd, entry.destination);
                        }
                    }
                }
                spans.add(new StorageSpan("raw", cursor, spanEnd - cursor, null));
                cursor = spanEnd;
            }
        }
        return spans;
    }

    private static final class DecodedSlot {
        final String form;
        final long entry;
        final String isa;
        final Long literalAddress;

        DecodedSlot(String form, long entry, String isa, Long literalAddress) {
            this.form = form;
            this.entry = entry;
            this.isa = isa;
            this.literalAddress = literalAddress;
        }
    }

    static long checkedPcRelative(long address, long displacement, String what) {
        if (address < 0 || address > PmeScriptSupport.UINT32_MAX - 8) {
            fail(what + " architectural PC leaves the u32 address domain");
        }
        long visiblePc = address + 8;
        if ((displacement >= 0 && displacement > PmeScriptSupport.UINT32_MAX - visiblePc)
                || (displacement < 0 && displacement < -visiblePc)) {
            fail(what + " displacement leaves the u32 address domain");
        }
        return visiblePc + displacement;
    }

    static void validateRequestedInstructionSpans(List<Root> roots) {
        List<Root> ordered = new ArrayList<Root>(roots);
        ordered.sort(rootComparator());
        long priorEnd = -1;
        for (Root root : ordered) {
            long end = root.entry + root.instructionSize;
            if (end <= root.entry || end > PmeScriptSupport.UINT32_END) {
                fail("exception-root requested instruction span leaves the u32 address domain");
            }
            if (root.entry < priorEnd) {
                fail("exception-root requested instruction spans intersect at "
                        + canonicalAddress(root.entry));
            }
            priorEnd = end;
        }
    }

    private static DecodedSlot decodeSlot(long address, long word) {
        if ((word & 0xff00_0000L) == 0xea00_0000L) {
            long immediate = word & 0x00ff_ffffL;
            if ((immediate & 0x0080_0000L) != 0) immediate |= ~0x00ff_ffffL;
            long target = checkedPcRelative(address, immediate << 2, "direct vector target");
            return new DecodedSlot("direct_branch", target, "arm", null);
        }
        if ((word & 0xffff_f000L) == 0xe59f_f000L
                || (word & 0xffff_f000L) == 0xe51f_f000L) {
            long offset = word & 0xfffL;
            long displacement = (word & 0x0080_0000L) != 0 ? offset : -offset;
            long literal = checkedPcRelative(address, displacement, "vector literal");
            // Runtime evidence validation independently reads and hashes the
            // literal; this decoder only returns its address. The target is
            // recovered by the caller from the authenticated raw bytes below.
            return new DecodedSlot("literal_load", literal, "literal", literal);
        }
        fail("unsupported exception vector instruction at " + canonicalAddress(address));
        return null;
    }

    // ---------------------------------------------------------------------
    // Existing-state classification and ownership postflight
    // ---------------------------------------------------------------------

    private static List<Plan> preflightProgramState(Program program, Manifest manifest,
            Register tMode) {
        StringPropertyMap registry = currentRegistry(program);
        Namespace namespace = currentNamespace(program);
        boolean replay = registry != null;
        if ((registry == null) != (namespace == null)) {
            fail("exception-root namespace and ownership registry are partial");
        }
        if (registry != null && registry.getSize() != manifest.applications.size()) {
            fail("exception-root ownership registry has a stale or partial size");
        }
        if (namespace == null && !program.getSymbolTable().getSymbols(
                RESERVED_NAMESPACE, program.getGlobalNamespace()).isEmpty()) {
            fail("exception-root reserved namespace leaf collides with foreign state");
        }
        if (namespace != null && (namespace.getSymbol() == null
                || namespace.getSymbol().getSource() != SourceType.ANALYSIS
                || namespace.getSymbol().getSymbolType() != SymbolType.NAMESPACE)) {
            fail("exception-root reserved namespace is not project-owned ANALYSIS state");
        }
        List<Plan> plans = new ArrayList<Plan>();
        FunctionManager functions = program.getFunctionManager();
        Map<String, Root> roots = new HashMap<String, Root>();
        for (Root root : manifest.roots) roots.put(rootKey(root.entry, root.isa), root);
        for (Application application : manifest.applications) {
            Address entry = PmeScriptSupport.programAddress(program, application.entry);
            Root root = roots.get(rootKey(application.entry, application.isa));
            Function existing = functions.getFunctionAt(entry);
            validateCodeState(program, functions, application, root, existing, tMode);
            RegistryEntry prior = null;
            String freshDisposition;
            if (replay) {
                String stored = registry.getString(entry);
                if (stored == null) fail("exception-root registry is missing " + entry);
                prior = parseRegistry(stored);
                validateOwnedState(program, namespace, application, root, existing, prior,
                        manifest.manifestBlake3, tMode, "owned");
                freshDisposition = prior.primaryDisposition;
            }
            else {
                if (namespace != null) fail("reserved exception-root namespace already exists");
                freshDisposition = classifyFreshPrimary(program, application, existing);
                if ("not_requested".equals(freshDisposition)
                        && (existing == null
                                || existing.getSymbol().getSource() == SourceType.DEFAULT)) {
                    requireAddressNameAvailable(program, application.entry,
                            primaryGuardName(application.entry),
                            "exception temporary primary guard");
                }
            }
            plans.add(new Plan(application, root, prior, freshDisposition));
        }
        if (replay) {
            // Reject entries outside the exact canonical application key set.
            ghidra.program.model.address.AddressIterator keys = registry.getPropertyIterator();
            int seen = 0;
            while (keys.hasNext()) {
                Address address = keys.next();
                boolean found = false;
                for (Application application : manifest.applications) {
                    if (address.getOffset() == application.entry) found = true;
                }
                if (!found) fail("exception-root registry contains an unrelated entry");
                seen++;
            }
            if (seen != manifest.applications.size()) {
                fail("exception-root registry enumeration does not conserve entries");
            }
            validateNamespaceInventory(program, namespace, manifest);
        }
        return Collections.unmodifiableList(plans);
    }

    private static void requireAddressNameAvailable(Program program, long rawAddress,
            String name, String what) {
        Address address = PmeScriptSupport.programAddress(program, rawAddress);
        if (program.getSymbolTable().getSymbol(
                name, address, program.getGlobalNamespace()) != null) {
            fail(what + " collides with an existing symbol at " + address + ": " + name);
        }
    }

    private static void validateCodeState(Program program, FunctionManager functions,
            Application application, Root root, Function existing, Register tMode) {
        Address entry = PmeScriptSupport.programAddress(program, application.entry);
        Address end = PmeScriptSupport.programAddress(program,
                application.entry + root.instructionSize - 1L);
        Iterator<Function> overlapping =
                functions.getFunctionsOverlapping(new AddressSet(entry, end));
        while (overlapping.hasNext()) {
            Function overlap = overlapping.next();
            if (existing == null || overlap.getID() != existing.getID()) {
                fail("a foreign function overlaps exception root " + entry);
            }
        }

        CodeUnit first = program.getListing().getCodeUnitContaining(entry);
        if (first instanceof Instruction) {
            requireInstruction((Instruction) first, root, tMode);
            return;
        }
        if (existing != null) {
            fail("existing exception-root function has no entry instruction at " + entry);
        }
        for (int offset = 0; offset < root.instructionSize; offset++) {
            Address address = PmeScriptSupport.programAddress(
                    program, application.entry + offset);
            CodeUnit unit = program.getListing().getCodeUnitContaining(address);
            if (unit != null && (!(unit instanceof Data) || ((Data) unit).isDefined())) {
                fail("instruction/data collision exists within exception root " + entry);
            }
        }
    }

    private static String classifyFreshPrimary(Program program, Application application,
            Function existing) {
        if (application.desiredPrimary == null) return "not_requested";
        Address entry = PmeScriptSupport.programAddress(program, application.entry);
        Symbol primary = program.getSymbolTable().getPrimarySymbol(entry);
        if (primary != null && primary.getSource() != SourceType.DEFAULT) {
            return "preserved";
        }
        // Ghidra permits duplicate global leaves at different addresses (the
        // binary loader itself may import Reset at zero), so only a meaningful
        // same-address symbol changes this root's primary disposition.
        Symbol sameName = program.getSymbolTable().getSymbol(application.desiredPrimary,
                entry, program.getGlobalNamespace());
        return sameName != null && sameName.getSource() != SourceType.DEFAULT
                ? "preserved" : "exception_owned";
    }

    private static void validateOwnedState(Program program, Namespace namespace,
            Application application, Root root, Function function, RegistryEntry prior,
            String expectedManifestBlake3, Register tMode, String stage) {
        Address entry = PmeScriptSupport.programAddress(program, application.entry);
        if (!prior.manifestBlake3.equals(expectedManifestBlake3)
                || prior.entry != application.entry || !prior.isa.equals(application.isa)
                || !prior.instructionBlake3.equals(root.instructionBlake3)) {
            fail("exception-root registry identity is stale at " + entry);
        }
        if (function == null || function.getID() != prior.functionId
                || !function.getEntryPoint().equals(entry)) {
            fail("exception-root registry function binding is stale at " + entry);
        }
        requireAppliedRoot(program, function, root, tMode, stage);
        if (!"created".equals(prior.functionDisposition)
                && !"foreign".equals(prior.functionDisposition)) {
            fail("exception-root function disposition is invalid at " + entry);
        }
        List<LabelEntry> labels = labelsAt(program, namespace, entry);
        if (labels.size() != application.roleLabels.size()
                || labels.size() != prior.labelIds.size()) {
            fail("exception-root label inventory is stale at " + entry);
        }
        // Claims stay in architectural table/slot order, while concrete symbol
        // identities are bound in lexical leaf order for stable Ghidra replay.
        List<String> expectedLabels = new ArrayList<String>(application.roleLabels);
        Collections.sort(expectedLabels);
        for (int index = 0; index < labels.size(); index++) {
            LabelEntry label = labels.get(index);
            if (!label.name.equals(expectedLabels.get(index))
                    || label.id != prior.labelIds.get(index).longValue()
                    || label.source != SourceType.ANALYSIS
                    || label.type != SymbolType.LABEL) {
                fail("exception-root label binding is stale at " + entry
                        + " (got " + label.name + "/" + label.id + "/" + label.source
                        + ", expected " + expectedLabels.get(index) + "/"
                        + prior.labelIds.get(index) + "/ANALYSIS)");
            }
        }
        if (!labelsDigest(labels).equals(prior.labelsBlake3)) {
            fail("exception-root label digest is stale at " + entry);
        }
        Symbol primary = function.getSymbol();
        String source = PmeScriptSupport.primarySource(primary.getSource());
        String digest = PmeScriptSupport.blake3Hex(
                PmeScriptSupport.boundedUtf8(primary.getName(), MAX_SYMBOL_UTF8_BYTES,
                        "exception-root primary"));
        if ("exception_owned".equals(prior.primaryDisposition)) {
            if (application.desiredPrimary == null
                    || !primary.getName().equals(application.desiredPrimary)
                    || primary.getSource() != SourceType.ANALYSIS
                    || prior.primaryId == null || prior.primaryId.longValue() != primary.getID()
                    || !source.equals(prior.primarySource)
                    || !digest.equals(prior.primaryNameBlake3)) {
                fail("owned exception primary is stale at " + entry);
            }
        }
        else if ("pass2_owned".equals(prior.primaryDisposition)) {
            String original = application.desiredPrimary == null ? null
                    : primaryNameDigest(application.desiredPrimary);
            if (application.desiredPrimary == null
                    || prior.primaryId == null || prior.primaryId.longValue() != primary.getID()
                    || primary.getSource() != SourceType.USER_DEFINED
                    || !source.equals(prior.primarySource)
                    || !digest.equals(prior.primaryNameBlake3)
                    || !("func".equals(prior.transitionAuthority)
                            || "registration".equals(prior.transitionAuthority))
                    || !original.equals(prior.transitionOriginalPrimaryBlake3)) {
                fail("pass-2-owned exception primary is stale at " + entry);
            }
        }
        else if ("preserved".equals(prior.primaryDisposition)) {
            if (application.desiredPrimary == null || prior.primaryId == null
                    || prior.primaryId.longValue() != primary.getID()
                    || !source.equals(prior.primarySource)
                    || !digest.equals(prior.primaryNameBlake3)) {
                fail("preserved exception primary is stale at " + entry);
            }
        }
        else if ("not_requested".equals(prior.primaryDisposition)) {
            if (application.desiredPrimary != null || prior.primaryId == null
                    || prior.primaryId.longValue() != primary.getID()
                    || !source.equals(prior.primarySource)
                    || !digest.equals(prior.primaryNameBlake3)) {
                fail("not-requested exception primary is stale at " + entry);
            }
        }
        else {
            fail("unknown exception primary disposition at " + entry);
        }
    }

    static AppliedState validateApplied(Program program, Manifest manifest, String identity) {
        if (!identity.equals(identity(manifest))) fail("postflight identity changed");
        StringPropertyMap registry = currentRegistry(program);
        Namespace namespace = currentNamespace(program);
        if (registry == null || namespace == null
                || registry.getSize() != manifest.applications.size()) {
            fail("exception-root terminal ownership state is incomplete");
        }
        Map<String, Root> roots = new HashMap<String, Root>();
        for (Root root : manifest.roots) roots.put(rootKey(root.entry, root.isa), root);
        Register tMode = program.getLanguage().getRegister("TMode");
        if (tMode == null) fail("the current language has no TMode register");
        int shared = 0;
        for (Application application : manifest.applications) {
            Root root = roots.get(rootKey(application.entry, application.isa));
            Address entry = PmeScriptSupport.programAddress(program, application.entry);
            Function function = program.getFunctionManager().getFunctionAt(entry);
            RegistryEntry prior = parseRegistry(registry.getString(entry));
            if (!prior.manifestBlake3.equals(manifest.manifestBlake3)) {
                fail("postflight registry does not bind the manifest");
            }
            validateOwnedState(program, namespace, application, root, function, prior,
                    manifest.manifestBlake3, tMode, "postflight");
            if (isSharedEntry(application)) shared++;
        }
        validateNamespaceInventory(program, namespace, manifest);
        return new AppliedState(shared);
    }

    /**
     * Identity-only postflight for scripts that intentionally receive no
     * manifest path. The ownership registry is the concrete state authority;
     * its complete function, instruction, primary, and label identities must
     * conserve the table/root counts carried by the invocation identity.
     */
    static AppliedState validateAppliedIdentity(Program program, String expectedIdentity) {
        String[] identity = parseIdentity(expectedIdentity);
        String manifestBlake3 = identity[1];
        int tableCount = (int) unsigned(identity[2], MAX_TABLES,
                "exception-root identity table count");
        int rootCount = (int) unsigned(identity[3], MAX_ROOTS,
                "exception-root identity root count");
        if (tableCount == 0 || rootCount == 0) {
            fail("a present exception-root identity has zero tables or roots");
        }

        StringPropertyMap registry = currentRegistry(program);
        Namespace namespace = currentNamespace(program);
        if (registry == null || namespace == null || registry.getSize() != rootCount) {
            fail("exception-root terminal ownership state is incomplete");
        }
        Register tMode = program.getLanguage().getRegister("TMode");
        if (tMode == null) fail("the current language has no TMode register");

        Set<Address> registered = new HashSet<Address>();
        AddressIterator properties = registry.getPropertyIterator();
        while (properties.hasNext()) {
            Address entry = properties.next();
            if (!registered.add(entry)) {
                fail("the exception-root registry carries a duplicate entry");
            }
        }
        Set<String> tables = new HashSet<String>();
        Set<String> claims = new HashSet<String>();
        int labelCount = 0;
        int shared = 0;
        for (Address entry : registered) {
            RegistryEntry prior = parseRegistry(registry.getString(entry));
            if (!manifestBlake3.equals(prior.manifestBlake3)
                    || entry.getOffset() != prior.entry) {
                fail("exception-root registry does not bind the invocation identity at " + entry);
            }
            Function function = program.getFunctionManager().getFunctionAt(entry);
            validateRegistryRoot(program, function, prior, tMode);

            List<LabelEntry> labels = labelsAt(program, namespace, entry);
            if (labels.size() != prior.labelIds.size()) {
                fail("exception-root label inventory is stale at " + entry);
            }
            Set<String> entryRoles = new HashSet<String>();
            for (int index = 0; index < labels.size(); index++) {
                LabelEntry label = labels.get(index);
                if (label.id != prior.labelIds.get(index).longValue()
                        || label.source != SourceType.ANALYSIS
                        || label.type != SymbolType.LABEL) {
                    fail("exception-root label binding is stale at " + entry);
                }
                String[] parsed = parseRoleLabel(label.name);
                tables.add(parsed[1]);
                if (!claims.add(parsed[1] + ":" + parsed[0])) {
                    fail("exception-root role label is duplicated: " + label.name);
                }
                entryRoles.add(parsed[0]);
                labelCount = Math.addExact(labelCount, 1);
            }
            if (!labelsDigest(labels).equals(prior.labelsBlake3)) {
                fail("exception-root label digest is stale at " + entry);
            }
            validateRegistryPrimary(function, prior, entryRoles, entry);
            if (entryRoles.size() > 1) shared = Math.addExact(shared, 1);
        }
        int expectedLabels = Math.multiplyExact(tableCount, SLOTS_PER_TABLE);
        if (tables.size() != tableCount || claims.size() != expectedLabels
                || labelCount != expectedLabels) {
            fail("exception-root role labels do not conserve the invocation identity");
        }
        SymbolIterator symbols = program.getSymbolTable().getSymbols(namespace);
        int namespaceLabels = 0;
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            namespaceLabels = Math.addExact(namespaceLabels, 1);
            if (symbol.getAddress() == null || !registered.contains(symbol.getAddress())
                    || symbol.getSource() != SourceType.ANALYSIS
                    || symbol.getSymbolType() != SymbolType.LABEL) {
                fail("exception-root reserved namespace contains unregistered state");
            }
        }
        if (namespaceLabels != labelCount) {
            fail("exception-root reserved namespace inventory is stale or partial");
        }
        return new AppliedState(shared);
    }

    static void validateAbsent(Program program) {
        StringPropertyMap registry = currentRegistry(program);
        if (registry != null && registry.getSize() != 0) {
            fail("the exception-root ownership registry is not empty");
        }
        Namespace namespace = currentNamespace(program);
        if (namespace != null) {
            SymbolIterator symbols = program.getSymbolTable().getSymbols(namespace);
            if (symbols.hasNext()) {
                fail("the exception-root reserved namespace is not empty");
            }
        }
    }

    private static void validateRegistryRoot(Program program, Function function,
            RegistryEntry prior, Register tMode) {
        Address entry = PmeScriptSupport.programAddress(program, prior.entry);
        if (function == null || function.getID() != prior.functionId
                || !function.getEntryPoint().equals(entry)) {
            fail("exception-root registry function binding is stale at " + entry);
        }
        if (!"created".equals(prior.functionDisposition)
                && !"foreign".equals(prior.functionDisposition)) {
            fail("exception-root function disposition is invalid at " + entry);
        }
        Instruction instruction = program.getListing().getInstructionAt(entry);
        if (instruction == null || instruction.isLengthOverridden()
                || ("arm".equals(prior.isa) && instruction.getLength() != 4)
                || ("thumb".equals(prior.isa)
                        && instruction.getLength() != 2 && instruction.getLength() != 4)) {
            fail("exception-root instruction length is stale at " + entry);
        }
        try {
            if (!PmeScriptSupport.blake3Hex(instruction.getBytes())
                    .equals(prior.instructionBlake3)) {
                fail("exception-root instruction bytes are stale at " + entry);
            }
        }
        catch (MemoryAccessException error) {
            throw new RootError("exception-root instruction is unreadable at " + entry, error);
        }
        BigInteger expected = "thumb".equals(prior.isa) ? BigInteger.ONE : BigInteger.ZERO;
        Address end = PmeScriptSupport.programAddress(program,
                prior.entry + instruction.getLength() - 1L);
        Address cursor = entry;
        while (true) {
            RegisterValue value = program.getProgramContext().getRegisterValue(tMode, cursor);
            if (value == null || !value.hasValue()
                    || !expected.equals(value.getUnsignedValue())) {
                fail("exception-root instruction ISA is stale at " + entry);
            }
            if (cursor.equals(end)) break;
            cursor = cursor.next();
            if (cursor == null) fail("exception-root instruction span wraps at " + entry);
        }
        if (!function.getBody().contains(entry, end)) {
            fail("exception-root function body does not contain its instruction at " + entry);
        }
    }

    private static void validateRegistryPrimary(Function function, RegistryEntry prior,
            Set<String> entryRoles, Address entry) {
        Symbol primary = function.getSymbol();
        String source = PmeScriptSupport.primarySource(primary.getSource());
        String digest = PmeScriptSupport.blake3Hex(PmeScriptSupport.boundedUtf8(
                primary.getName(), MAX_SYMBOL_UTF8_BYTES, "exception-root primary"));
        if (prior.primaryId == null || prior.primaryId.longValue() != primary.getID()
                || !source.equals(prior.primarySource)
                || !digest.equals(prior.primaryNameBlake3)) {
            fail("exception-root primary binding is stale at " + entry);
        }
        if ("exception_owned".equals(prior.primaryDisposition)) {
            if (entryRoles.size() != 1 || primary.getSource() != SourceType.ANALYSIS
                    || !primary.getName().equals(primaryForRole(entryRoles.iterator().next()))) {
                fail("owned exception primary is stale at " + entry);
            }
        }
        else if ("pass2_owned".equals(prior.primaryDisposition)) {
            if (entryRoles.size() != 1 || primary.getSource() != SourceType.USER_DEFINED
                    || !("func".equals(prior.transitionAuthority)
                            || "registration".equals(prior.transitionAuthority))
                    || prior.transitionOriginalPrimaryBlake3 == null) {
                fail("pass-2-owned exception primary is stale at " + entry);
            }
        }
        else if ("preserved".equals(prior.primaryDisposition)) {
            if (entryRoles.size() != 1 || primary.getSource() == SourceType.DEFAULT) {
                fail("preserved exception primary is stale at " + entry);
            }
        }
        else if ("not_requested".equals(prior.primaryDisposition)) {
            if (entryRoles.size() < 2) {
                fail("not-requested exception primary is stale at " + entry);
            }
        }
        else {
            fail("unknown exception primary disposition at " + entry);
        }
    }

    private static String[] parseRoleLabel(String leaf) {
        String prefix = "exception_";
        int split = leaf.lastIndexOf('_');
        if (!leaf.startsWith(prefix) || split <= prefix.length()
                || split + 9 != leaf.length()) {
            fail("exception-root role label is not canonical: " + leaf);
        }
        String role = role(leaf.substring(prefix.length(), split),
                "exception-root role label");
        String table = leaf.substring(split + 1);
        if (!table.matches("[0-9a-f]{8}")) {
            fail("exception-root role label table address is not canonical: " + leaf);
        }
        return new String[] { role, table };
    }

    private static String[] parseIdentity(String value) {
        if (value == null) fail("exception-root identity is missing");
        String[] parts = value.split(":", -1);
        if (parts.length != 4 || !IDENTITY_VERSION.equals(parts[0])) {
            fail("exception-root identity is not the v1 grammar");
        }
        hash(parts[1], "exception-root identity manifest BLAKE3");
        unsigned(parts[2], MAX_TABLES, "exception-root identity table count");
        unsigned(parts[3], MAX_ROOTS, "exception-root identity root count");
        return parts;
    }

    private static void validateNamespaceInventory(Program program, Namespace namespace,
            Manifest manifest) {
        Set<String> expected = new HashSet<String>();
        for (Application application : manifest.applications) {
            for (String leaf : application.roleLabels) {
                expected.add(canonicalAddress(application.entry) + ":" + leaf);
            }
        }
        Set<String> actual = new HashSet<String>();
        SymbolIterator symbols = program.getSymbolTable().getSymbols(namespace);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getAddress() == null || symbol.getSource() != SourceType.ANALYSIS
                    || symbol.getSymbolType() != SymbolType.LABEL
                    || !actual.add(canonicalAddress(symbol.getAddress().getOffset())
                            + ":" + symbol.getName())) {
                fail("exception-root reserved namespace contains noncanonical state");
            }
        }
        if (!actual.equals(expected)) {
            fail("exception-root reserved namespace inventory is stale or partial");
        }
    }

    // ---------------------------------------------------------------------
    // Registry and label ownership grammar
    // ---------------------------------------------------------------------

    static String primaryNameDigest(String name) {
        return PmeScriptSupport.blake3Hex(PmeScriptSupport.boundedUtf8(
                name, MAX_SYMBOL_UTF8_BYTES, "exception-root primary"));
    }

    static void validatePass2Transition(RegistryEntry registry,
            PalTasksSupport.MapDecision decision, Address entry) {
        if (!"pass2_owned".equals(registry.primaryDisposition)) {
            fail("the exception registry disposition at " + entry
                    + " is not pass2_owned");
        }
        if (!decision.exceptionTransitionAuthority.equals(registry.transitionAuthority)) {
            fail("exception transition authority does not match the symbol map at " + entry);
        }
        if (!primaryNameDigest(decision.originalPrimary).equals(
                registry.transitionOriginalPrimaryBlake3)) {
            fail("exception transition original primary does not match the symbol map at "
                    + entry);
        }
        if (!decision.finalSource.equals(registry.primarySource)
                || !primaryNameDigest(decision.finalPrimary).equals(
                        registry.primaryNameBlake3)) {
            fail("exception transition final primary does not match the symbol map at "
                    + entry);
        }
    }

    static void validatePass2Transitions(Program program, PalTasksSupport.SymbolMap map) {
        StringPropertyMap registry = currentRegistry(program);
        Set<Address> expected = new HashSet<Address>();
        for (int index = 0; index < map.decisions.size(); index++) {
            PalTasksSupport.MapDecision decision = map.decisions.get(index);
            if (decision.exceptionTransitionAuthority == null) continue;
            Address entry = PmeScriptSupport.programAddress(
                    program, map.executions.get(index).entry);
            if (!expected.add(entry)) {
                fail("the symbol map carries duplicate exception transitions at " + entry);
            }
            RegistryEntry retained = parseRegistry(
                    registry == null ? null : registry.getString(entry));
            validatePass2Transition(retained, decision, entry);
        }
    }

    static String registryValue(RegistryEntry entry) {
        String primaryId = entry.primaryId == null ? "none" : Long.toString(entry.primaryId);
        String source = entry.primarySource == null ? "none" : entry.primarySource;
        String primaryHash = entry.primaryNameBlake3 == null
                ? "none" : entry.primaryNameBlake3;
        String transitionAuthority = entry.transitionAuthority == null
                ? "none" : entry.transitionAuthority;
        String transitionOriginal = entry.transitionOriginalPrimaryBlake3 == null
                ? "none" : entry.transitionOriginalPrimaryBlake3;
        StringBuilder ids = new StringBuilder();
        for (int index = 0; index < entry.labelIds.size(); index++) {
            if (index != 0) ids.append(',');
            ids.append(entry.labelIds.get(index));
        }
        return String.join(":", IDENTITY_VERSION, entry.manifestBlake3,
                String.format(Locale.ROOT, "%08x", entry.entry), entry.isa,
                entry.instructionBlake3, Long.toString(entry.functionId),
                entry.functionDisposition, entry.primaryDisposition, primaryId, source,
                primaryHash, transitionAuthority, transitionOriginal,
                Integer.toString(entry.labelIds.size()), ids.toString(),
                entry.labelsBlake3);
    }

    static RegistryEntry parseRegistry(String value) {
        if (value == null) fail("exception-root registry value is missing");
        String[] fields = value.split(":", -1);
        if (fields.length != 16 || !IDENTITY_VERSION.equals(fields[0])) {
            fail("exception-root registry grammar is invalid");
        }
        String manifest = hash(fields[1], "registry manifest hash");
        if (!fields[2].matches("[0-9a-f]{8}")) fail("registry entry is not canonical");
        long entry = Long.parseUnsignedLong(fields[2], 16);
        String isa = isa(fields[3], "registry ISA");
        String instruction = hash(fields[4], "registry instruction hash");
        long functionId = unsigned(fields[5], Long.MAX_VALUE, "registry function ID");
        String functionDisposition = oneOf(fields[6], "registry function disposition",
                "created", "foreign");
        String primaryDisposition = oneOf(fields[7], "registry primary disposition",
                "exception_owned", "preserved", "not_requested", "pass2_owned");
        Long primaryId = "none".equals(fields[8]) ? null
                : unsigned(fields[8], Long.MAX_VALUE, "registry primary ID");
        String source = "none".equals(fields[9]) ? null
                : oneOf(fields[9], "registry primary source", "default", "analysis",
                        "ai", "imported", "user_defined");
        String primaryHash = "none".equals(fields[10]) ? null
                : hash(fields[10], "registry primary hash");
        String transitionAuthority = "none".equals(fields[11]) ? null
                : oneOf(fields[11], "registry transition authority", "func", "registration");
        String transitionOriginal = "none".equals(fields[12]) ? null
                : hash(fields[12], "registry transition original primary hash");
        int labelCount = (int) unsigned(fields[13], 16, "registry label count");
        List<Long> labelIds = new ArrayList<Long>();
        if (labelCount == 0) {
            if (!fields[14].isEmpty()) fail("zero-label registry carries label IDs");
        }
        else {
            String[] ids = fields[14].split(",", -1);
            if (ids.length != labelCount) fail("registry label IDs do not conserve");
            for (String id : ids) {
                labelIds.add(unsigned(id, Long.MAX_VALUE, "registry label ID"));
            }
        }
        String labelsHash = hash(fields[15], "registry labels hash");
        if (primaryId == null || source == null || primaryHash == null) {
            fail("exception-root registry does not bind a resulting primary identity");
        }
        if ("pass2_owned".equals(primaryDisposition)) {
            if (transitionAuthority == null || transitionOriginal == null
                    || !"user_defined".equals(source)) {
                fail("pass-2-owned exception registry lacks its exact transition");
            }
        }
        else if (transitionAuthority != null || transitionOriginal != null) {
            fail("an untransitioned exception registry carries transition state");
        }
        return new RegistryEntry(manifest, entry, isa, instruction, functionId,
                functionDisposition, primaryDisposition, primaryId, source, primaryHash,
                transitionAuthority, transitionOriginal,
                Collections.unmodifiableList(labelIds), labelsHash);
    }

    static final class LabelEntry {
        final long id;
        final String name;
        final SourceType source;
        final SymbolType type;

        LabelEntry(long id, String name, SourceType source, SymbolType type) {
            this.id = id;
            this.name = name;
            this.source = source;
            this.type = type;
        }
    }

    static List<LabelEntry> labelsAt(Program program, Namespace namespace, Address entry) {
        List<LabelEntry> labels = new ArrayList<LabelEntry>();
        SymbolIterator symbols = program.getSymbolTable().getSymbolsAsIterator(entry);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (namespace.equals(symbol.getParentNamespace())) {
                labels.add(new LabelEntry(symbol.getID(), symbol.getName(), symbol.getSource(),
                        symbol.getSymbolType()));
            }
        }
        labels.sort(Comparator.comparing(label -> label.name));
        return labels;
    }

    static String labelsDigest(List<LabelEntry> labels) {
        Blake3Digest digest = new Blake3Digest();
        byte[] domain = PmeScriptSupport.ascii(
                "pixel-modem-extractor-exception-labels-v1\0");
        digest.update(domain, 0, domain.length);
        for (LabelEntry label : labels) {
            byte[] id = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
                    .putLong(label.id).array();
            byte[] name = PmeScriptSupport.boundedUtf8(label.name,
                    MAX_SYMBOL_UTF8_BYTES, "exception role label");
            byte[] length = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
                    .putInt(name.length).array();
            digest.update(id, 0, id.length);
            digest.update(length, 0, length.length);
            digest.update(name, 0, name.length);
        }
        return PmeScriptSupport.finishHash(digest);
    }

    static StringPropertyMap currentRegistry(Program program) {
        return program.getUsrPropertyManager().getStringPropertyMap(OWNERSHIP_MAP);
    }

    static Namespace currentNamespace(Program program) {
        return program.getSymbolTable().getNamespace(
                RESERVED_NAMESPACE, program.getGlobalNamespace());
    }

    static void requireInstruction(Instruction instruction, Root root, Register tMode) {
        requireInstruction(instruction, root, tMode, "existing");
    }

    private static void requireAppliedRoot(Program program, Function function, Root root,
            Register tMode, String stage) {
        Address entry = PmeScriptSupport.programAddress(program, root.entry);
        Instruction instruction = program.getListing().getInstructionAt(entry);
        if (instruction == null) {
            fail(stage + " exception-root instruction is missing");
        }
        requireInstruction(instruction, root, tMode, stage);
        BigInteger expected = "thumb".equals(root.isa) ? BigInteger.ONE : BigInteger.ZERO;
        for (long offset = 0; offset < root.instructionSize; offset++) {
            Address address = PmeScriptSupport.programAddress(program, root.entry + offset);
            RegisterValue value = program.getProgramContext().getRegisterValue(tMode, address);
            if (value == null || !value.hasValue()
                    || !expected.equals(value.getUnsignedValue())) {
                fail(stage + " exception-root instruction ISA is stale");
            }
        }
        Address end = PmeScriptSupport.programAddress(program,
                root.entry + root.instructionSize - 1L);
        if (!function.getBody().contains(entry, end)) {
            fail(stage + " exception-root function body does not contain its instruction");
        }
    }

    private static void requireInstruction(Instruction instruction, Root root, Register tMode,
            String stage) {
        if (instruction.getLength() != root.instructionSize
                || instruction.isLengthOverridden()) {
            fail(stage + " exception-root instruction length is stale");
        }
        RegisterValue value = instruction.getRegisterValue(tMode);
        BigInteger expected = "thumb".equals(root.isa) ? BigInteger.ONE : BigInteger.ZERO;
        if (value == null || !value.hasValue()
                || !expected.equals(value.getUnsignedValue())) {
            fail(stage + " exception-root instruction ISA is stale");
        }
        try {
            if (!PmeScriptSupport.blake3Hex(instruction.getBytes())
                    .equals(root.instructionBlake3)) {
                fail(stage + " exception-root instruction bytes are stale");
            }
        }
        catch (MemoryAccessException error) {
            throw new RootError(stage + " exception-root instruction is unreadable", error);
        }
    }

    // ---------------------------------------------------------------------
    // Pure helpers
    // ---------------------------------------------------------------------

    private static String hashMemory(Program program, TaskMonitor monitor, Address start,
            long size, String what) throws Exception {
        Blake3Digest digest = new Blake3Digest();
        byte[] buffer = new byte[64 * 1024];
        long offset = 0;
        while (offset < size) {
            if (monitor.isCancelled()) fail(what + " validation was cancelled");
            int wanted = (int) Math.min(buffer.length, size - offset);
            Address address = start.addNoWrap(offset);
            int read = program.getMemory().getBytes(address, buffer, 0, wanted);
            if (read != wanted) fail(what + " is not fully readable");
            digest.update(buffer, 0, read);
            offset += read;
        }
        return PmeScriptSupport.finishHash(digest);
    }

    private static String hashZeros(long size) {
        Blake3Digest digest = new Blake3Digest();
        byte[] zeros = new byte[64 * 1024];
        long remaining = size;
        while (remaining > 0) {
            int chunk = (int) Math.min(remaining, zeros.length);
            digest.update(zeros, 0, chunk);
            remaining -= chunk;
        }
        return PmeScriptSupport.finishHash(digest);
    }

    private static boolean rangesOverlap(long firstStart, long firstEnd,
            long secondStart, long secondEnd) {
        return firstStart < secondEnd && secondStart < firstEnd;
    }

    private static boolean sameTable(Table left, Table right) {
        if (!left.kind.equals(right.kind) || left.address != right.address
                || !left.blake3.equals(right.blake3)
                || !sameSpans(left.storage, right.storage)
                || left.slots.size() != right.slots.size()) return false;
        for (int index = 0; index < left.slots.size(); index++) {
            Slot a = left.slots.get(index);
            Slot b = right.slots.get(index);
            if (a.index != b.index || !a.role.equals(b.role) || a.address != b.address
                    || !a.form.equals(b.form) || !a.slotBlake3.equals(b.slotBlake3)
                    || !sameSpans(a.slotStorage, b.slotStorage)
                    || !sameLiteral(a.literal, b.literal) || a.entry != b.entry
                    || !a.isa.equals(b.isa) || a.instructionSize != b.instructionSize
                    || !a.instructionBlake3.equals(b.instructionBlake3)
                    || !sameSpans(a.instructionStorage, b.instructionStorage)) return false;
        }
        return true;
    }

    private static boolean sameLiteral(Literal left, Literal right) {
        if (left == null || right == null) return left == right;
        return left.address == right.address && left.blake3.equals(right.blake3)
                && sameSpans(left.storage, right.storage);
    }

    private static boolean sameRoot(Root expected, Root actual) {
        return expected.entry == actual.entry && expected.isa.equals(actual.isa)
                && expected.instructionSize == actual.instructionSize
                && expected.instructionBlake3.equals(actual.instructionBlake3)
                && sameSpans(expected.storage, actual.storage)
                && sameClaims(expected.claims, actual.claims);
    }

    private static boolean sameClaims(List<Claim> left, List<Claim> right) {
        if (left.size() != right.size()) return false;
        for (int index = 0; index < left.size(); index++) {
            if (!left.get(index).same(right.get(index))) return false;
        }
        return true;
    }

    private static boolean sameSpans(List<StorageSpan> left, List<StorageSpan> right) {
        if (left.size() != right.size()) return false;
        for (int index = 0; index < left.size(); index++) {
            if (!left.get(index).same(right.get(index))) return false;
        }
        return true;
    }

    private static Comparator<Root> rootComparator() {
        return (left, right) -> {
            int byAddress = Long.compare(left.entry, right.entry);
            if (byAddress != 0) return byAddress;
            return Integer.compare(isaOrder(left.isa), isaOrder(right.isa));
        };
    }

    private static int isaOrder(String isa) {
        return "arm".equals(isa) ? 0 : 1;
    }

    private static String rootKey(long entry, String isa) {
        return canonicalAddress(entry) + ":" + isa;
    }

    static String canonicalAddress(long address) {
        return String.format(Locale.ROOT, "0x%08x", address);
    }

    static boolean isSharedEntry(Application application) {
        // Repeated claims for one role across tables retain that role's unique
        // primary; only a multi-claim application suppressed to null is shared.
        return application.desiredPrimary == null && application.claims.size() > 1;
    }

    static String primaryGuardName(long address) {
        return PmeScriptSupport.requireSymbolLeaf(
                String.format(Locale.ROOT, "PME_ExceptionRootGuard_%08x", address),
                MAX_SYMBOL_UTF8_BYTES, "exception temporary primary guard");
    }

    private static String roleLabel(Claim claim) {
        String label = "exception_" + claim.role + "_"
                + String.format(Locale.ROOT, "%08x", claim.tableAddress);
        return PmeScriptSupport.requireSymbolLeaf(
                label, MAX_SYMBOL_UTF8_BYTES, "exception role label");
    }

    private static String primaryForRole(String role) {
        for (int index = 0; index < ROLES.length; index++) {
            if (ROLES[index].equals(role)) return PRIMARIES[index];
        }
        fail("unknown exception role " + role);
        return null;
    }

    private static String role(String value, String what) {
        for (String role : ROLES) if (role.equals(value)) return value;
        fail(what + " is not a known architectural role");
        return null;
    }

    private static String isa(String value, String what) {
        return oneOf(value, what, "arm", "thumb");
    }

    private static String hash(String value, String what) {
        if (!HASH.matcher(value).matches()) fail(what + " is not lowercase BLAKE3");
        return value;
    }

    private static String stringValue(JsonReader reader, String what) throws IOException {
        if (reader.peek() != JsonToken.STRING) fail(what + " is not a string");
        return reader.nextString();
    }

    private static long addressValue(JsonReader reader, String what) throws IOException {
        return address(stringValue(reader, what), what);
    }

    private static String hashValue(JsonReader reader, String what) throws IOException {
        return hash(stringValue(reader, what), what);
    }

    private static long unsignedValue(JsonReader reader, long maximum, String what)
            throws IOException {
        if (reader.peek() != JsonToken.NUMBER) {
            fail(what + " is not a canonical unsigned decimal");
        }
        return unsigned(reader.nextString(), maximum, what);
    }

    private static String nullableHash(JsonReader reader, String what) throws IOException {
        if (reader.peek() == JsonToken.NULL) {
            reader.nextNull();
            return null;
        }
        return hashValue(reader, what);
    }

    private static long address(String value, String what) {
        if (!ADDRESS.matcher(value).matches()) fail(what + " is not a canonical u32 address");
        return Long.parseUnsignedLong(value.substring(2), 16);
    }

    private static Long nullableAddress(JsonReader reader, String what) throws IOException {
        if (reader.peek() == JsonToken.NULL) {
            reader.nextNull();
            return null;
        }
        return addressValue(reader, what);
    }

    private static long unsigned(String value, long maximum, String what) {
        if (!DECIMAL.matcher(value).matches()) {
            fail(what + " is not a canonical unsigned decimal");
        }
        try {
            long parsed = Long.parseLong(value);
            if (parsed < 0 || parsed > maximum) fail(what + " exceeds its bound");
            return parsed;
        }
        catch (NumberFormatException error) {
            throw new RootError(what + " exceeds the signed parser domain", error);
        }
    }

    private static Long nullableUnsigned(JsonReader reader, long maximum, String what)
            throws IOException {
        if (reader.peek() == JsonToken.NULL) {
            reader.nextNull();
            return null;
        }
        return unsignedValue(reader, maximum, what);
    }

    private static String printable(String value, int maximumBytes, String what) {
        byte[] bytes = PmeScriptSupport.boundedUtf8(value, maximumBytes, what);
        if (bytes.length == 0) fail(what + " is empty");
        for (byte valueByte : bytes) {
            int unsigned = valueByte & 0xff;
            if (unsigned < 0x20 || unsigned > 0x7e) {
                fail(what + " is not printable ASCII");
            }
        }
        return value;
    }

    private static String oneOf(String value, String what, String... choices) {
        for (String choice : choices) if (choice.equals(value)) return value;
        fail(what + " has an unknown closed-enum value");
        return null;
    }

    private static void exact(JsonReader reader, String wanted, String what) throws IOException {
        String actual = stringValue(reader, what);
        if (!wanted.equals(actual)) fail(what + " does not match the required value");
    }

    private static void exactLong(JsonReader reader, long wanted, String what)
            throws IOException {
        long actual = unsignedValue(reader, wanted, what);
        if (actual != wanted) fail(what + " does not match the required value");
    }

    private static void name(JsonReader reader, String wanted) throws IOException {
        if (!reader.hasNext()) fail("exception-root object ended before " + wanted);
        String actual = reader.nextName();
        if (!wanted.equals(actual)) {
            fail("exception-root object expected key " + wanted + " but found " + actual);
        }
    }

    private static boolean booleanValue(JsonReader reader, String what) throws IOException {
        if (reader.peek() != JsonToken.BOOLEAN) fail(what + " is not boolean");
        return reader.nextBoolean();
    }

    private static void requireSortedUnique(List<Long> values, String what) {
        long prior = -1;
        for (long value : values) {
            if (value <= prior) fail(what + " is not sorted and unique");
            prior = value;
        }
    }

    private static void requireInImage(Image image, long address, long size, String what) {
        if (size <= 0 || address < image.base
                || address > image.base + image.size - size) {
            fail(what + " leaves the image");
        }
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

    private static void fail(String message) {
        throw new RootError(message);
    }
}
