// StartupMetadataSupport.java - strict parser, independent semantic preflight,
// and ownership/postflight support for Phase 3B startup metadata.
//@category PixelModem
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

final class StartupMetadataSupport {
    static final String FORMAT = "pixel-modem-extractor-startup-metadata-v1";
    static final String IDENTITY_VERSION = "v1";
    static final String RESERVED_NAMESPACE = "PixelModemExtractor_StartupMetadata_v1";
    static final String OWNERSHIP_MAP = "PixelModemExtractor.StartupMetadata.v1.Ownership";
    static final String BACKEND_CRATE = "scaleservers-arm32-assembly";
    static final String BACKEND_VERSION = "1.0.0";
    static final int MAX_MANIFEST_BYTES = 1024 * 1024;
    static final int MAX_APPLICATIONS = 2;
    static final int MAX_PRIVILEGED_OPS = 65_536;
    static final int MAX_SCATTER_ENTRIES = 256;
    static final int MAX_OPERANDS = 64;
    static final int MAX_REASON_CODE_POINTS = 2048;
    static final int MAX_SYMBOL_UTF8_BYTES = 2000;

    private static final Pattern HASH = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern ADDRESS = Pattern.compile("0x[0-9a-f]{8}");
    private static final Pattern DECIMAL = Pattern.compile("0|[1-9][0-9]*");

    private StartupMetadataSupport() {}

    static final class StartupError extends RuntimeException {
        private static final long serialVersionUID = 1L;

        StartupError(String message) {
            super(message);
        }

        StartupError(String message, Throwable cause) {
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

    static final class Inventories {
        final String functionsBlake3;
        final String thumbFunctionsBlake3;

        Inventories(String functionsBlake3, String thumbFunctionsBlake3) {
            this.functionsBlake3 = functionsBlake3;
            this.thumbFunctionsBlake3 = thumbFunctionsBlake3;
        }
    }

    static final class Application {
        final String role;
        final long entry;
        final String isa;
        final String desiredPrimary;
        final String roleLabel;
        final boolean setNoReturn;

        Application(String role, long entry, String isa, String desiredPrimary,
                String roleLabel, boolean setNoReturn) {
            this.role = role;
            this.entry = entry;
            this.isa = isa;
            this.desiredPrimary = desiredPrimary;
            this.roleLabel = roleLabel;
            this.setNoReturn = setNoReturn;
        }
    }

    static final class Manifest {
        final String toolVersion;
        final Image image;
        final RuntimeInfo runtime;
        final Inventories inventories;
        final String exceptionRoots;
        final boolean hardwarePresent;
        final long hardwareEntry;
        final String hardwareIsa;
        final boolean stackPresent;
        final long stackEntry;
        final String stackIsa;
        final boolean stackNonReturn;
        final List<Application> applications;
        final int privilegedOps;
        String manifestBlake3;

        Manifest(String toolVersion, Image image, RuntimeInfo runtime, Inventories inventories,
                String exceptionRoots, boolean hardwarePresent, long hardwareEntry,
                String hardwareIsa, boolean stackPresent, long stackEntry, String stackIsa,
                boolean stackNonReturn, List<Application> applications, int privilegedOps) {
            this.toolVersion = toolVersion;
            this.image = image;
            this.runtime = runtime;
            this.inventories = inventories;
            this.exceptionRoots = exceptionRoots;
            this.hardwarePresent = hardwarePresent;
            this.hardwareEntry = hardwareEntry;
            this.hardwareIsa = hardwareIsa;
            this.stackPresent = stackPresent;
            this.stackEntry = stackEntry;
            this.stackIsa = stackIsa;
            this.stackNonReturn = stackNonReturn;
            this.applications = applications;
            this.privilegedOps = privilegedOps;
        }
    }

    static final class RegistryEntry {
        final String manifestBlake3;
        final long entry;
        final String isa;
        final long functionId;
        final long primaryId;
        final String primarySource;
        final String primaryNameBlake3;
        final boolean setNoReturn;
        final long labelId;

        RegistryEntry(String manifestBlake3, long entry, String isa, long functionId,
                long primaryId, String primarySource, String primaryNameBlake3,
                boolean setNoReturn, long labelId) {
            this.manifestBlake3 = manifestBlake3;
            this.entry = entry;
            this.isa = isa;
            this.functionId = functionId;
            this.primaryId = primaryId;
            this.primarySource = primarySource;
            this.primaryNameBlake3 = primaryNameBlake3;
            this.setNoReturn = setNoReturn;
            this.labelId = labelId;
        }
    }

    static final class Validated implements AutoCloseable {
        final Manifest manifest;
        final String identity;
        final Register tMode;
        final PmeScriptSupport.TrustedFile manifestFile;
        final PmeScriptSupport.TrustedFile rawFile;
        final PmeScriptSupport.TrustedFile scatterFile;
        final PmeScriptSupport.TrustedFile functionsFile;
        private boolean closed;

        Validated(Manifest manifest, String identity, Register tMode,
                PmeScriptSupport.TrustedFile manifestFile, PmeScriptSupport.TrustedFile rawFile,
                PmeScriptSupport.TrustedFile scatterFile,
                PmeScriptSupport.TrustedFile functionsFile) {
            this.manifest = manifest;
            this.identity = identity;
            this.tMode = tMode;
            this.manifestFile = manifestFile;
            this.rawFile = rawFile;
            this.scatterFile = scatterFile;
            this.functionsFile = functionsFile;
        }

        void verifyRetainedFiles() {
            manifestFile.verifyPathIdentity("startup metadata manifest");
            rawFile.verifyPathIdentity("startup metadata raw image");
            if (scatterFile != null) {
                scatterFile.verifyPathIdentity("startup metadata scatter map");
            }
            if (functionsFile != null) {
                functionsFile.verifyPathIdentity("startup metadata functions.json");
            }
        }

        @Override
        public void close() throws Exception {
            if (closed) return;
            closed = true;
            Throwable failure = null;
            failure = closeOne(functionsFile, failure);
            failure = closeOne(scatterFile, failure);
            failure = closeOne(rawFile, failure);
            failure = closeOne(manifestFile, failure);
            if (failure != null) rethrow(failure);
        }

        private static Throwable closeOne(AutoCloseable closeable, Throwable failure) {
            if (closeable == null) return failure;
            try {
                closeable.close();
            }
            catch (Throwable error) {
                if (failure == null) return error;
                suppress(failure, error);
            }
            return failure;
        }
    }

    static Validated preflight(Program program, TaskMonitor monitor, File kitRootArgument,
            String expectedLabel, String expectedImageBlake3, String expectedIdentity,
            File manifestArgument, String scatterArgument, File functionsArgument,
            String expectedFunctionsBlake3) throws Exception {
        if (monitor != null && monitor.isCancelled()) {
            fail("startup metadata preflight was cancelled");
        }
        PmeScriptSupport.assertGhidraSymbolLimit();
        File kitRoot = PmeScriptSupport.requireCanonicalDirectory(
                kitRootArgument, "startup metadata kit root");
        PmeScriptSupport.TrustedFile manifestFile = null;
        PmeScriptSupport.TrustedFile rawFile = null;
        PmeScriptSupport.TrustedFile scatterFile = null;
        PmeScriptSupport.TrustedFile functionsFile = null;
        try {
            manifestFile = PmeScriptSupport.openCanonicalContainedFile(
                    kitRoot, manifestArgument, "startup metadata manifest");
            byte[] manifestBytes = manifestFile.readAll(
                    MAX_MANIFEST_BYTES, "startup metadata manifest");
            String text = PmeScriptSupport.decodeUtf8(manifestBytes, "startup metadata manifest");
            Manifest manifest = parseManifest(text);
            byte[] canonical = PmeScriptSupport.canonicalJsonBytes(
                    text, "startup metadata manifest");
            if (!Arrays.equals(canonical, manifestBytes)) {
                fail("startup metadata manifest bytes are not in canonical field order or JSON spelling");
            }
            manifest.manifestBlake3 = PmeScriptSupport.blake3Hex(manifestBytes);
            validateManifestSemantics(manifest);

            if (!expectedLabel.equals(manifest.image.label)
                    || !expectedLabel.equals(program.getName())) {
                fail("startup metadata image label does not match the current program");
            }
            String identity = identity(manifest);
            if (!identity.equals(expectedIdentity)) {
                fail("startup metadata identity does not match the expected current run");
            }
            if (!HASH.matcher(expectedImageBlake3).matches()
                    || !expectedImageBlake3.equals(manifest.image.blake3)) {
                fail("startup metadata image BLAKE3 does not match the invocation");
            }

            rawFile = PmeScriptSupport.openContainedChild(kitRoot,
                    "images/" + expectedLabel, "startup metadata raw image");
            if (rawFile.size() != manifest.image.size
                    || !rawFile.blake3("startup metadata raw image").equals(manifest.image.blake3)) {
                fail("startup metadata raw image identity does not match the manifest");
            }

            if (manifest.runtime.scatterBlake3 == null) {
                if (!"-".equals(scatterArgument)
                        || !manifest.runtime.scatterEntriesUsed.isEmpty()) {
                    fail("raw-only startup metadata requires the explicit '-' scatter sentinel");
                }
            }
            else {
                if ("-".equals(scatterArgument)) {
                    fail("scatter-backed startup metadata requires a scatter map argument");
                }
                scatterFile = PmeScriptSupport.openCanonicalContainedFile(
                        kitRoot, new File(scatterArgument), "startup metadata scatter map");
                if (!manifest.runtime.scatterBlake3.equals(
                        scatterFile.blake3("startup metadata scatter map"))) {
                    fail("startup metadata scatter BLAKE3 does not match the manifest dependency");
                }
            }

            if (!HASH.matcher(expectedFunctionsBlake3).matches()
                    || !expectedFunctionsBlake3.equals(manifest.inventories.functionsBlake3)) {
                fail("startup metadata functions BLAKE3 does not match the invocation");
            }
            functionsFile = PmeScriptSupport.openCanonicalFile(
                    functionsArgument, "startup metadata functions.json");
            if (!expectedFunctionsBlake3.equals(
                    functionsFile.blake3("startup metadata functions.json"))) {
                fail("functions.json BLAKE3 does not match the retained file");
            }

            Register tMode = program.getLanguage().getRegister("TMode");
            if (tMode == null) {
                fail("the current language has no TMode register");
            }
            preflightProgramState(program, manifest, tMode);
            manifestFile.verifyPathIdentity("startup metadata manifest");
            rawFile.verifyPathIdentity("startup metadata raw image");
            if (scatterFile != null) {
                scatterFile.verifyPathIdentity("startup metadata scatter map");
            }
            functionsFile.verifyPathIdentity("startup metadata functions.json");
            Validated validated = new Validated(manifest, identity, tMode, manifestFile, rawFile,
                    scatterFile, functionsFile);
            manifestFile = null;
            rawFile = null;
            scatterFile = null;
            functionsFile = null;
            return validated;
        }
        catch (Throwable error) {
            closeQuietly(functionsFile, error);
            closeQuietly(scatterFile, error);
            closeQuietly(rawFile, error);
            closeQuietly(manifestFile, error);
            rethrow(error);
            return null;
        }
    }

    static String identity(Manifest manifest) {
        int noReturn = 0;
        for (Application application : manifest.applications) {
            if (application.setNoReturn) noReturn++;
        }
        return IDENTITY_VERSION + ":" + manifest.manifestBlake3 + ":"
                + manifest.applications.size() + ":" + noReturn + ":"
                + manifest.privilegedOps;
    }

    static StringPropertyMap currentRegistry(Program program) {
        return program.getUsrPropertyManager().getStringPropertyMap(OWNERSHIP_MAP);
    }

    static Namespace currentNamespace(Program program) {
        return program.getSymbolTable().getNamespace(
                RESERVED_NAMESPACE, program.getGlobalNamespace());
    }

    static String registryValue(RegistryEntry entry) {
        return String.join(":", IDENTITY_VERSION, entry.manifestBlake3,
                String.format(Locale.ROOT, "%08x", entry.entry), entry.isa,
                Long.toString(entry.functionId), Long.toString(entry.primaryId),
                entry.primarySource, entry.primaryNameBlake3,
                entry.setNoReturn ? "1" : "0", Long.toString(entry.labelId));
    }

    static RegistryEntry parseRegistry(String value) {
        if (value == null) fail("startup metadata registry value is missing");
        String[] parts = value.split(":", -1);
        if (parts.length != 10) {
            fail("startup metadata registry value does not have the exact v1 field count");
        }
        if (!IDENTITY_VERSION.equals(parts[0])) {
            fail("startup metadata registry value is not the v1 grammar");
        }
        String manifestBlake3 = hash(parts[1], "startup registry manifest BLAKE3");
        long entry = address("0x" + parts[2], "startup registry entry");
        String isa = isa(parts[3], "startup registry ISA");
        long functionId = unsigned(parts[4], Long.MAX_VALUE, "startup registry function ID");
        long primaryId = unsigned(parts[5], Long.MAX_VALUE, "startup registry primary ID");
        if (!"default".equals(parts[6]) && !"analysis".equals(parts[6])
                && !"imported".equals(parts[6]) && !"user_defined".equals(parts[6])
                && !"ai".equals(parts[6])) {
            fail("startup registry primary source is unknown");
        }
        String nameBlake3 = hash(parts[7], "startup registry primary-name BLAKE3");
        if (!"0".equals(parts[8]) && !"1".equals(parts[8])) {
            fail("startup registry set_no_return is not 0 or 1");
        }
        long labelId = unsigned(parts[9], Long.MAX_VALUE, "startup registry label ID");
        return new RegistryEntry(manifestBlake3, entry, isa, functionId, primaryId, parts[6],
                nameBlake3, "1".equals(parts[8]), labelId);
    }

    static String primaryNameDigest(String name) {
        return PmeScriptSupport.blake3Hex(PmeScriptSupport.boundedUtf8(
                name, MAX_SYMBOL_UTF8_BYTES, "startup metadata primary"));
    }

    static void validateApplied(Program program, Manifest manifest, String identity) {
        if (!identity.equals(identity(manifest))) {
            fail("startup metadata applied identity drifted");
        }
        Namespace namespace = currentNamespace(program);
        if (namespace == null) {
            fail("startup metadata reserved namespace is missing");
        }
        StringPropertyMap registry = currentRegistry(program);
        if (registry == null) {
            fail("startup metadata ownership registry is missing");
        }
        Register tMode = program.getLanguage().getRegister("TMode");
        if (tMode == null) {
            fail("the current language has no TMode register");
        }
        Set<String> expectedLabels = new HashSet<String>();
        Set<Long> expectedEntries = new HashSet<Long>();
        for (Application application : manifest.applications) {
            Address entry = PmeScriptSupport.programAddress(program, application.entry);
            Function function = program.getFunctionManager().getFunctionAt(entry);
            if (function == null || !function.getEntryPoint().equals(entry)) {
                fail("startup metadata applied function is missing at " + entry);
            }
            requireIsa(program, function, application, tMode);
            if (application.setNoReturn && !function.hasNoReturn()) {
                fail("startup metadata no-return is missing at " + entry);
            }
            Symbol label = program.getSymbolTable().getSymbol(
                    application.roleLabel, entry, namespace);
            if (label == null || label.getSource() != SourceType.ANALYSIS
                    || label.getSymbolType() != SymbolType.LABEL) {
                fail("startup metadata role label is missing at " + entry);
            }
            RegistryEntry retained = parseRegistry(registry.getString(entry));
            if (!retained.manifestBlake3.equals(manifest.manifestBlake3)
                    || retained.entry != application.entry
                    || !retained.isa.equals(application.isa)
                    || retained.functionId != function.getID()
                    || retained.primaryId != function.getSymbol().getID()
                    || !retained.primarySource.equals(
                            PmeScriptSupport.primarySource(function.getSymbol().getSource()))
                    || !retained.primaryNameBlake3.equals(
                            primaryNameDigest(function.getSymbol().getName()))
                    || retained.setNoReturn != application.setNoReturn
                    || retained.labelId != label.getID()) {
                fail("startup metadata ownership registry is stale at " + entry);
            }
            if (!expectedLabels.add(canonicalAddress(application.entry) + ":"
                    + application.roleLabel)
                    || !expectedEntries.add(application.entry)) {
                fail("startup metadata applied applications are not unique");
            }
        }
        Set<String> actualLabels = new HashSet<String>();
        SymbolIterator symbols = program.getSymbolTable().getSymbols(namespace);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getAddress() == null || symbol.getSource() != SourceType.ANALYSIS
                    || symbol.getSymbolType() != SymbolType.LABEL
                    || !actualLabels.add(canonicalAddress(symbol.getAddress().getOffset())
                            + ":" + symbol.getName())) {
                fail("startup metadata reserved namespace contains noncanonical state");
            }
        }
        if (!actualLabels.equals(expectedLabels)) {
            fail("startup metadata reserved namespace inventory is stale or partial");
        }
        Set<Long> actualEntries = new HashSet<Long>();
        ghidra.program.model.address.AddressIterator entries = registry.getPropertyIterator();
        while (entries.hasNext()) {
            Address entry = entries.next();
            RegistryEntry retained = parseRegistry(registry.getString(entry));
            if (!actualEntries.add(retained.entry) || retained.entry != entry.getOffset()) {
                fail("startup metadata registry contains noncanonical state");
            }
        }
        if (!actualEntries.equals(expectedEntries)) {
            fail("startup metadata registry inventory is stale or partial");
        }
    }

    static void validateAbsent(Program program) {
        StringPropertyMap registry = currentRegistry(program);
        if (registry != null && registry.getSize() > 0) {
            fail("startup metadata ownership registry is not empty");
        }
        Namespace namespace = currentNamespace(program);
        if (namespace != null) {
            SymbolIterator symbols = program.getSymbolTable().getSymbols(namespace);
            while (symbols.hasNext()) {
                symbols.next();
                fail("startup metadata reserved namespace is not empty");
            }
        }
    }

    static Validated retainForExport(Program program, File kitRootArgument, String expectedLabel,
            String expectedIdentity, File manifestArgument, String scatterArgument)
            throws Exception {
        PmeScriptSupport.assertGhidraSymbolLimit();
        File kitRoot = PmeScriptSupport.requireCanonicalDirectory(
                kitRootArgument, "startup metadata kit root");
        PmeScriptSupport.TrustedFile manifestFile = null;
        PmeScriptSupport.TrustedFile rawFile = null;
        PmeScriptSupport.TrustedFile scatterFile = null;
        try {
            manifestFile = PmeScriptSupport.openCanonicalContainedFile(
                    kitRoot, manifestArgument, "startup metadata manifest");
            byte[] manifestBytes = manifestFile.readAll(
                    MAX_MANIFEST_BYTES, "startup metadata manifest");
            String text = PmeScriptSupport.decodeUtf8(manifestBytes, "startup metadata manifest");
            Manifest manifest = parseManifest(text);
            byte[] canonical = PmeScriptSupport.canonicalJsonBytes(
                    text, "startup metadata manifest");
            if (!Arrays.equals(canonical, manifestBytes)) {
                fail("startup metadata manifest bytes are not in canonical field order or JSON spelling");
            }
            manifest.manifestBlake3 = PmeScriptSupport.blake3Hex(manifestBytes);
            if (!expectedLabel.equals(manifest.image.label)
                    || !expectedLabel.equals(program.getName())) {
                fail("startup metadata image label does not match the current program");
            }
            String identity = identity(manifest);
            if (!identity.equals(expectedIdentity)) {
                fail("startup metadata identity does not match the expected current run");
            }
            rawFile = PmeScriptSupport.openContainedChild(kitRoot,
                    "images/" + expectedLabel, "startup metadata raw image");
            if (rawFile.size() != manifest.image.size
                    || !rawFile.blake3("startup metadata raw image").equals(manifest.image.blake3)) {
                fail("startup metadata raw image identity does not match the manifest");
            }
            if (manifest.runtime.scatterBlake3 == null) {
                if (!"-".equals(scatterArgument)
                        || !manifest.runtime.scatterEntriesUsed.isEmpty()) {
                    fail("raw-only startup metadata requires the explicit '-' scatter sentinel");
                }
            }
            else {
                if ("-".equals(scatterArgument)) {
                    fail("scatter-backed startup metadata requires a scatter map argument");
                }
                scatterFile = PmeScriptSupport.openCanonicalContainedFile(
                        kitRoot, new File(scatterArgument), "startup metadata scatter map");
                if (!manifest.runtime.scatterBlake3.equals(
                        scatterFile.blake3("startup metadata scatter map"))) {
                    fail("startup metadata scatter BLAKE3 does not match the manifest dependency");
                }
            }
            Register tMode = program.getLanguage().getRegister("TMode");
            if (tMode == null) {
                fail("the current language has no TMode register");
            }
            manifestFile.verifyPathIdentity("startup metadata manifest");
            rawFile.verifyPathIdentity("startup metadata raw image");
            if (scatterFile != null) {
                scatterFile.verifyPathIdentity("startup metadata scatter map");
            }
            Validated validated = new Validated(manifest, identity, tMode, manifestFile, rawFile,
                    scatterFile, null);
            manifestFile = null;
            rawFile = null;
            scatterFile = null;
            return validated;
        }
        catch (Throwable error) {
            closeQuietly(scatterFile, error);
            closeQuietly(rawFile, error);
            closeQuietly(manifestFile, error);
            rethrow(error);
            return null;
        }
    }

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
            name(reader, "inventories");
            Inventories inventories = readInventories(reader);
            name(reader, "decoder");
            readDecoder(reader);
            name(reader, "exception_roots");
            String exceptionRoots = nullablePrintable(reader, 256, "exception_roots");
            name(reader, "hardware_init");
            Section hardware = readHardware(reader);
            name(reader, "stack_guard");
            Section stack = readStackGuard(reader);
            name(reader, "compiler");
            readCompiler(reader);
            name(reader, "privileged_ops");
            int privilegedOps = readPrivilegedOps(reader);
            name(reader, "applications");
            List<Application> applications = readArray(reader, MAX_APPLICATIONS,
                    StartupMetadataSupport::readApplication, "applications");
            reader.endObject();
            if (reader.peek() != JsonToken.END_DOCUMENT) {
                fail("startup metadata manifest has trailing JSON");
            }
            return new Manifest(toolVersion, image, runtime, inventories, exceptionRoots,
                    hardware.present, hardware.entry, hardware.isa, stack.present, stack.entry,
                    stack.isa, stack.nonReturn, applications, privilegedOps);
        }
        catch (StartupError error) {
            throw error;
        }
        catch (Exception error) {
            throw new StartupError("malformed startup metadata manifest", error);
        }
    }

    private static final class Section {
        final boolean present;
        final long entry;
        final String isa;
        final boolean nonReturn;

        Section(boolean present, long entry, String isa, boolean nonReturn) {
            this.present = present;
            this.entry = entry;
            this.isa = isa;
            this.nonReturn = nonReturn;
        }
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
        List<Long> entries = readLongArray(reader, MAX_SCATTER_ENTRIES,
                PmeScriptSupport.UINT32_MAX, "runtime.scatter_entries_used");
        reader.endObject();
        return new RuntimeInfo(scatter, entries);
    }

    private static Inventories readInventories(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "functions_blake3");
        String functions = hashValue(reader, "inventories.functions_blake3");
        name(reader, "thumb_functions_blake3");
        String thumb = nullableHash(reader, "inventories.thumb_functions_blake3");
        reader.endObject();
        return new Inventories(functions, thumb);
    }

    private static void readDecoder(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "crate");
        exact(reader, BACKEND_CRATE, "decoder.crate");
        name(reader, "version");
        exact(reader, BACKEND_VERSION, "decoder.version");
        reader.endObject();
    }

    private static Section readHardware(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "status");
        String status = oneOf(stringValue(reader, "hardware_init.status"),
                "hardware_init.status", "absent", "present");
        if ("absent".equals(status)) {
            reader.endObject();
            return new Section(false, 0, null, false);
        }
        name(reader, "entry");
        long entry = addressValue(reader, "hardware_init.entry");
        name(reader, "isa");
        String isa = isa(stringValue(reader, "hardware_init.isa"), "hardware_init.isa");
        name(reader, "owner");
        readOwner(reader);
        name(reader, "execution_blake3");
        hashValue(reader, "hardware_init.execution_blake3");
        reader.endObject();
        return new Section(true, entry, isa, false);
    }

    private static Section readStackGuard(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "status");
        String status = oneOf(stringValue(reader, "stack_guard.status"),
                "stack_guard.status", "absent", "present");
        if ("absent".equals(status)) {
            reader.endObject();
            return new Section(false, 0, null, false);
        }
        name(reader, "entry");
        long entry = addressValue(reader, "stack_guard.entry");
        name(reader, "isa");
        String isa = isa(stringValue(reader, "stack_guard.isa"), "stack_guard.isa");
        name(reader, "owner");
        readOwner(reader);
        name(reader, "execution_blake3");
        hashValue(reader, "stack_guard.execution_blake3");
        name(reader, "non_return");
        boolean nonReturn = booleanValue(reader, "stack_guard.non_return");
        reader.endObject();
        return new Section(true, entry, isa, nonReturn);
    }

    private static void readCompiler(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "status");
        String status = oneOf(stringValue(reader, "compiler.status"),
                "compiler.status", "absent", "present");
        if ("absent".equals(status)) {
            reader.endObject();
            return;
        }
        name(reader, "format_address");
        addressValue(reader, "compiler.format_address");
        name(reader, "format_len");
        unsignedValue(reader, PmeScriptSupport.UINT32_MAX, "compiler.format_len");
        name(reader, "format_blake3");
        hashValue(reader, "compiler.format_blake3");
        name(reader, "callsite_pc");
        addressValue(reader, "compiler.callsite_pc");
        name(reader, "isa");
        isa(stringValue(reader, "compiler.isa"), "compiler.isa");
        name(reader, "operands");
        readLongArray(reader, MAX_OPERANDS, PmeScriptSupport.UINT32_MAX, "compiler.operands");
        reader.endObject();
    }

    private static int readPrivilegedOps(JsonReader reader) throws IOException {
        List<Object> ops = readArray(reader, MAX_PRIVILEGED_OPS, input -> {
            readPrivilegedOp(input);
            return Boolean.TRUE;
        }, "privileged_ops");
        return ops.size();
    }

    private static void readPrivilegedOp(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "pc");
        addressValue(reader, "privileged_ops.pc");
        name(reader, "isa");
        isa(stringValue(reader, "privileged_ops.isa"), "privileged_ops.isa");
        name(reader, "entry");
        addressValue(reader, "privileged_ops.entry");
        name(reader, "owner");
        readOwner(reader);
        name(reader, "execution_blake3");
        hashValue(reader, "privileged_ops.execution_blake3");
        name(reader, "direction");
        oneOf(stringValue(reader, "privileged_ops.direction"),
                "privileged_ops.direction", "read", "write");
        name(reader, "class");
        oneOf(stringValue(reader, "privileged_ops.class"), "privileged_ops.class",
                "midr", "features", "sctlr", "ttbr", "ttbcr", "dacr", "fault",
                "cache_tlb", "pmu", "vbar", "context_id", "cpsr_spsr", "unclassified");
        name(reader, "coprocessor");
        nullableUnsigned(reader, 255, "privileged_ops.coprocessor");
        name(reader, "opcode1");
        nullableUnsigned(reader, 255, "privileged_ops.opcode1");
        name(reader, "crn");
        nullableUnsigned(reader, 255, "privileged_ops.crn");
        name(reader, "crm");
        nullableUnsigned(reader, 255, "privileged_ops.crm");
        name(reader, "opcode2");
        nullableUnsigned(reader, 255, "privileged_ops.opcode2");
        name(reader, "register");
        nullableUnsigned(reader, 15, "privileged_ops.register");
        name(reader, "immediate");
        nullableUnsigned(reader, PmeScriptSupport.UINT32_MAX, "privileged_ops.immediate");
        reader.endObject();
    }

    private static void readOwner(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "kind");
        String kind = oneOf(stringValue(reader, "owner.kind"),
                "owner.kind", "ghidra", "legacy", "run");
        if ("ghidra".equals(kind)) {
            reader.endObject();
            return;
        }
        name(reader, "producer");
        oneOf(stringValue(reader, "owner.producer"),
                "owner.producer", "ghidra", "radare2", "rizin");
        if ("legacy".equals(kind)) {
            reader.endObject();
            return;
        }
        name(reader, "region_index");
        unsignedValue(reader, PmeScriptSupport.UINT32_MAX, "owner.region_index");
        name(reader, "run_index");
        unsignedValue(reader, PmeScriptSupport.UINT32_MAX, "owner.run_index");
        reader.endObject();
    }

    private static Application readApplication(JsonReader reader) throws IOException {
        reader.beginObject();
        name(reader, "role");
        String role = oneOf(stringValue(reader, "application.role"),
                "application.role", "hardware_init", "stack_protection_failure");
        name(reader, "entry");
        long entry = addressValue(reader, "application.entry");
        name(reader, "isa");
        String isa = isa(stringValue(reader, "application.isa"), "application.isa");
        name(reader, "desired_primary");
        String desired = PmeScriptSupport.requireSymbolLeaf(
                stringValue(reader, "application.desired_primary"),
                MAX_SYMBOL_UTF8_BYTES, "application.desired_primary");
        name(reader, "role_label");
        String label = PmeScriptSupport.requireSymbolLeaf(
                stringValue(reader, "application.role_label"),
                MAX_SYMBOL_UTF8_BYTES, "application.role_label");
        name(reader, "set_no_return");
        boolean setNoReturn = booleanValue(reader, "application.set_no_return");
        reader.endObject();
        return new Application(role, entry, isa, desired, label, setNoReturn);
    }

    private static void validateManifestSemantics(Manifest manifest) {
        requireSortedUnique(manifest.runtime.scatterEntriesUsed, "scatter_entries_used");
        if (!manifest.runtime.scatterEntriesUsed.isEmpty()
                && manifest.runtime.scatterBlake3 == null) {
            fail("scatter-backed evidence has no complete load-map dependency");
        }
        boolean sawHardware = false;
        boolean sawStack = false;
        int noReturn = 0;
        for (Application application : manifest.applications) {
            if ("hardware_init".equals(application.role)) {
                if (sawHardware || sawStack) fail("applications are not in role order");
                if (!"hw_Init".equals(application.desiredPrimary)
                        || !"startup_hardware_init".equals(application.roleLabel)) {
                    fail("application names do not match the closed role");
                }
                if (application.setNoReturn) fail("hardware_init cannot set no-return");
                if (!manifest.hardwarePresent
                        || manifest.hardwareEntry != application.entry
                        || !application.isa.equals(manifest.hardwareIsa)) {
                    fail("hardware_init application does not match the present section");
                }
                sawHardware = true;
            }
            else if ("stack_protection_failure".equals(application.role)) {
                if (sawStack) fail("duplicate stack_guard application");
                if (!"StackProtectionFailure".equals(application.desiredPrimary)
                        || !"startup_stack_protection_failure".equals(application.roleLabel)) {
                    fail("application names do not match the closed role");
                }
                if (!manifest.stackPresent
                        || manifest.stackEntry != application.entry
                        || !application.isa.equals(manifest.stackIsa)
                        || application.setNoReturn != manifest.stackNonReturn) {
                    fail("stack_guard application does not match the present section");
                }
                sawStack = true;
            }
            else {
                fail("role is not a closed startup role");
            }
            if (application.setNoReturn) noReturn++;
        }
        if (manifest.hardwarePresent && !sawHardware) {
            fail("present hardware_init has no application");
        }
        if (manifest.stackPresent && !sawStack) {
            fail("present stack_guard has no application");
        }
        if (noReturn > 1) fail("startup metadata no-return count exceeds one");
        for (int index = 0; index < manifest.applications.size(); index++) {
            Application application = manifest.applications.get(index);
            for (int prior = 0; prior < index; prior++) {
                Application other = manifest.applications.get(prior);
                if (other.entry == application.entry && other.isa.equals(application.isa)) {
                    fail("hardware_init and stack_guard share entry "
                            + canonicalAddress(application.entry));
                }
            }
        }
    }

    private static void preflightProgramState(Program program, Manifest manifest, Register tMode) {
        List<AddressSet> spans = new ArrayList<AddressSet>();
        for (Application application : manifest.applications) {
            Address entry = PmeScriptSupport.programAddress(program, application.entry);
            Function function = program.getFunctionManager().getFunctionAt(entry);
            if (function == null || !function.getEntryPoint().equals(entry)) {
                fail("startup metadata application does not exist as a function at " + entry);
            }
            Instruction instruction = program.getListing().getInstructionAt(entry);
            if (instruction == null) {
                fail("startup metadata application has no instruction at " + entry);
            }
            requireIsa(program, function, application, tMode);
            AddressSet span = new AddressSet(entry, instruction.getMaxAddress());
            if (!function.getBody().contains(span)) {
                fail("startup metadata function body does not contain its instruction at "
                        + entry);
            }
            for (AddressSet prior : spans) {
                if (prior.intersects(span)) {
                    fail("startup metadata applications have colliding instruction spans");
                }
            }
            spans.add(span);
        }
    }

    private static void requireIsa(Program program, Function function, Application application,
            Register tMode) {
        Address entry = function.getEntryPoint();
        Instruction instruction = program.getListing().getInstructionAt(entry);
        if (instruction == null) {
            fail("startup metadata instruction is missing at " + entry);
        }
        if (("arm".equals(application.isa) && instruction.getLength() != 4)
                || ("thumb".equals(application.isa)
                        && instruction.getLength() != 2 && instruction.getLength() != 4)) {
            fail("startup metadata instruction length does not match ISA at " + entry);
        }
        BigInteger expected = "thumb".equals(application.isa) ? BigInteger.ONE : BigInteger.ZERO;
        Address end = instruction.getMaxAddress();
        Address cursor = entry;
        while (true) {
            RegisterValue value = program.getProgramContext().getRegisterValue(tMode, cursor);
            if (value == null || !value.hasValue()
                    || !expected.equals(value.getUnsignedValue())) {
                fail("startup metadata instruction ISA does not match at " + entry);
            }
            if (cursor.equals(end)) break;
            cursor = cursor.next();
            if (cursor == null) fail("startup metadata instruction span wraps at " + entry);
        }
    }

    static String canonicalAddress(long address) {
        return String.format(Locale.ROOT, "0x%08x", address);
    }

    static String boundReason(String reason) {
        String bounded = reason;
        if (bounded == null || bounded.isEmpty()) {
            bounded = "startup metadata map preflight failed";
        }
        int count = bounded.codePointCount(0, bounded.length());
        if (count > MAX_REASON_CODE_POINTS) {
            int end = bounded.offsetByCodePoints(0, MAX_REASON_CODE_POINTS);
            bounded = bounded.substring(0, end);
        }
        return bounded;
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

    private static String nullablePrintable(JsonReader reader, int maximumBytes, String what)
            throws IOException {
        if (reader.peek() == JsonToken.NULL) {
            reader.nextNull();
            return null;
        }
        return printable(stringValue(reader, what), maximumBytes, what);
    }

    private static Long nullableUnsigned(JsonReader reader, long maximum, String what)
            throws IOException {
        if (reader.peek() == JsonToken.NULL) {
            reader.nextNull();
            return null;
        }
        return unsignedValue(reader, maximum, what);
    }

    private static boolean booleanValue(JsonReader reader, String what) throws IOException {
        if (reader.peek() != JsonToken.BOOLEAN) fail(what + " is not boolean");
        return reader.nextBoolean();
    }

    private static long address(String value, String what) {
        if (!ADDRESS.matcher(value).matches()) fail(what + " is not a canonical u32 address");
        return Long.parseUnsignedLong(value.substring(2), 16);
    }

    private static String hash(String value, String what) {
        if (!HASH.matcher(value).matches()) fail(what + " is not lowercase BLAKE3");
        return value;
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
            throw new StartupError(what + " exceeds the signed parser domain", error);
        }
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

    private static String isa(String value, String what) {
        return oneOf(value, what, "arm", "thumb");
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
        if (!reader.hasNext()) fail("startup metadata object ended before " + wanted);
        String actual = reader.nextName();
        if (!wanted.equals(actual)) {
            fail("startup metadata object expected key " + wanted + " but found " + actual);
        }
    }

    private static void requireSortedUnique(List<Long> values, String what) {
        long prior = -1;
        for (long value : values) {
            if (value <= prior) fail(what + " is not sorted and unique");
            prior = value;
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
        throw new StartupError(message);
    }
}
