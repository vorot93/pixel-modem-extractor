// ApplyScatterLoad.java - strict pre-analysis scatter block applicator.
// Arg[0] = canonical import-kit root.
// Arg[1] = expected image label.
// Arg[2] = canonical scatter load-map path.
//@category PixelModem
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import org.bouncycastle.crypto.digests.Blake3Digest;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

// A failed HeadlessScript aborts follow-on analysis/scripts while preserving the
// imported raw program, unlike a plain GhidraScript whose exception is ignored.
public class ApplyScatterLoad extends HeadlessScript {
    private static final String FORMAT = "pixel-modem-extractor-scatter-load-v1";
    private static final long UINT32_MAX = 0xffff_ffffL;
    private static final long UINT32_END = 0x1_0000_0000L;
    private static final int MAX_ENTRIES = 256;
    private static final long MAX_LOGICAL_OUTPUT = 512L * 1024L * 1024L;
    private static final int MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final Pattern ADDRESS = Pattern.compile("^0x[0-9a-f]{8}$");
    private static final Pattern HASH = Pattern.compile("^[0-9a-f]{64}$");
    private static final Pattern LABEL = Pattern.compile("^[A-Za-z0-9_.-]+$");
    private static final Pattern UNSIGNED_INTEGER = Pattern.compile("^(0|[1-9][0-9]*)$");

    private static final class MapError extends Exception {
        MapError(String message) {
            super(message);
        }

        MapError(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static final class LexicalNumber extends Number {
        private static final long serialVersionUID = 1L;
        private final String text;

        LexicalNumber(String text) {
            this.text = text;
        }

        private BigDecimal value() {
            return new BigDecimal(text);
        }

        @Override
        public int intValue() {
            return value().intValue();
        }

        @Override
        public long longValue() {
            return value().longValue();
        }

        @Override
        public float floatValue() {
            return value().floatValue();
        }

        @Override
        public double doubleValue() {
            return value().doubleValue();
        }

        @Override
        public String toString() {
            return text;
        }
    }

    private static final class Candidate {
        final int index;
        final String name;
        final Address start;
        final long size;
        final String outputHash;
        final RetainedPayload payload;

        Candidate(int index, String name, Address start, long size, String outputHash,
                RetainedPayload payload) {
            this.index = index;
            this.name = name;
            this.start = start;
            this.size = size;
            this.outputHash = outputHash;
            this.payload = payload;
        }
    }

    // Keeps the validated file identity open through mutation. The created-block
    // hash below also rejects in-place changes made through another handle.
    private static final class RetainedPayload {
        private final FileInputStream input;
        private boolean closed;

        RetainedPayload(FileInputStream input) {
            this.input = input;
        }

        InputStream input() throws IOException {
            input.getChannel().position(0);
            return input;
        }

        void close() throws IOException {
            if (!closed) {
                input.close();
                closed = true;
            }
        }
    }

    private static final class Preflight {
        final String label;
        final List<Candidate> candidates;
        final List<RetainedPayload> payloads;
        final long logicalBytes;

        Preflight(String label, List<Candidate> candidates, List<RetainedPayload> payloads,
                long logicalBytes) {
            this.label = label;
            this.candidates = candidates;
            this.payloads = payloads;
            this.logicalBytes = logicalBytes;
        }
    }

    private static final class Handlers {
        final long nullHandler;
        final long copyHandler;
        final long decompress1Handler;
        final long zeroHandler;

        Handlers(long nullHandler, long copyHandler, long decompress1Handler, long zeroHandler) {
            this.nullHandler = nullHandler;
            this.copyHandler = copyHandler;
            this.decompress1Handler = decompress1Handler;
            this.zeroHandler = zeroHandler;
        }

        long forOperation(String operation) throws MapError {
            switch (operation) {
                case "null":
                    return nullHandler;
                case "copy":
                    return copyHandler;
                case "decompress1":
                    return decompress1Handler;
                case "zero":
                    return zeroHandler;
                default:
                    throw new MapError("unsupported scatter operation " + operation);
            }
        }
    }

    @Override
    public void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        List<MemoryBlock> created = new ArrayList<>();
        Preflight preflight = preflight();
        try {
            for (Candidate candidate : preflight.candidates) {
                MemoryBlock block;
                if (candidate.payload == null) {
                    block = memory.createInitializedBlock(candidate.name, candidate.start,
                            candidate.size, (byte) 0, monitor, false);
                    created.add(block);
                }
                else {
                    block = memory.createInitializedBlock(candidate.name, candidate.start,
                            candidate.payload.input(), candidate.size, monitor, false);
                    created.add(block);
                }
                block.setRead(true);
                block.setWrite(true);
                block.setExecute(false);
                block.setVolatile(false);
                if (!block.isInitialized() || !block.isRead() || !block.isWrite()
                        || block.isExecute() || block.isVolatile()) {
                    throw new MapError(
                            "scatter block permissions failed verification for entry "
                                    + candidate.index);
                }
                String actualHash = hashMemory(block.getStart(), candidate.size,
                        "created scatter block for entry " + candidate.index);
                if (!actualHash.equals(candidate.outputHash)) {
                    throw new MapError(
                            "created scatter block hash failed verification for entry "
                                    + candidate.index);
                }
                if (candidate.payload != null) {
                    candidate.payload.close();
                }
            }
            closePayloadsOrThrow(preflight.payloads);
        }
        catch (Throwable failure) {
            // Ghidra commits a script transaction even when run() throws. Abort
            // explicitly after best-effort cleanup so unreturned partial creates
            // and failed removals cannot survive executeNormal's final end(true).
            recoverMutationFailure(memory, created, preflight.payloads, failure);
            if (failure instanceof Exception) {
                throw (Exception) failure;
            }
            if (failure instanceof Error) {
                throw (Error) failure;
            }
            throw new RuntimeException(failure);
        }

        println("ApplyScatterLoad: created " + created.size() + " block(s), "
                + preflight.logicalBytes + " logical byte(s) for " + preflight.label);
    }

    private Preflight preflight() throws MapError {
        List<RetainedPayload> payloads = new ArrayList<>();
        try {
            return preflight(payloads);
        }
        catch (MapError failure) {
            closePayloads(payloads, failure);
            throw failure;
        }
        catch (RuntimeException | Error failure) {
            closePayloads(payloads, failure);
            throw failure;
        }
    }

    private Preflight preflight(List<RetainedPayload> payloads) throws MapError {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new MapError("expected exactly three arguments: root, image label, load map");
        }
        File root = requireCanonicalDirectoryArgument(args[0], "import-kit root");
        String expectedLabel = args[1];
        if (!isSafeLabel(expectedLabel)) {
            throw new MapError("expected image label is not a safe path component");
        }
        File mapFile = requireCanonicalFileArgument(args[2], "scatter load map");
        if (!isStrictlyContained(root, mapFile)) {
            throw new MapError("scatter load map escapes the import-kit root");
        }
        File mapParent;
        try {
            mapParent = mapFile.getParentFile().getCanonicalFile();
        }
        catch (IOException error) {
            throw new MapError("scatter load-map parent cannot be canonicalized", error);
        }
        if (!isStrictlyContained(root, mapParent)) {
            throw new MapError("scatter load-map directory escapes the import-kit root");
        }

        JsonObject document = readDocument(mapFile);
        requireExactKeys(document, "load-map root", "format", "schema_version",
                "tool_version", "image", "loader", "table", "entries");
        if (!FORMAT.equals(requireString(document, "format", "load-map root"))) {
            throw new MapError("unexpected scatter load-map format");
        }
        if (requireUnsigned(document, "schema_version", 1, "load-map root") != 1) {
            throw new MapError("unsupported scatter load-map schema version");
        }
        if (requireString(document, "tool_version", "load-map root").isEmpty()) {
            throw new MapError("load-map tool_version is empty");
        }

        JsonObject image = requireObject(document, "image", "load-map root");
        requireExactKeys(image, "image", "label", "base_addr", "size", "blake3");
        String label = requireString(image, "label", "image");
        if (!label.equals(expectedLabel) || !label.equals(currentProgram.getName())) {
            throw new MapError("load-map image does not match the argument and current program");
        }
        String imageHash = requireHash(image, "blake3", "image");
        long imageBase = requireAddress(image, "base_addr", "image");
        long imageSize = requireUnsigned(image, "size", Integer.MAX_VALUE, "image");
        if (imageSize == 0) {
            throw new MapError("raw image size is zero");
        }
        long imageEnd = checkedEnd(imageBase, imageSize, "raw image");

        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Address imageStart = toAddress(space, imageBase, "raw image base");
        Address imageLast = toAddress(space, imageEnd - 1, "raw image end");
        Memory memory = currentProgram.getMemory();
        MemoryBlock rawBlock = memory.getBlock(imageStart);
        if (rawBlock == null || !rawBlock.getStart().equals(imageStart)
                || !rawBlock.getEnd().equals(imageLast) || rawBlock.getSize() != imageSize
                || !rawBlock.isInitialized()) {
            throw new MapError("raw image block does not exactly match the declared image range");
        }

        File rawImage;
        try {
            rawImage = new File(new File(root, "images"), label).getCanonicalFile();
        }
        catch (IOException error) {
            throw new MapError("raw image path cannot be canonicalized", error);
        }
        if (!isStrictlyContained(root, rawImage) || !rawImage.isFile() || !rawImage.canRead()) {
            throw new MapError("raw image is not a contained readable regular file");
        }
        validateFile(rawImage, imageSize, imageHash, imageStart, "raw image");

        validateLoader(document, imageBase, imageEnd);
        JsonArray entries = requireArray(document, "entries", "load-map root");
        Handlers handlers = validateTable(document, entries, imageBase, imageEnd);

        Set<Integer> indices = new HashSet<>();
        Set<String> names = new HashSet<>();
        List<Candidate> candidates = new ArrayList<>();
        long logicalBytes = 0;
        for (int position = 0; position < entries.size(); position++) {
            JsonElement element = entries.get(position);
            if (!element.isJsonObject()) {
                throw new MapError("scatter entry " + position + " is not an object");
            }
            JsonObject entry = element.getAsJsonObject();
            String context = "scatter entry " + position;
            requireKeys(entry, context,
                    new String[] { "index", "source", "destination", "size", "handler",
                        "operation", "materialization" },
                    new String[] { "compressed_size", "output_blake3" });
            int index = (int) requireUnsigned(entry, "index", entries.size() - 1L, context);
            if (index != position) {
                throw new MapError(context + " index does not match its array position");
            }
            if (!indices.add(index)) {
                throw new MapError("duplicate scatter entry index " + index);
            }
            long source = requireAddress(entry, "source", context);
            long destination = requireAddress(entry, "destination", context);
            long size = requireUnsigned(entry, "size", UINT32_MAX, context);
            long handler = requireAddress(entry, "handler", context);
            String operation = requireString(entry, "operation", context);
            if (handler != handlers.forOperation(operation)) {
                throw new MapError(context + " handler does not match its operation");
            }

            if ("decompress1".equals(operation)) {
                long compressedSize = requireUnsigned(entry, "compressed_size", Integer.MAX_VALUE,
                        context);
                if (compressedSize == 0) {
                    throw new MapError(context + " compressed_size is zero");
                }
                requireWithinRaw(source, compressedSize, imageBase, imageEnd,
                        context + " compressed source");
            }
            else if (entry.has("compressed_size")) {
                throw new MapError(context + " has compressed_size for a non-decompress entry");
            }

            String outputHash = null;
            if ("null".equals(operation)) {
                if (entry.has("output_blake3")) {
                    throw new MapError(context + " null operation has output_blake3");
                }
            }
            else {
                outputHash = requireHash(entry, "output_blake3", context);
            }

            JsonObject materialization = requireObject(entry, "materialization", context);
            String kind = requireString(materialization, "kind", context + " materialization");
            if ("null".equals(operation)) {
                requireExactKeys(materialization, context + " materialization", "kind");
                if (!"none".equals(kind) || size != 0) {
                    throw new MapError(context + " null operation must be a zero-size none entry");
                }
                continue;
            }

            if (size == 0 || size > Integer.MAX_VALUE) {
                throw new MapError(context + " size is outside 1..Integer.MAX_VALUE");
            }
            long destinationEnd = checkedEnd(destination, size, context + " destination");
            logicalBytes = addLogicalBytes(logicalBytes, size, context);

            if ("copy".equals(operation)) {
                requireWithinRaw(source, size, imageBase, imageEnd, context + " copy source");
            }

            if ("none".equals(kind)) {
                requireExactKeys(materialization, context + " materialization", "kind");
                if (!"copy".equals(operation) || source != destination) {
                    throw new MapError(context + " none entry is not an exact self-copy");
                }
                String actual = hashMemory(toAddress(space, source, context + " source"), size,
                        context + " self-copy");
                if (!actual.equals(outputHash)) {
                    throw new MapError(context + " self-copy output hash does not match memory");
                }
                continue;
            }

            RetainedPayload payload = null;
            if ("file".equals(kind)) {
                requireExactKeys(materialization, context + " materialization", "kind", "path",
                        "size");
                if (!"copy".equals(operation) && !"decompress1".equals(operation)) {
                    throw new MapError(context + " file materialization has an invalid operation");
                }
                if ("copy".equals(operation) && source == destination) {
                    throw new MapError(context + " exact self-copy must use none materialization");
                }
                long payloadSize = requireUnsigned(materialization, "size", Integer.MAX_VALUE,
                        context + " materialization");
                if (payloadSize != size) {
                    throw new MapError(context + " payload size does not match entry size");
                }
                File payloadFile = resolvePayload(mapParent,
                        requireString(materialization, "path", context + " materialization"),
                        context);
                Address copySource = "copy".equals(operation)
                        ? toAddress(space, source, context + " copy source") : null;
                payload = openValidatedPayload(payloadFile, size, outputHash, copySource,
                        context + " payload");
                retainPayload(payloads, payload);
            }
            else if ("zero_fill".equals(kind)) {
                requireExactKeys(materialization, context + " materialization", "kind");
                if (!"zero".equals(operation) && !"decompress1".equals(operation)) {
                    throw new MapError(
                            context + " zero_fill materialization has an invalid operation");
                }
                if (!hashZeros(size).equals(outputHash)) {
                    throw new MapError(context + " zero_fill output hash is incorrect");
                }
            }
            else {
                throw new MapError(context + " has unsupported materialization kind " + kind);
            }

            Address start = toAddress(space, destination, context + " destination");
            Address end = toAddress(space, destinationEnd - 1, context + " destination end");
            rejectExistingCollision(memory, start, end, context);
            for (Candidate other : candidates) {
                Address otherEnd = other.start.add(other.size - 1);
                if (rangesOverlap(start, end, other.start, otherEnd)) {
                    throw new MapError(context + " overlaps scatter entry " + other.index);
                }
            }
            String name = String.format(Locale.ROOT, "SCATTER_%s_%02d",
                    operation.toUpperCase(Locale.ROOT), index);
            if (!names.add(name)) {
                throw new MapError("duplicate generated scatter block name " + name);
            }
            if (memory.getBlock(name) != null) {
                throw new MapError("generated scatter block name already exists: " + name);
            }
            candidates.add(new Candidate(index, name, start, size, outputHash, payload));
        }
        if (indices.size() != entries.size()) {
            throw new MapError("scatter entry indices are not complete");
        }
        return new Preflight(label, candidates, payloads, logicalBytes);
    }

    private void validateLoader(JsonObject document, long imageBase, long imageEnd)
            throws MapError {
        JsonObject loader = requireObject(document, "loader", "load-map root");
        requireExactKeys(loader, "loader", "address", "literal_pair");
        requireWithinRaw(requireAddress(loader, "address", "loader"), 16, imageBase, imageEnd,
                "loader instruction window");
        requireWithinRaw(requireAddress(loader, "literal_pair", "loader"), 8, imageBase, imageEnd,
                "loader literal pair");
    }

    private Handlers validateTable(JsonObject document, JsonArray entries, long imageBase,
            long imageEnd) throws MapError {
        JsonObject table = requireObject(document, "table", "load-map root");
        requireExactKeys(table, "table", "start", "end", "entry_count", "handlers");
        long start = requireAddress(table, "start", "table");
        long end = requireAddress(table, "end", "table");
        long entryCount = requireUnsigned(table, "entry_count", MAX_ENTRIES, "table");
        if (entryCount == 0 || entryCount != entries.size()) {
            throw new MapError("table entry_count does not match the non-empty entries array");
        }
        long expectedLength = entryCount * 16;
        if (end <= start || end - start != expectedLength) {
            throw new MapError("table range does not exactly match entry_count descriptors");
        }
        requireWithinRaw(start, expectedLength, imageBase, imageEnd, "scatter table");

        JsonObject object = requireObject(table, "handlers", "table");
        requireExactKeys(object, "table handlers", "null", "copy", "decompress1", "zero");
        Handlers handlers = new Handlers(
                requireAddress(object, "null", "table handlers"),
                requireAddress(object, "copy", "table handlers"),
                requireAddress(object, "decompress1", "table handlers"),
                requireAddress(object, "zero", "table handlers"));
        Set<Long> distinct = new HashSet<>(Arrays.asList(handlers.nullHandler,
                handlers.copyHandler, handlers.decompress1Handler, handlers.zeroHandler));
        if (distinct.size() != 4) {
            throw new MapError("table handlers are not four distinct addresses");
        }
        for (long handler : distinct) {
            requireWithinRaw(handler & ~1L, 1, imageBase, imageEnd, "table handler");
        }
        return handlers;
    }

    private void validateFile(File file, long size, String expectedHash, Address expectedMemory,
            String context) throws MapError {
        if (!file.isFile() || !file.canRead()) {
            throw new MapError(context + " is not a readable file of the declared size");
        }
        try (FileInputStream input = new FileInputStream(file)) {
            if (input.getChannel().size() != size) {
                throw new MapError(context + " does not have the declared size");
            }
            validateInput(input, size, expectedHash, expectedMemory, context);
        }
        catch (IOException | MemoryAccessException error) {
            throw new MapError(context + " could not be validated", error);
        }
    }

    private RetainedPayload openValidatedPayload(File file, long size, String expectedHash,
            Address expectedMemory, String context) throws MapError {
        FileInputStream input = null;
        try {
            input = new FileInputStream(file);
            if (input.getChannel().size() != size) {
                throw new MapError(context + " does not have the declared size");
            }
            validateInput(input, size, expectedHash, expectedMemory, context);
            input.getChannel().position(0);
            return new RetainedPayload(input);
        }
        catch (MapError failure) {
            closeInput(input, failure);
            throw failure;
        }
        catch (IOException | MemoryAccessException error) {
            MapError failure = new MapError(context + " could not be validated", error);
            closeInput(input, failure);
            throw failure;
        }
        catch (RuntimeException | Error failure) {
            closeInput(input, failure);
            throw failure;
        }
    }

    private void validateInput(InputStream input, long size, String expectedHash,
            Address expectedMemory, String context)
            throws IOException, MemoryAccessException, MapError {
        Blake3Digest digest = new Blake3Digest();
        byte[] bytes = new byte[BUFFER_SIZE];
        byte[] memoryBytes = expectedMemory == null ? null : new byte[BUFFER_SIZE];
        long offset = 0;
        while (offset < size) {
            int wanted = (int) Math.min(bytes.length, size - offset);
            int read = readFully(input, bytes, wanted);
            if (read != wanted) {
                throw new MapError(context + " ended before its declared size");
            }
            digest.update(bytes, 0, read);
            if (memoryBytes != null) {
                int memoryRead = currentProgram.getMemory().getBytes(expectedMemory.add(offset),
                        memoryBytes, 0, read);
                if (memoryRead != read
                        || Arrays.mismatch(bytes, 0, read, memoryBytes, 0, read) != -1) {
                    throw new MapError(context + " bytes do not match the raw image mapping");
                }
            }
            offset += read;
        }
        if (input.read() != -1) {
            throw new MapError(context + " exceeds its declared size");
        }
        if (!finishHash(digest).equals(expectedHash)) {
            throw new MapError(context + " BLAKE3 does not match the load map");
        }
    }

    private static void retainPayload(List<RetainedPayload> payloads, RetainedPayload payload) {
        try {
            payloads.add(payload);
        }
        catch (RuntimeException | Error failure) {
            closePayload(payload, failure);
            throw failure;
        }
    }

    private static void closeInput(FileInputStream input, Throwable original) {
        if (input == null) {
            return;
        }
        try {
            input.close();
        }
        catch (Throwable closeFailure) {
            suppress(original, closeFailure);
        }
    }

    private static void closePayload(RetainedPayload payload, Throwable original) {
        try {
            payload.close();
        }
        catch (Throwable closeFailure) {
            suppress(original, closeFailure);
        }
    }

    private static void closePayloadsOrThrow(List<RetainedPayload> payloads) throws IOException {
        IOException first = null;
        for (int index = payloads.size() - 1; index >= 0; index--) {
            try {
                payloads.get(index).close();
            }
            catch (IOException failure) {
                if (first == null) {
                    first = failure;
                }
                else {
                    first.addSuppressed(failure);
                }
            }
        }
        if (first != null) {
            throw first;
        }
    }

    private static void closePayloads(List<RetainedPayload> payloads, Throwable original) {
        for (int index = payloads.size() - 1; index >= 0; index--) {
            closePayload(payloads.get(index), original);
        }
    }

    private String hashMemory(Address start, long size, String context) throws MapError {
        Blake3Digest digest = new Blake3Digest();
        byte[] bytes = new byte[BUFFER_SIZE];
        long offset = 0;
        try {
            while (offset < size) {
                int wanted = (int) Math.min(bytes.length, size - offset);
                int read = currentProgram.getMemory().getBytes(start.add(offset), bytes, 0, wanted);
                if (read != wanted) {
                    throw new MapError(context + " is not fully initialized");
                }
                digest.update(bytes, 0, read);
                offset += read;
            }
        }
        catch (MemoryAccessException error) {
            throw new MapError(context + " could not be read", error);
        }
        return finishHash(digest);
    }

    private static String hashZeros(long size) {
        Blake3Digest digest = new Blake3Digest();
        byte[] zeros = new byte[BUFFER_SIZE];
        long remaining = size;
        while (remaining > 0) {
            int length = (int) Math.min(zeros.length, remaining);
            digest.update(zeros, 0, length);
            remaining -= length;
        }
        return finishHash(digest);
    }

    private static String finishHash(Blake3Digest digest) {
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        StringBuilder text = new StringBuilder(output.length * 2);
        for (byte value : output) {
            text.append(String.format("%02x", value & 0xff));
        }
        return text.toString();
    }

    private static int readFully(InputStream input, byte[] output, int length) throws IOException {
        int offset = 0;
        while (offset < length) {
            int read = input.read(output, offset, length - offset);
            if (read < 0) {
                break;
            }
            if (read == 0) {
                continue;
            }
            offset += read;
        }
        return offset;
    }

    private static JsonObject readDocument(File mapFile) throws MapError {
        byte[] snapshot = readManifestSnapshot(mapFile);
        String json;
        try {
            json = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(snapshot))
                    .toString();
        }
        catch (CharacterCodingException error) {
            throw new MapError("scatter load map is not valid UTF-8", error);
        }

        JsonElement parsed;
        try (JsonReader reader = new JsonReader(new StringReader(json))) {
            reader.setStrictness(Strictness.STRICT);
            parsed = readStrictValue(reader);
            if (reader.peek() != JsonToken.END_DOCUMENT) {
                throw new MapError("scatter load map has trailing non-whitespace content");
            }
        }
        catch (IOException | IllegalStateException error) {
            throw new MapError("scatter load map is not strict JSON", error);
        }
        if (!parsed.isJsonObject()) {
            throw new MapError("scatter load-map root is not an object");
        }
        return parsed.getAsJsonObject();
    }

    private static byte[] readManifestSnapshot(File mapFile) throws MapError {
        try (InputStream input = new BufferedInputStream(new FileInputStream(mapFile));
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int total = 0;
            while (true) {
                int read = input.read(buffer);
                if (read < 0) {
                    return output.toByteArray();
                }
                if (read == 0) {
                    continue;
                }
                if (read > MAX_MANIFEST_BYTES - total) {
                    throw new MapError("scatter load map exceeds the manifest size limit");
                }
                output.write(buffer, 0, read);
                total += read;
            }
        }
        catch (IOException error) {
            throw new MapError("scatter load map could not be read", error);
        }
    }

    private static JsonElement readStrictValue(JsonReader reader) throws IOException, MapError {
        JsonToken token = reader.peek();
        switch (token) {
            case BEGIN_OBJECT:
                return readStrictObject(reader);
            case BEGIN_ARRAY:
                JsonArray array = new JsonArray();
                reader.beginArray();
                while (reader.hasNext()) {
                    array.add(readStrictValue(reader));
                }
                reader.endArray();
                return array;
            case STRING:
                return new JsonPrimitive(reader.nextString());
            case NUMBER:
                return new JsonPrimitive(new LexicalNumber(reader.nextString()));
            case BOOLEAN:
                return new JsonPrimitive(reader.nextBoolean());
            case NULL:
                reader.nextNull();
                return JsonNull.INSTANCE;
            default:
                throw new MapError("unexpected JSON token " + token + " at " + reader.getPath());
        }
    }

    private static JsonObject readStrictObject(JsonReader reader) throws IOException, MapError {
        JsonObject object = new JsonObject();
        Set<String> names = new HashSet<>();
        reader.beginObject();
        while (reader.hasNext()) {
            String name = reader.nextName();
            if (!names.add(name)) {
                throw new MapError("duplicate JSON member " + name + " at " + reader.getPath());
            }
            object.add(name, readStrictValue(reader));
        }
        reader.endObject();
        return object;
    }

    private static File requireCanonicalDirectoryArgument(String path, String description)
            throws MapError {
        File canonical = requireCanonicalArgument(path, description);
        if (!canonical.isDirectory()) {
            throw new MapError(description + " is not a directory");
        }
        return canonical;
    }

    private static File requireCanonicalFileArgument(String path, String description)
            throws MapError {
        File canonical = requireCanonicalArgument(path, description);
        if (!canonical.isFile() || !canonical.canRead()) {
            throw new MapError(description + " is not a readable regular file");
        }
        return canonical;
    }

    private static File requireCanonicalArgument(String path, String description) throws MapError {
        File supplied = new File(path);
        if (!supplied.isAbsolute()) {
            throw new MapError(description + " is not absolute");
        }
        try {
            File canonical = supplied.getCanonicalFile();
            if (!canonical.getPath().equals(supplied.getPath())) {
                throw new MapError(description + " is not in canonical form");
            }
            return canonical;
        }
        catch (IOException error) {
            throw new MapError(description + " cannot be canonicalized", error);
        }
    }

    private static File resolvePayload(File mapParent, String path, String context)
            throws MapError {
        File relative = new File(path);
        if (path.isEmpty() || relative.isAbsolute()) {
            throw new MapError(context + " payload path is not relative");
        }
        try {
            File payload = new File(mapParent, path).getCanonicalFile();
            if (!isStrictlyContained(mapParent, payload) || !payload.isFile()
                    || !payload.canRead()) {
                throw new MapError(context + " payload is not a contained readable regular file");
            }
            return payload;
        }
        catch (IOException error) {
            throw new MapError(context + " payload path cannot be canonicalized", error);
        }
    }

    private static boolean isStrictlyContained(File root, File child) {
        return !root.toPath().equals(child.toPath()) && child.toPath().startsWith(root.toPath());
    }

    private static boolean isSafeLabel(String label) {
        return !label.isEmpty() && !".".equals(label) && !"..".equals(label)
                && LABEL.matcher(label).matches();
    }

    private static JsonObject requireObject(JsonObject object, String field, String context)
            throws MapError {
        JsonElement value = object.get(field);
        if (value == null || !value.isJsonObject()) {
            throw new MapError(context + " field " + field + " is not an object");
        }
        return value.getAsJsonObject();
    }

    private static JsonArray requireArray(JsonObject object, String field, String context)
            throws MapError {
        JsonElement value = object.get(field);
        if (value == null || !value.isJsonArray()) {
            throw new MapError(context + " field " + field + " is not an array");
        }
        return value.getAsJsonArray();
    }

    private static String requireString(JsonObject object, String field, String context)
            throws MapError {
        JsonElement value = object.get(field);
        if (value == null || !value.isJsonPrimitive()) {
            throw new MapError(context + " field " + field + " is not a string");
        }
        JsonPrimitive primitive = value.getAsJsonPrimitive();
        if (!primitive.isString()) {
            throw new MapError(context + " field " + field + " is not a string");
        }
        return primitive.getAsString();
    }

    private static String requireHash(JsonObject object, String field, String context)
            throws MapError {
        String value = requireString(object, field, context);
        if (!HASH.matcher(value).matches()) {
            throw new MapError(context + " field " + field + " is not canonical BLAKE3");
        }
        return value;
    }

    private static long requireAddress(JsonObject object, String field, String context)
            throws MapError {
        String value = requireString(object, field, context);
        if (!ADDRESS.matcher(value).matches()) {
            throw new MapError(context + " field " + field + " is not a canonical address");
        }
        return Long.parseLong(value.substring(2), 16);
    }

    private static long requireUnsigned(JsonObject object, String field, long maximum,
            String context) throws MapError {
        JsonElement value = object.get(field);
        if (value == null || !value.isJsonPrimitive()
                || !value.getAsJsonPrimitive().isNumber()) {
            throw new MapError(context + " field " + field + " is not an unsigned integer");
        }
        String text = value.getAsJsonPrimitive().getAsString();
        if (!UNSIGNED_INTEGER.matcher(text).matches()) {
            throw new MapError(context + " field " + field + " is not an unsigned integer");
        }
        try {
            long result = Long.parseLong(text);
            if (result > maximum) {
                throw new MapError(context + " field " + field + " exceeds " + maximum);
            }
            return result;
        }
        catch (NumberFormatException error) {
            throw new MapError(context + " field " + field + " exceeds 64 bits", error);
        }
    }

    private static void requireExactKeys(JsonObject object, String context, String... required)
            throws MapError {
        requireKeys(object, context, required, new String[0]);
    }

    private static void requireKeys(JsonObject object, String context, String[] required,
            String[] optional) throws MapError {
        Set<String> allowed = new HashSet<>();
        allowed.addAll(Arrays.asList(required));
        allowed.addAll(Arrays.asList(optional));
        for (String field : required) {
            if (!object.has(field)) {
                throw new MapError(context + " is missing field " + field);
            }
        }
        for (String field : object.keySet()) {
            if (!allowed.contains(field)) {
                throw new MapError(context + " has unknown field " + field);
            }
        }
    }

    private static long checkedEnd(long start, long size, String context) throws MapError {
        if (start < 0 || start > UINT32_MAX || size < 0 || size > UINT32_MAX
                || start + size > UINT32_END) {
            throw new MapError(context + " range overflows the 32-bit address space");
        }
        return start + size;
    }

    private static void requireWithinRaw(long start, long size, long imageBase, long imageEnd,
            String context) throws MapError {
        long end = checkedEnd(start, size, context);
        if (size == 0 || start < imageBase || end > imageEnd) {
            throw new MapError(context + " range escapes the raw image");
        }
    }

    private static long addLogicalBytes(long current, long size, String context) throws MapError {
        long total;
        try {
            total = Math.addExact(current, size);
        }
        catch (ArithmeticException error) {
            throw new MapError(context + " logical byte count overflows", error);
        }
        if (total > MAX_LOGICAL_OUTPUT) {
            throw new MapError("scatter logical output exceeds the supported limit");
        }
        return total;
    }

    private static Address toAddress(AddressSpace space, long value, String context)
            throws MapError {
        try {
            return space.getAddress(value);
        }
        catch (AddressOutOfBoundsException error) {
            throw new MapError(context + " is outside the default address space", error);
        }
    }

    private static void rejectExistingCollision(Memory memory, Address start, Address end,
            String context) throws MapError {
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.getStart().getAddressSpace().equals(start.getAddressSpace())
                    && rangesOverlap(start, end, block.getStart(), block.getEnd())) {
                throw new MapError(context + " overlaps existing memory block " + block.getName());
            }
        }
    }

    private static boolean rangesOverlap(Address firstStart, Address firstEnd, Address secondStart,
            Address secondEnd) {
        return firstStart.compareTo(secondEnd) <= 0 && secondStart.compareTo(firstEnd) <= 0;
    }

    private static void rollback(Memory memory, List<MemoryBlock> created, Throwable original) {
        for (int index = created.size() - 1; index >= 0; index--) {
            try {
                memory.removeBlock(created.get(index), TaskMonitor.DUMMY);
            }
            catch (Throwable rollbackFailure) {
                suppress(original, rollbackFailure);
            }
        }
    }

    private void recoverMutationFailure(Memory memory, List<MemoryBlock> created,
            List<RetainedPayload> payloads, Throwable original) {
        try {
            rollback(memory, created, original);
        }
        catch (Throwable rollbackFailure) {
            suppress(original, rollbackFailure);
        }
        try {
            closePayloads(payloads, original);
        }
        catch (Throwable closeFailure) {
            suppress(original, closeFailure);
        }
        try {
            end(false);
        }
        catch (Throwable abortFailure) {
            suppress(original, abortFailure);
        }
    }

    private static void suppress(Throwable original, Throwable cleanupFailure) {
        if (cleanupFailure == original) {
            return;
        }
        try {
            original.addSuppressed(cleanupFailure);
        }
        catch (Throwable ignored) {
            // Preserve the original failure even if suppression itself is unavailable.
        }
    }
}
