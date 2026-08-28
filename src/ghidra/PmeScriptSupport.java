// PmeScriptSupport.java - package-private generic support shared by
// pixel-modem-extractor Ghidra scripts. Domain schemas and ownership stay in
// their dedicated support classes; this class owns only canonical containment,
// retained regular-file identity, BLAKE3, bounded Unicode, and symbol helpers.
//@category PixelModem
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Locale;
import java.util.Objects;
import org.bouncycastle.crypto.digests.Blake3Digest;

final class PmeScriptSupport {
    static final long UINT32_MAX = 0xffff_ffffL;
    static final long UINT32_END = 0x1_0000_0000L;
    static final int GHIDRA_SYMBOL_LEAF_LIMIT = 2000;
    private static final int HASH_BUFFER_SIZE = 64 * 1024;
    private static final int MAX_JSON_DEPTH = 64;

    private PmeScriptSupport() {}

    static final class SupportError extends RuntimeException {
        private static final long serialVersionUID = 1L;

        SupportError(String message) {
            super(message);
        }

        SupportError(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** A canonical no-follow regular-file argument retained from validation
     * through every read. File-key checks reject a path swap around open. */
    static final class TrustedFile implements AutoCloseable {
        private final File path;
        private final FileInputStream input;
        private final Object fileKey;
        private final long size;
        private final long modifiedMillis;
        private boolean closed;

        private TrustedFile(File path, FileInputStream input, BasicFileAttributes attributes) {
            this.path = path;
            this.input = input;
            this.fileKey = attributes.fileKey();
            this.size = attributes.size();
            this.modifiedMillis = attributes.lastModifiedTime().toMillis();
        }

        File path() {
            return path;
        }

        long size() {
            return size;
        }

        byte[] readAll(long maximum, String what) throws IOException {
            if (maximum < 0 || size > maximum || size > Integer.MAX_VALUE) {
                fail(what + " exceeds its " + maximum + "-byte ceiling");
            }
            input.getChannel().position(0);
            byte[] bytes = new byte[(int) size];
            if (readFully(input, bytes, bytes.length) != bytes.length) {
                fail(what + " ended before its retained size");
            }
            if (input.read() != -1) {
                fail(what + " grew while it was being authenticated");
            }
            return bytes;
        }

        byte[] readRange(long offset, int length, String what) throws IOException {
            if (offset < 0 || length < 0 || offset > size - length) {
                fail(what + " range leaves its retained regular file");
            }
            input.getChannel().position(offset);
            byte[] bytes = new byte[length];
            if (readFully(input, bytes, length) != length) {
                fail(what + " range ended before its retained size");
            }
            return bytes;
        }

        String blake3(String what) throws IOException {
            input.getChannel().position(0);
            return hashExact(input, size, what);
        }

        Reader utf8Reader() throws IOException {
            input.getChannel().position(0);
            return new InputStreamReader(input, StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT));
        }

        void verifyPathIdentity(String what) {
            BasicFileAttributes current = attributes(path, what);
            if (!current.isRegularFile() || current.isSymbolicLink()
                    || current.size() != size
                    || current.lastModifiedTime().toMillis() != modifiedMillis
                    || (fileKey != null && !fileKey.equals(current.fileKey()))) {
                fail(what + " no longer names the retained regular file");
            }
        }

        @Override
        public void close() throws IOException {
            if (!closed) {
                input.close();
                closed = true;
            }
        }
    }

    static File requireCanonicalDirectory(File file, String what) {
        File canonical = requireCanonicalArgument(file, what);
        BasicFileAttributes attributes = attributes(canonical, what);
        if (!attributes.isDirectory() || attributes.isSymbolicLink()) {
            fail(what + " is not a directory");
        }
        return canonical;
    }

    static TrustedFile openCanonicalFile(File file, String what) {
        File canonical = requireCanonicalArgument(file, what);
        return openRegular(canonical, what);
    }

    static TrustedFile openCanonicalContainedFile(File root, File file, String what) {
        File canonical = requireCanonicalArgument(file, what);
        if (!isStrictlyContained(root, canonical)) {
            fail(what + " escapes the import-kit root");
        }
        return openRegular(canonical, what);
    }

    static TrustedFile openContainedChild(File root, String relative, String what) {
        if (relative == null || relative.isEmpty()) {
            fail(what + " has an empty relative path");
        }
        Path relativePath = Path.of(relative);
        if (relativePath.isAbsolute()) fail(what + " path is not relative");
        for (Path component : relativePath) {
            if (".".equals(component.toString()) || "..".equals(component.toString())) {
                fail(what + " path is not lexically canonical");
            }
        }
        Path lexical = root.toPath().resolve(relativePath).normalize();
        if (lexical.equals(root.toPath()) || !lexical.startsWith(root.toPath())) {
            fail(what + " escapes the import-kit root");
        }
        File child = lexical.toFile();
        BasicFileAttributes before = attributes(child, what);
        if (before.isSymbolicLink()) fail(what + " is a symbolic link");
        try {
            File canonical = child.getCanonicalFile();
            if (!canonical.equals(child)) {
                fail(what + " path contains a symbolic link or noncanonical component");
            }
        }
        catch (IOException error) {
            throw new SupportError(what + " cannot be canonicalized", error);
        }
        return openRegular(child, what);
    }

    static boolean isStrictlyContained(File root, File child) {
        return !root.toPath().equals(child.toPath()) && child.toPath().startsWith(root.toPath());
    }

    private static File requireCanonicalArgument(File file, String what) {
        if (file == null || !file.isAbsolute()) {
            fail(what + " is not absolute");
        }
        try {
            File canonical = file.getCanonicalFile();
            if (!canonical.getPath().equals(file.getPath())) {
                fail(what + " is not in canonical form");
            }
            return canonical;
        }
        catch (IOException error) {
            throw new SupportError(what + " cannot be canonicalized", error);
        }
    }

    private static TrustedFile openRegular(File path, String what) {
        BasicFileAttributes before = attributes(path, what);
        if (!before.isRegularFile() || before.isSymbolicLink()) {
            fail(what + " is not a regular file");
        }
        FileInputStream input;
        try {
            input = new FileInputStream(path);
        }
        catch (IOException error) {
            throw new SupportError(what + " could not be opened", error);
        }
        try {
            BasicFileAttributes after = attributes(path, what);
            if (!after.isRegularFile() || after.isSymbolicLink()
                    || before.size() != after.size()
                    || before.lastModifiedTime().toMillis()
                            != after.lastModifiedTime().toMillis()
                    || (before.fileKey() != null
                            && !Objects.equals(before.fileKey(), after.fileKey()))) {
                input.close();
                fail(what + " changed identity while it was being opened");
            }
            if (input.getChannel().size() != after.size()) {
                input.close();
                fail(what + " opened size does not match its regular-file identity");
            }
            return new TrustedFile(path, input, after);
        }
        catch (Throwable error) {
            try {
                input.close();
            }
            catch (Throwable closeFailure) {
                suppress(error, closeFailure);
            }
            if (error instanceof Error) throw (Error) error;
            if (error instanceof RuntimeException) throw (RuntimeException) error;
            throw new SupportError(what + " identity could not be retained", error);
        }
    }

    private static BasicFileAttributes attributes(File path, String what) {
        try {
            return Files.readAttributes(path.toPath(), BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
        }
        catch (IOException error) {
            throw new SupportError(what + " metadata is unavailable", error);
        }
    }

    static String blake3Hex(byte[] payload) {
        return blake3Hex(new byte[0], payload);
    }

    static String blake3Hex(byte[] domain, byte[] payload) {
        Blake3Digest digest = new Blake3Digest();
        digest.update(domain, 0, domain.length);
        digest.update(payload, 0, payload.length);
        return finishHash(digest);
    }

    static String hashExact(InputStream input, long size, String what) throws IOException {
        if (size < 0) {
            fail(what + " has a negative retained size");
        }
        Blake3Digest digest = new Blake3Digest();
        byte[] buffer = new byte[HASH_BUFFER_SIZE];
        long offset = 0;
        while (offset < size) {
            int wanted = (int) Math.min(buffer.length, size - offset);
            int read = readFully(input, buffer, wanted);
            if (read != wanted) {
                fail(what + " ended before its retained size");
            }
            digest.update(buffer, 0, read);
            offset += read;
        }
        if (input.read() != -1) {
            fail(what + " grew while it was being authenticated");
        }
        return finishHash(digest);
    }

    static String finishHash(Blake3Digest digest) {
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        StringBuilder text = new StringBuilder(output.length * 2);
        for (byte value : output) {
            text.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        }
        return text.toString();
    }

    static byte[] hexToBytes(String text, String what) {
        if (text == null || text.length() % 2 != 0) {
            fail(what + " is not even-length hexadecimal");
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream(text.length() / 2);
        for (int index = 0; index < text.length(); index += 2) {
            int high = Character.digit(text.charAt(index), 16);
            int low = Character.digit(text.charAt(index + 1), 16);
            if (high < 0 || low < 0) {
                fail(what + " contains a non-hexadecimal character");
            }
            output.write((high << 4) | low);
        }
        return output.toByteArray();
    }

    static byte[] boundedUtf8(String value, int maximumBytes, String what) {
        if (value == null) {
            fail(what + " is missing");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (++index >= value.length()
                        || !Character.isLowSurrogate(value.charAt(index))) {
                    fail(what + " contains an unpaired surrogate");
                }
            }
            else if (Character.isLowSurrogate(character)) {
                fail(what + " contains an unpaired surrogate");
            }
        }
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        if (encoded.length > maximumBytes) {
            fail(what + " exceeds its " + maximumBytes + "-byte UTF-8 limit");
        }
        return encoded;
    }

    static String decodeUtf8(byte[] bytes, String what) {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(bytes)).toString();
        }
        catch (CharacterCodingException error) {
            throw new SupportError(what + " is not valid UTF-8", error);
        }
    }

    static String boundedReason(String reason, int maximumBytes) {
        if (reason == null || reason.isEmpty()) {
            return "unknown failure";
        }
        StringBuilder bounded = new StringBuilder();
        int used = 0;
        for (int offset = 0; offset < reason.length();) {
            int point = reason.codePointAt(offset);
            String piece = new String(Character.toChars(point));
            int bytes = piece.getBytes(StandardCharsets.UTF_8).length;
            if (used + bytes > maximumBytes) {
                break;
            }
            bounded.append(piece);
            used += bytes;
            offset += Character.charCount(point);
        }
        return bounded.length() == 0 ? "unknown failure" : bounded.toString();
    }

    static String jsonString(String value) {
        boundedUtf8(value, Integer.MAX_VALUE, "JSON string");
        StringBuilder out = new StringBuilder(value.length() + 2);
        out.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) character));
                    }
                    else {
                        out.append(character);
                    }
            }
        }
        out.append('"');
        return out.toString();
    }

    static byte[] canonicalJsonBytes(String text, String what) {
        StringBuilder output = new StringBuilder(text.length());
        try (JsonReader reader = new JsonReader(new StringReader(text))) {
            reader.setStrictness(Strictness.STRICT);
            writeCanonicalJson(reader, output, 0, what);
            if (reader.peek() != JsonToken.END_DOCUMENT) {
                fail(what + " has trailing JSON");
            }
        }
        catch (IOException | IllegalStateException error) {
            throw new SupportError(what + " cannot be canonicalized", error);
        }
        return boundedUtf8(output.toString(), Integer.MAX_VALUE, what + " canonical JSON");
    }

    private static void writeCanonicalJson(JsonReader reader, StringBuilder output, int depth,
            String what) throws IOException {
        if (depth > MAX_JSON_DEPTH) {
            fail(what + " exceeds the JSON nesting limit");
        }
        switch (reader.peek()) {
            case BEGIN_OBJECT:
                reader.beginObject();
                output.append('{');
                boolean firstMember = true;
                while (reader.hasNext()) {
                    output.append(firstMember ? "\n" : ",\n");
                    appendIndent(output, depth + 1);
                    output.append(jsonString(reader.nextName())).append(": ");
                    writeCanonicalJson(reader, output, depth + 1, what);
                    firstMember = false;
                }
                reader.endObject();
                if (!firstMember) {
                    output.append('\n');
                    appendIndent(output, depth);
                }
                output.append('}');
                break;
            case BEGIN_ARRAY:
                reader.beginArray();
                output.append('[');
                boolean firstElement = true;
                while (reader.hasNext()) {
                    output.append(firstElement ? "\n" : ",\n");
                    appendIndent(output, depth + 1);
                    writeCanonicalJson(reader, output, depth + 1, what);
                    firstElement = false;
                }
                reader.endArray();
                if (!firstElement) {
                    output.append('\n');
                    appendIndent(output, depth);
                }
                output.append(']');
                break;
            case STRING:
                output.append(jsonString(reader.nextString()));
                break;
            case NUMBER:
                output.append(reader.nextString());
                break;
            case BOOLEAN:
                output.append(reader.nextBoolean());
                break;
            case NULL:
                reader.nextNull();
                output.append("null");
                break;
            default:
                fail(what + " contains an invalid JSON value");
        }
    }

    private static void appendIndent(StringBuilder output, int depth) {
        for (int index = 0; index < depth; index++) {
            output.append("  ");
        }
    }

    static void assertGhidraSymbolLimit() {
        if (SymbolUtilities.MAX_SYMBOL_NAME_LENGTH != GHIDRA_SYMBOL_LEAF_LIMIT) {
            fail("SymbolUtilities.MAX_SYMBOL_NAME_LENGTH != 2000 is not supported");
        }
    }

    static String requireSymbolLeaf(String leaf, int maximumUtf8Bytes, String what) {
        assertGhidraSymbolLimit();
        if (leaf == null || leaf.isEmpty() || leaf.length() > GHIDRA_SYMBOL_LEAF_LIMIT) {
            fail(what + " is not a bounded symbol leaf");
        }
        boundedUtf8(leaf, maximumUtf8Bytes, what);
        try {
            SymbolUtilities.validateName(leaf);
        }
        catch (ghidra.util.exception.InvalidInputException error) {
            throw new SupportError(what + " is not a valid Ghidra symbol leaf", error);
        }
        return leaf;
    }

    static String primarySource(SourceType source) {
        switch (source) {
            case DEFAULT: return "default";
            case ANALYSIS: return "analysis";
            case AI: return "ai";
            case IMPORTED: return "imported";
            case USER_DEFINED: return "user_defined";
            default: fail("unknown primary source " + source); return null;
        }
    }

    static Address programAddress(Program program, long value) {
        if (value < 0 || value > UINT32_MAX) {
            fail("address is outside the u32 domain");
        }
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        try {
            return space.getAddress(value);
        }
        catch (AddressOutOfBoundsException error) {
            throw new SupportError("address is outside the default address space", error);
        }
    }

    static byte[] ascii(String text) {
        for (int index = 0; index < text.length(); index++) {
            if (text.charAt(index) > 0x7f) {
                fail("ASCII input contains a non-ASCII character");
            }
        }
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    private static int readFully(InputStream input, byte[] output, int length) throws IOException {
        int offset = 0;
        while (offset < length) {
            int read = input.read(output, offset, length - offset);
            if (read < 0) {
                break;
            }
            offset += read;
        }
        return offset;
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

    private static void fail(String message) {
        throw new SupportError(message);
    }
}
