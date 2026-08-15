// ApplyGlobalTypes.java — strict Ghidra headless post-script for pixel-modem-extractor.
// Arg[0] = absolute path to the current image's global_types map
// (pixel-modem-extractor-global-types-v1).
//
// Preflights the whole map before the first mutation, then applies undefined1/2/4/8
// at each address, widening ONLY undefined bytes — never a committed data type or an
// instruction. Fail-closed: a span collision or out-of-memory address is skipped and
// counted; a malformed map returns an error line with zero mutation.
//@category PixelModem
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.util.CodeUnitInsertionException;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class ApplyGlobalTypes extends GhidraScript {
    private static final String FORMAT = "pixel-modem-extractor-global-types-v1";
    private static final int ERROR_MAX_CODE_POINTS = 2048;
    private static final Pattern HEX_ADDRESS = Pattern.compile("^[0-9a-fA-F]+$");

    private static final class MapError extends Exception {
        MapError(String message) { super(message); }
        MapError(String message, Throwable cause) { super(message, cause); }
    }

    private static final class Candidate {
        final Address address;
        final int width;
        Candidate(Address address, int width) {
            this.address = address;
            this.width = width;
        }
    }

    @Override
    public void run() throws Exception {
        String image = currentProgram.getName();
        List<Candidate> candidates;
        try {
            candidates = preflight(image);
        } catch (MapError error) {
            emitError(image, error.getMessage());
            return;
        }

        int applied = 0;
        int skippedOutsideMemory = 0;
        int skippedCollision = 0;

        for (Candidate candidate : candidates) {
            Address end;
            try {
                end = candidate.address.add(candidate.width - 1);
            } catch (AddressOutOfBoundsException error) {
                skippedOutsideMemory++;
                continue;
            }
            if (!currentProgram.getMemory().contains(candidate.address)
                    || !currentProgram.getMemory().contains(end)) {
                skippedOutsideMemory++;
                continue;
            }
            DataType dt = Undefined.getUndefinedDataType(candidate.width);
            try {
                // Clears only undefined bytes in the span; throws if a committed
                // type or instruction is in the way. That throw IS the fail-closed guard.
                DataUtilities.createData(
                        currentProgram, candidate.address, dt, candidate.width, false,
                        ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
                applied++;
            } catch (CodeUnitInsertionException expectedConflict) {
                skippedCollision++;
            }
        }

        int classified = Math.addExact(Math.addExact(applied, skippedOutsideMemory), skippedCollision);
        if (classified != candidates.size()) {
            throw new IllegalStateException("ApplyGlobalTypes classification did not conserve candidates");
        }
        emitOk(image, candidates.size(), applied, skippedOutsideMemory, skippedCollision);
    }

    private List<Candidate> preflight(String expectedImage) throws MapError {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new MapError("expected exactly one global_types map argument");
        }
        File mapFile = new File(args[0]);
        if (!mapFile.isFile() || !mapFile.canRead()) {
            throw new MapError("global_types map is not a readable regular file");
        }
        JsonElement parsed;
        try (FileReader reader = new FileReader(mapFile)) {
            parsed = JsonParser.parseReader(reader);
        } catch (IOException | JsonParseException error) {
            throw new MapError("global_types map is not readable JSON: " + error.getMessage(), error);
        }
        if (!parsed.isJsonObject()) {
            throw new MapError("global_types map root is not an object");
        }
        JsonObject root = parsed.getAsJsonObject();
        if (!FORMAT.equals(requireString(root, "format"))) {
            throw new MapError("unexpected global_types map format");
        }
        if (!expectedImage.equals(requireString(root, "image"))) {
            throw new MapError("global_types image does not match current program");
        }
        if (!root.has("types") || !root.get("types").isJsonArray()) {
            throw new MapError("types field is not an array");
        }
        JsonArray types = root.getAsJsonArray("types");
        AddressSpace defaultSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Set<Long> seen = new HashSet<>();
        List<Candidate> candidates = new ArrayList<>();
        for (int index = 0; index < types.size(); index++) {
            JsonElement element = types.get(index);
            if (!element.isJsonObject()) {
                throw new MapError("type entry " + index + " is not an object");
            }
            JsonObject entry = element.getAsJsonObject();
            long rawAddress = parseHexAddress(requirePrimitive(entry, "address", index).getAsString(), index);
            int width = requirePrimitive(entry, "width", index).getAsInt();
            if (width != 1 && width != 2 && width != 4 && width != 8) {
                throw new MapError("type entry " + index + " has invalid width " + width);
            }
            if (!seen.add(rawAddress)) {
                throw new MapError("duplicate address at type entry " + index);
            }
            Address address;
            try {
                address = defaultSpace.getAddress(rawAddress);
            } catch (AddressOutOfBoundsException error) {
                throw new MapError("type entry " + index + " address is outside the default space", error);
            }
            candidates.add(new Candidate(address, width));
        }
        return candidates;
    }

    private static String requireString(JsonObject object, String field) throws MapError {
        if (!object.has(field) || !object.get(field).isJsonPrimitive()
                || !object.getAsJsonPrimitive(field).isString()) {
            throw new MapError(field + " is not a string");
        }
        return object.get(field).getAsString();
    }

    private static JsonPrimitive requirePrimitive(JsonObject object, String field, int index)
            throws MapError {
        if (!object.has(field) || !object.get(field).isJsonPrimitive()) {
            throw new MapError("type entry " + index + " has non-primitive " + field);
        }
        return object.getAsJsonPrimitive(field);
    }

    private static long parseHexAddress(String value, int index) throws MapError {
        String text = value.trim();
        if (text.startsWith("0x") || text.startsWith("0X")) {
            text = text.substring(2);
        }
        if (!HEX_ADDRESS.matcher(text).matches()) {
            throw new MapError("type entry " + index + " has a malformed address");
        }
        try {
            return Long.parseUnsignedLong(text, 16);
        } catch (NumberFormatException error) {
            throw new MapError("type entry " + index + " address exceeds 64 bits", error);
        }
    }

    private static void emitOk(String image, int candidates, int applied,
            int skippedOutsideMemory, int skippedCollision) {
        JsonObject summary = new JsonObject();
        summary.addProperty("image", image);
        summary.addProperty("status", "ok");
        summary.addProperty("candidates", candidates);
        summary.addProperty("applied", applied);
        summary.addProperty("skipped_outside_memory", skippedOutsideMemory);
        summary.addProperty("skipped_collision", skippedCollision);
        emit(summary);
    }

    private static void emitError(String image, String reason) {
        JsonObject summary = new JsonObject();
        summary.addProperty("image", image);
        summary.addProperty("status", "error");
        summary.addProperty("error", boundReason(reason));
        emit(summary);
    }

    private static String boundReason(String reason) {
        String bounded = (reason == null || reason.isEmpty()) ? "global_types map preflight failed" : reason;
        int count = bounded.codePointCount(0, bounded.length());
        if (count > ERROR_MAX_CODE_POINTS) {
            bounded = bounded.substring(0, bounded.offsetByCodePoints(0, ERROR_MAX_CODE_POINTS));
        }
        return bounded;
    }

    private static void emit(JsonObject summary) {
        // Sole machine-interface line — do not route through println (adds a log wrapper).
        System.out.println("ApplyGlobalTypes: " + summary);
    }
}
