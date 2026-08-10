// ApplyGlobals.java — strict Ghidra headless post-script for pixel-modem-extractor.
// Arg[0] = absolute path to the current image's globals.json.
//
// Preflights the whole selected Recovered set before the first mutation, then
// renames only exact generated default DAT_<address> primary labels. Provisional
// and unknown tiers remain record-only. Map errors return normally so a later
// ExportDecomp.java script can still export independently applied functions.
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
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApplyGlobals extends GhidraScript {
    private static final String FORMAT = "pixel-modem-extractor-globals-v1";
    private static final int ERROR_MAX_CODE_POINTS = 2048;
    private static final Pattern HEX_ADDRESS = Pattern.compile("^[0-9a-fA-F]+$");
    private static final Pattern DAT_NAME =
            Pattern.compile("^DAT_([0-9a-f]+)$", Pattern.CASE_INSENSITIVE);

    private static final class MapError extends Exception {
        MapError(String message) {
            super(message);
        }

        MapError(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static final class Candidate {
        final long rawAddress;
        final Address address;
        final String name;

        Candidate(long rawAddress, Address address, String name) {
            this.rawAddress = rawAddress;
            this.address = address;
            this.name = name;
        }
    }

    @Override
    public void run() throws Exception {
        String image = currentProgram.getName();
        List<Candidate> candidates;
        try {
            candidates = preflight(image);
        }
        catch (MapError error) {
            emitError(image, error.getMessage());
            return;
        }

        SymbolTable symbols = currentProgram.getSymbolTable();
        int applied = 0;
        int skippedOutsideMemory = 0;
        int skippedMissing = 0;
        int skippedNonDefault = 0;
        int skippedRejected = 0;

        for (Candidate candidate : candidates) {
            if (!currentProgram.getMemory().contains(candidate.address)) {
                skippedOutsideMemory++;
                continue;
            }

            Symbol primary = symbols.getPrimarySymbol(candidate.address);
            if (primary == null) {
                skippedMissing++;
                continue;
            }
            if (!isOwnedDefaultLabel(primary, candidate.rawAddress)) {
                skippedNonDefault++;
                continue;
            }

            try {
                primary.setName(candidate.name, SourceType.USER_DEFINED);
                applied++;
            }
            catch (DuplicateNameException | InvalidInputException expectedRejection) {
                println("ApplyGlobals rejected requested name at " + candidate.address + ": "
                        + expectedRejection.getMessage());
                skippedRejected++;
            }
        }

        int classified = Math.addExact(
                Math.addExact(
                        Math.addExact(Math.addExact(applied, skippedOutsideMemory), skippedMissing),
                        skippedNonDefault),
                skippedRejected);
        if (classified != candidates.size()) {
            throw new IllegalStateException(
                    "ApplyGlobals classification did not conserve candidates");
        }
        emitOk(image, candidates.size(), applied, skippedOutsideMemory, skippedMissing,
                skippedNonDefault, skippedRejected);
    }

    private List<Candidate> preflight(String expectedImage) throws MapError {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new MapError("expected exactly one globals.json argument");
        }
        File mapFile = new File(args[0]);
        if (!mapFile.isFile() || !mapFile.canRead()) {
            throw new MapError("globals map is not a readable regular file");
        }

        JsonElement parsed;
        try (FileReader reader = new FileReader(mapFile)) {
            parsed = JsonParser.parseReader(reader);
        }
        catch (IOException | JsonParseException error) {
            throw new MapError("globals map is not readable JSON: " + error.getMessage(), error);
        }
        if (!parsed.isJsonObject()) {
            throw new MapError("globals map root is not an object");
        }
        JsonObject root = parsed.getAsJsonObject();
        String format = requireString(root, "format");
        if (!FORMAT.equals(format)) {
            throw new MapError("unexpected globals map format");
        }
        String image = requireString(root, "image");
        if (!expectedImage.equals(image)) {
            throw new MapError("globals image does not match current program");
        }
        if (!root.has("globals") || !root.get("globals").isJsonArray()) {
            throw new MapError("globals field is not an array");
        }

        JsonArray globals = root.getAsJsonArray("globals");
        AddressSpace defaultSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Set<Long> selectedAddresses = new HashSet<>();
        List<Candidate> candidates = new ArrayList<>();
        for (int index = 0; index < globals.size(); index++) {
            JsonElement element = globals.get(index);
            if (!element.isJsonObject()) {
                throw new MapError("global entry " + index + " is not an object");
            }
            JsonObject global = element.getAsJsonObject();
            JsonPrimitive tier = requirePrimitive(global, "tier", index);
            if (!"recovered".equals(tier.getAsString())) {
                continue;
            }

            String addressText = requirePrimitive(global, "address", index).getAsString();
            String name = requirePrimitive(global, "name", index).getAsString();
            long rawAddress = parseHexAddress(addressText, index);
            if (!selectedAddresses.add(rawAddress)) {
                throw new MapError("duplicate selected address at global entry " + index);
            }
            Address address;
            try {
                address = defaultSpace.getAddress(rawAddress);
            }
            catch (AddressOutOfBoundsException error) {
                throw new MapError(
                        "selected address is outside the default address space at global entry "
                                + index,
                        error);
            }
            candidates.add(new Candidate(rawAddress, address, name));
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
            throw new MapError("selected global entry " + index + " has non-primitive " + field);
        }
        return object.getAsJsonPrimitive(field);
    }

    private static long parseHexAddress(String value, int index) throws MapError {
        String text = value.trim();
        if (text.startsWith("0x") || text.startsWith("0X")) {
            text = text.substring(2);
        }
        if (!HEX_ADDRESS.matcher(text).matches()) {
            throw new MapError("selected global entry " + index + " has a malformed address");
        }
        try {
            return Long.parseUnsignedLong(text, 16);
        }
        catch (NumberFormatException error) {
            throw new MapError("selected global entry " + index + " address exceeds 64 bits", error);
        }
    }

    private static boolean isOwnedDefaultLabel(Symbol primary, long rawAddress) {
        if (primary.getSource() != SourceType.DEFAULT
                || !SymbolType.LABEL.equals(primary.getSymbolType())) {
            return false;
        }
        Matcher matcher = DAT_NAME.matcher(primary.getName());
        if (!matcher.matches()) {
            return false;
        }
        try {
            long suffix = Long.parseUnsignedLong(matcher.group(1), 16);
            return Long.compareUnsigned(suffix, rawAddress) == 0;
        }
        catch (NumberFormatException ignored) {
            return false;
        }
    }

    private static void emitOk(String image, int candidates, int applied,
            int skippedOutsideMemory, int skippedMissing, int skippedNonDefault,
            int skippedRejected) {
        JsonObject summary = new JsonObject();
        summary.addProperty("image", image);
        summary.addProperty("status", "ok");
        summary.addProperty("candidates", candidates);
        summary.addProperty("applied", applied);
        summary.addProperty("skipped_outside_memory", skippedOutsideMemory);
        summary.addProperty("skipped_missing", skippedMissing);
        summary.addProperty("skipped_non_default", skippedNonDefault);
        summary.addProperty("skipped_rejected", skippedRejected);
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
        String bounded = reason;
        if (bounded == null || bounded.isEmpty()) {
            bounded = "globals map preflight failed";
        }
        int count = bounded.codePointCount(0, bounded.length());
        if (count > ERROR_MAX_CODE_POINTS) {
            int end = bounded.offsetByCodePoints(0, ERROR_MAX_CODE_POINTS);
            bounded = bounded.substring(0, end);
        }
        return bounded;
    }

    private static void emit(JsonObject summary) {
        // This is the sole machine-interface line. Do not duplicate it through
        // GhidraScript.println, which adds a log wrapper and breaks strict parsing.
        System.out.println("ApplyGlobals: " + summary);
    }
}
