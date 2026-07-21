// ApplySymbols.java — Ghidra headless post-script for pixel-modem-extractor.
// Arg[0] = absolute path to a symbol_map.json produced by symbolicate::write_symbol_map.
// Renames functions and sets plate comments from the recovered evidence, so the
// subsequent ExportDecomp.java pass emits decompiled C with names + inline
// evidence baked in. Fail-closed per symbol: a missing function, an invalid
// name, or a name collision is logged via println and skipped. The script
// always returns normally so ExportDecomp still runs and decompiled.c is
// complete.
//@category PixelModem
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;

import java.io.File;
import java.io.FileReader;

public class ApplySymbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ApplySymbols: missing symbol_map.json argument");
            summarize("?", 0, 0, 0);
            return;
        }
        File mapFile = new File(args[0]);
        if (!mapFile.exists()) {
            println("ApplySymbols: symbol map not found: " + mapFile.getAbsolutePath());
            summarize("?", 0, 0, 0);
            return;
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        JsonObject root;
        try (FileReader r = new FileReader(mapFile)) {
            root = JsonParser.parseReader(r).getAsJsonObject();
        }
        String image = root.has("image") ? root.get("image").getAsString() : "?";
        JsonArray symbols = root.has("symbols") ? root.getAsJsonArray("symbols") : new JsonArray();

        int applied = 0;
        int comments = 0;
        int skipped = 0;
        for (JsonElement el : symbols) {
            if (!el.isJsonObject()) { skipped++; continue; }
            JsonObject sym = el.getAsJsonObject();
            if (!sym.has("entry") || !sym.get("entry").isJsonPrimitive()) {
                skipped++;
                continue;
            }
            long entryAddr;
            try {
                entryAddr = parseAddr(sym.get("entry").getAsString());
            } catch (Exception e) {
                println("ApplySymbols: bad entry " + sym.get("entry") + ": " + e.getMessage());
                skipped++;
                continue;
            }
            Address a;
            try {
                a = toAddr(entryAddr);
            } catch (Exception e) {
                println("ApplySymbols: cannot resolve " + sym.get("entry") + ": " + e.getMessage());
                skipped++;
                continue;
            }

            // Plate comment is independent of whether a function exists at the
            // address — it still anchors the evidence for the decompiler.
            if (sym.has("annotations") && sym.get("annotations").isJsonArray()) {
                JsonArray anns = sym.getAsJsonArray("annotations");
                StringBuilder b = new StringBuilder();
                for (JsonElement an : anns) {
                    if (!an.isJsonPrimitive()) continue;
                    if (b.length() > 0) b.append("\n// ");
                    b.append(an.getAsString());
                }
                if (b.length() > 0) {
                    try {
                        listing.setComment(a, CodeUnit.PLATE_COMMENT, b.toString());
                        comments++;
                    } catch (Exception e) {
                        println("ApplySymbols: could not set plate comment at " + a + ": " + e.getMessage());
                    }
                }
            }

            Function fn = fm.getFunctionAt(a);
            if (fn == null) {
                println("ApplySymbols: no function at " + a + " (entry may have moved)");
                skipped++;
                continue;
            }
            if (!sym.has("name") || sym.get("name").isJsonNull()) {
                continue; // no rename — Tier::None
            }
            String name = sym.get("name").getAsString();
            SourceType source = SourceType.ANALYSIS;
            if (sym.has("tier") && sym.get("tier").isJsonPrimitive()
                    && "recovered".equals(sym.get("tier").getAsString())) {
                source = SourceType.USER_DEFINED;
            }
            try {
                fn.setName(name, source);
                applied++;
            } catch (Exception e) {
                println("ApplySymbols: could not rename " + a + " to " + name + ": " + e.getMessage());
                skipped++;
            }
        }
        summarize(image, applied, comments, skipped);
    }

    private void summarize(String image, int applied, int comments, int skipped) {
        // Bypass GhidraScript.println (which routes through Msg.info and gets wrapped as
        // "INFO  ApplySymbols.java> ... (GhidraScript)"): emit on stdout verbatim so the
        // Rust driver's parse_pass2_summary can strip_prefix("ApplySymbols:").
        String line = "ApplySymbols: image=" + image + " applied " + applied
                + " names, " + comments + " plate comments, skipped " + skipped;
        System.out.println(line);
        println(line);
    }

    private static long parseAddr(String s) throws NumberFormatException {
        String t = s.trim();
        if (t.startsWith("0x") || t.startsWith("0X")) t = t.substring(2);
        return Long.parseUnsignedLong(t, 16);
    }
}
