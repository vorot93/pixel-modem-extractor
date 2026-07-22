// TameAnalysis.java — Ghidra headless PRE-script for pixel-modem-extractor.
// Runs before auto-analysis. Phase 2+: takes a mode argument.
//
//   arg[0] = "tighten" (new default; Phase 2+): disable the Aggressive Instruction
//     Finder plus the analysis options identified by the Phase-2.1 investigation
//     (TIGHTEN_EXTRA disables the `Repair Flow Damage` sub-option of
//     `Non-Returning Functions - Discovered` — see CONTRIBUTING.md § Winning
//     TameAnalysis options). Does NOT data-mark regions; Ghidra attempts Thumb
//     function discovery and decompilation. Per-function convergence failures
//     fall through to radare2 in the Rust host (see decompile::thumb_enrich).
//
//   arg[0] = "datamark" (today's Phase-1 behavior; also used by --no-thumb-decompile):
//     additionally mark each remaining arg "addrHex:lenHex" as DATA so Ghidra's
//     analysis of surrounding A32 code converges cleanly on images whose dense
//     Thumb regions we don't want Ghidra to attempt.
//
// When no arg is supplied, defaults to "tighten" (Phase 2+ production behavior).
//@category PixelModem
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

public class TameAnalysis extends GhidraScript {
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

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = args.length == 0 ? "tighten" : args[0];

        Options opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        for (String name : DISABLE) {
            if (opts.contains(name)) {
                opts.setBoolean(name, false);
                println("TameAnalysis: disabled '" + name + "'");
            }
        }

        if (mode.equals("tighten")) {
            for (String name : TIGHTEN_EXTRA) {
                if (opts.contains(name)) {
                    opts.setBoolean(name, false);
                    println("TameAnalysis: disabled '" + name + "'");
                }
            }
            println("TameAnalysis: mode=tighten (Phase 2+)");
            return;
        }

        if (mode.equals("datamark")) {
            Listing listing = currentProgram.getListing();
            for (int i = 1; i < args.length; i++) {
                String arg = args[i];
                int colon = arg.indexOf(':');
                if (colon < 0) continue;
                long addr = Long.parseLong(arg.substring(0, colon), 16);
                long len = Long.parseLong(arg.substring(colon + 1), 16);
                Address start = toAddr(addr);
                Address end = start.add(len - 1);
                try {
                    listing.clearCodeUnits(start, end, false);
                    listing.createData(start, new ArrayDataType(Undefined1DataType.dataType, (int) len, 1));
                    println("TameAnalysis: marked data region (radare2 handles it) " + start + ".." + end);
                } catch (Exception e) {
                    println("TameAnalysis: could not mark " + start + ": " + e.getMessage());
                }
            }
            println("TameAnalysis: mode=datamark (Phase-1 fallback)");
            return;
        }

        println("TameAnalysis: unknown mode '" + mode + "' (expected 'tighten' or 'datamark')");
    }
}
