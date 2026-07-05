// TameAnalysis.java — Ghidra headless PRE-script for pixel-modem-extractor.
// Runs before auto-analysis. Two jobs:
//
//   1. Disable the Aggressive Instruction Finder (coverage-neutral: Function Start
//      Search does the real discovery; measured identical counts with it on/off).
//   2. Mark the dense high-entropy regions passed as script args ("addrHex:lenHex")
//      as DATA. MAIN interleaves ARM/A32 code with large Thumb-2 blobs (the protocol
//      stack); Ghidra cannot converge on the Thumb blobs — it spins forever in an
//      overlapping-function repair loop — so the host hands those regions to radare2
//      instead and tells Ghidra to skip them here. With them marked as data, Ghidra's
//      analysis of the surrounding A32 code converges cleanly.
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

    @Override
    public void run() throws Exception {
        Options opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        for (String name : DISABLE) {
            if (opts.contains(name)) {
                opts.setBoolean(name, false);
                println("TameAnalysis: disabled '" + name + "'");
            }
        }

        Listing listing = currentProgram.getListing();
        for (String arg : getScriptArgs()) {
            int colon = arg.indexOf(':');
            if (colon < 0) {
                continue;
            }
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
    }
}
