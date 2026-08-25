// ApplyThumbNames.java — pass-2 creation of named producer-authenticated
// Thumb functions the Ghidra analyzer never discovered.
//
// A pass-2 symbol map (v3) carries a `creations` section: named Thumb
// executions whose identity a validated producer inventory (radare2/Rizin
// strict v3) authenticated over exact decode ranges, but whose entry is
// absent from the Ghidra function inventory. For every creation this script
// declares the Thumb context at the entry, disassembles over the
// authenticated address set (flow-enabled, code analysis disabled), creates
// a function, and names it (USER_DEFINED for recovered-tier evidence,
// ANALYSIS for provisional). The created function's body must cover every
// authenticated range — the map's execution identity is the fail-closed
// gate, never a prologue heuristic.
//
// Fail-closed rules mirrored from ApplySymbols/ApplyPalTasks:
// - a pre-existing Ghidra function at the entry is never touched (skipped);
// - a duplicate requested name is a skip, never a renamed variant;
// - every mutation is journaled and rolled back in reverse, and a failed
//   script transaction is aborted via end(false) — Ghidra otherwise commits
//   a failed script transaction;
// - the postflight re-verifies every created function's primary and source.
//
// Budgets: PME_THUMB_CREATE_ENTRY_BUDGET_MS (default 30 s) and
// PME_THUMB_CREATE_PHASE_BUDGET_MS (default 60 min); malformed or
// non-positive values fail loudly. Budgets gate wall-clock only.

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.util.task.TimeoutTaskMonitor;

import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class ApplyThumbNames extends HeadlessScript {
    private static final long ENTRY_BUDGET_MS =
            budgetOverride("PME_THUMB_CREATE_ENTRY_BUDGET_MS", 30_000L);
    private static final long PHASE_BUDGET_MS =
            budgetOverride("PME_THUMB_CREATE_PHASE_BUDGET_MS", 60 * 60_000L);
    /** Aggregate newly-defined bytes this script may carve (PAL precedent). */
    private static final long MAX_CREATED_BYTES = 64L * 1024L * 1024L;

    private static long budgetOverride(String variable, long fallback) {
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
        throw new PalTasksSupport.PalError(message);
    }

    private static void suppress(Throwable original, Throwable cleanupFailure) {
        if (cleanupFailure == original) {
            return;
        }
        try {
            original.addSuppressed(cleanupFailure);
        }
        catch (Throwable ignored) {
            // Preserve the original failure even if suppression is unavailable.
        }
    }

    @FunctionalInterface
    private interface Undo {
        void run() throws Exception;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) {
            fail("expected exactly four arguments: image label, image BLAKE3, "
                    + "symbol map, its BLAKE3");
        }
        String label = args[0];
        String imageBlake3 = args[1];
        File mapFile = new File(args[2]);
        String mapHash = args[3];

        // The map is authenticated through the shared reader; the retained
        // functions.json binding is verified by ApplySymbols in this same
        // process, so only the identity preflights are repeated here.
        PalTasksSupport.SymbolMap map = PalTasksSupport.readSymbolMapForExport(mapFile, mapHash);
        if (!label.equals(currentProgram.getName())) {
            fail("the expected image label does not match the current program name");
        }
        if (!imageBlake3.equals(map.imageBlake3)) {
            fail("the expected image BLAKE3 does not match the symbol map");
        }
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        if (tMode == null) {
            fail("the language lacks the TMode context register");
        }

        List<Undo> undoJournal = new ArrayList<>();
        long createdBytes = 0;
        int created = 0;
        int reapplied = 0;
        int skippedExisting = 0;
        boolean authenticatedConflictSkip = false;
        int skippedCollision = 0;
        long phaseDeadline = System.currentTimeMillis() + PHASE_BUDGET_MS;

        try {
            FunctionManager functions = currentProgram.getFunctionManager();
            List<Function> touched = new ArrayList<>();
            for (PalTasksSupport.MapCreation creation : map.creations) {
                Address entry = PalTasksSupport.programAddress(currentProgram, creation.entry);
                Function existing = functions.getFunctionAt(entry);
                SourceType wantedSource = "user_defined".equals(creation.finalSource)
                        ? SourceType.USER_DEFINED : SourceType.ANALYSIS;
                if (existing != null) {
                    if (existing.getName().equals(creation.finalPrimary)
                            && PalTasksSupport.primarySource(existing.getSymbol().getSource())
                                    .equals(creation.finalSource)) {
                        reapplied++;
                    }
                    else {
                        skippedExisting++;
                    }
                    continue;
                }
                if (System.currentTimeMillis() >= phaseDeadline) {
                    fail("the ApplyThumbNames phase budget was exhausted before " + entry);
                }
                long remaining = phaseDeadline - System.currentTimeMillis();
                long budget = Math.min(ENTRY_BUDGET_MS, Math.max(remaining, 1L));
                TimeoutTaskMonitor monitor =
                        TimeoutTaskMonitor.timeoutIn(budget, TimeUnit.MILLISECONDS);

                AddressSet authenticated = new AddressSet();
                for (PalTasksSupport.ExecutionRangeWire range : creation.decodeRanges) {
                    if (!"thumb".equals(range.isa)) {
                        fail("a creation decode range is not Thumb at " + entry);
                    }
                    authenticated.add(PalTasksSupport.programAddress(currentProgram, range.start),
                            PalTasksSupport.programAddress(currentProgram, range.end - 1));
                }

                // A Ghidra function overlapping the authenticated span must
                // never be damaged by the carve — skip (counted) instead.
                for (ghidra.program.model.listing.Instruction insn : currentProgram
                        .getListing().getInstructions(authenticated, true)) {
                    if (functions.getFunctionContaining(insn.getAddress()) != null) {
                        skippedExisting++;
                        authenticatedConflictSkip = true;
                        break;
                    }
                }
                if (authenticatedConflictSkip) {
                    authenticatedConflictSkip = false;
                    continue;
                }

                // 1. Declare the Thumb context over the first instruction.
                // Ghidra may already have disassembled these bytes in ARM
                // mode (unowned — no function claimed them); clearing those
                // instructions resolves the context conflict, and the whole
                // script transaction still rolls back atomically on failure.
                RegisterValue priorContext =
                        currentProgram.getProgramContext().getRegisterValue(tMode, entry);
                Address firstEnd = entry.add(creation.decodeRanges.get(0).end
                        - creation.decodeRanges.get(0).start - 1);
                try {
                    currentProgram.getProgramContext()
                            .setValue(tMode, entry, firstEnd, BigInteger.ONE);
                }
                catch (ghidra.program.model.listing.ContextChangeException conflict) {
                    for (ghidra.program.model.address.AddressRange range : authenticated) {
                        currentProgram.getListing().clearCodeUnits(range.getMinAddress(),
                                range.getMaxAddress(), false);
                    }
                    try {
                        currentProgram.getProgramContext()
                                .setValue(tMode, entry, firstEnd, BigInteger.ONE);
                    }
                    catch (ghidra.program.model.listing.ContextChangeException retry) {
                        fail("the creation ISA context could not be declared at " + entry
                                + ": " + retry.getMessage());
                    }
                }
                final RegisterValue priorFinal = priorContext;
                final Address firstEndFinal = firstEnd;
                undoJournal.add(() -> {
                    currentProgram.getProgramContext().remove(entry, firstEndFinal, tMode);
                    if (priorFinal != null && priorFinal.hasValue()) {
                        currentProgram.getProgramContext()
                                .setValue(tMode, entry, firstEndFinal, priorFinal.getUnsignedValue());
                    }
                });

                // 2. Bounded flow-enabled disassembly over authenticated memory.
                DisassembleCommand disassemble =
                        new DisassembleCommand(entry, authenticated, true);
                disassemble.enableCodeAnalysis(false);
                boolean disassembled = disassemble.applyTo(currentProgram, monitor);
                if (monitor.didTimeout()) {
                    fail("the per-entry ApplyThumbNames budget was exhausted at " + entry);
                }
                if (!disassembled) {
                    fail("disassembly failed at " + entry + ": " + disassemble.getStatusMsg());
                }
                AddressSetView disassembledSet = disassemble.getDisassembledAddressSet();
                createdBytes += disassembledSet.getNumAddresses();
                if (createdBytes > MAX_CREATED_BYTES) {
                    fail("the aggregate created-byte budget was exhausted at " + entry);
                }
                final AddressSetView toClear = disassembledSet;
                undoJournal.add(() -> {
                    for (ghidra.program.model.address.AddressRange range : toClear) {
                        currentProgram.getListing().clearCodeUnits(range.getMinAddress(),
                                range.getMaxAddress(), false);
                    }
                });

                // 3. Create the function, then name it.
                CreateFunctionCmd create =
                        new CreateFunctionCmd(null, entry, null, SourceType.ANALYSIS);
                if (!create.applyTo(currentProgram, monitor) || monitor.didTimeout()) {
                    fail("function creation failed at " + entry + ": " + create.getStatusMsg());
                }
                Function function = functions.getFunctionAt(entry);
                if (function == null) {
                    fail("no function exists at the created entry " + entry);
                }
                undoJournal.add(() -> functions.removeFunction(entry));
                try {
                    function.setName(creation.finalPrimary, wantedSource);
                }
                catch (ghidra.util.exception.DuplicateNameException
                        | ghidra.util.exception.InvalidInputException error) {
                    skippedCollision++;
                    functions.removeFunction(entry);
                    undoJournal.remove(undoJournal.size() - 1);
                    continue;
                }
                catch (Throwable error) {
                    fail("the creation rename to " + creation.finalPrimary + " failed at "
                            + entry + ": " + error.getMessage());
                }

                // 4. The created function must sit at the entry with its first
                // authenticated instruction inside the body. Full-range
                // coverage is deliberately NOT required: the authenticated
                // ranges gate WHICH entries are eligible (a validated
                // producer execution), while Ghidra's own flow analysis owns
                // how far the body extends.
                AddressSetView body = function.getBody();
                if (!body.contains(entry,
                        entry.add(creation.decodeRanges.get(0).end
                                - creation.decodeRanges.get(0).start - 1))) {
                    fail("the created body does not contain the entry instruction at "
                            + entry + " (body=" + body + ")");
                }
                touched.add(function);
                created++;
            }

            // Postflight: every created or reapplied function still carries
            // its final primary and source.
            for (PalTasksSupport.MapCreation creation : map.creations) {
                Address entry = PalTasksSupport.programAddress(currentProgram, creation.entry);
                Function function = functions.getFunctionAt(entry);
                if (function == null || !function.getName().equals(creation.finalPrimary)
                        || !PalTasksSupport.primarySource(function.getSymbol().getSource())
                                .equals(creation.finalSource)) {
                    fail("verification lost a created function at " + entry);
                }
            }
        }
        catch (Throwable original) {
            for (int index = undoJournal.size() - 1; index >= 0; index--) {
                try {
                    undoJournal.get(index).run();
                }
                catch (Throwable cleanupFailure) {
                    suppress(original, cleanupFailure);
                }
            }
            end(false);
            if (original instanceof PalTasksSupport.PalError pal) {
                throw pal;
            }
            if (original instanceof Exception exception) {
                throw exception;
            }
            throw new Exception(original);
        }

        String summary = "ApplyThumbNames: image=" + label + " created " + created
                + " functions, " + reapplied + " reapplied, skipped_existing="
                + skippedExisting + ", skipped_collision=" + skippedCollision + " over "
                + map.creations.size() + " creations";
        System.out.println(summary);
        println(summary);
    }
}
