// ApplyThumbNames.java — pass-2 creation of named producer-authenticated
// Thumb functions the Ghidra analyzer never discovered.
//
// A pass-2 symbol map (v4) carries a `creations` section: named Thumb
// executions whose identity a validated producer inventory (radare2/Rizin
// strict v3) authenticated over exact decode ranges, but whose entry is
// absent from the Ghidra function inventory. For every creation this script
// declares the Thumb context at the entry, disassembles only inside the
// authenticated address set (flow-enabled, code analysis disabled), and
// passes the explicit returned disassembly set to CreateFunctionCmd before
// naming it (USER_DEFINED for recovered-tier evidence, ANALYSIS for
// provisional). The final function body must remain wholly inside the
// authenticated ranges.
//
// This script runs before every other pass-2 mutator so malformed producer or
// ownership state cannot follow another mutation. Ghidra rolls it back when a
// later post-script fails in the same headless invocation. A separately
// committed staged run is still valid only for an identical retry, which
// revalidates it as reapplied before Rust publishes an export. Persistent
// ownership lives in PixelModemExtractor.ThumbNames.v1.Ownership with value:
// v1:<map_blake3>:<producer_execution_blake3>:<function_id>:<primary_symbol_id>:<ghidra_execution_blake3>.
// A successor map may represent an old creation through either its current
// creation request or authenticated execution. Preflight validates every row,
// then transactionally rewrites only predecessor map hashes; SymbolPass2 stays
// at the predecessor value until ApplySymbols completes the current map.
//
// Arguments: canonical kit root, label, image BLAKE3, exception identity,
// exception manifest or '-', scatter map or '-', retained functions.json and
// its BLAKE3, then the symbol map and its BLAKE3.
//
// Fail-closed rules mirrored from ApplySymbols/ApplyPalTasks:
// - existing-entry handling is exhaustive and ordered: an owned matching
//   existing function is fully revalidated and counted reapplied; an exact
//   name/source existing function without ownership is a hard failure; any
//   other existing entry function is preserved and counted skipped_existing;
// - a duplicate requested name is a skip, never a renamed variant;
// - every mutation is journaled and rolled back in reverse, and a failed
//   script transaction is aborted via end(false) — Ghidra otherwise commits
//   a failed script transaction;
// - postflight re-verifies ownership, concrete function/symbol IDs,
//   primary/source, projection, memory, and execution digest.
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
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.task.TimeoutTaskMonitor;
import com.google.gson.JsonObject;

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

    private static long phaseRemaining(long deadline, Address entry) {
        long remaining = deadline - System.currentTimeMillis();
        if (remaining <= 0) {
            fail("the ApplyThumbNames phase budget was exhausted before " + entry);
        }
        return remaining;
    }

    private static TimeoutTaskMonitor phaseMonitor(long deadline, Address entry) {
        long budget = Math.min(ENTRY_BUDGET_MS, phaseRemaining(deadline, entry));
        return TimeoutTaskMonitor.timeoutIn(budget, TimeUnit.MILLISECONDS);
    }

    private boolean hasStraddlingCodeUnit(AddressSet authenticated) {
        for (ghidra.program.model.address.AddressRange range : authenticated) {
            for (Address boundary : new Address[] {
                    range.getMinAddress(), range.getMaxAddress() }) {
                CodeUnit unit = currentProgram.getListing().getCodeUnitContaining(boundary);
                if (unit != null && !authenticated.contains(
                        unit.getMinAddress(), unit.getMaxAddress())) {
                    return true;
                }
            }
        }
        CodeUnitIterator units = currentProgram.getListing().getCodeUnits(authenticated, true);
        while (units.hasNext()) {
            CodeUnit unit = units.next();
            if (!authenticated.contains(unit.getMinAddress(), unit.getMaxAddress())) {
                return true;
            }
        }
        return false;
    }

    private void clearContainedCodeUnits(AddressSet authenticated) {
        AddressSet clearable = new AddressSet();
        CodeUnitIterator units = currentProgram.getListing().getCodeUnits(authenticated, true);
        while (units.hasNext()) {
            CodeUnit unit = units.next();
            if (!authenticated.contains(unit.getMinAddress(), unit.getMaxAddress())) {
                fail("a code unit straddles authenticated creation memory at "
                        + unit.getMinAddress());
            }
            clearable.add(unit.getMinAddress(), unit.getMaxAddress());
        }
        for (ghidra.program.model.address.AddressRange range : clearable) {
            currentProgram.getListing().clearCodeUnits(
                    range.getMinAddress(), range.getMaxAddress(), false);
        }
    }

    @FunctionalInterface
    private interface Undo {
        void run() throws Exception;
    }

    private static final class Planned {
        final PalTasksSupport.MapCreation creation;
        final Address entry;
        final SourceType wantedSource;
        final AddressSet authenticated;

        Planned(PalTasksSupport.MapCreation creation, Address entry, SourceType wantedSource,
                AddressSet authenticated) {
            this.creation = creation;
            this.entry = entry;
            this.wantedSource = wantedSource;
            this.authenticated = authenticated;
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 10) {
            fail("expected exactly ten arguments: kit root, image label, image BLAKE3, "
                    + "exception identity, exception manifest, scatter manifest, retained "
                    + "functions.json, its BLAKE3, symbol map, its BLAKE3");
        }
        File kitRoot = new File(args[0]);
        String label = args[1];
        String imageBlake3 = args[2];
        String exceptionIdentity = args[3];
        File exceptionManifest = "-".equals(args[4]) ? null : new File(args[4]);
        String scatterArgument = args[5];
        File functionsFile = new File(args[6]);
        String functionsHash = args[7];
        File mapFile = new File(args[8]);
        String mapHash = args[9];

        ExceptionRootsSupport.Pass2MapState pass2State =
                ExceptionRootsSupport.retainPass2MapState(
                        currentProgram, monitor, kitRoot, label, imageBlake3,
                        exceptionIdentity, exceptionManifest, scatterArgument,
                        functionsFile, functionsHash, mapFile, mapHash,
                        ExceptionRootsSupport.Pass2MapPhase.BEFORE_MUTATION);
        PalTasksSupport.SymbolMap map = pass2State.map;

        List<Undo> undoJournal = new ArrayList<>();
        try {
            Register tMode = currentProgram.getLanguage().getRegister("TMode");
            if (tMode == null) {
                fail("the language lacks the TMode context register");
            }
            long createdBytes = 0;
            int created = 0;
            int reapplied = 0;
            int skippedExisting = 0;
            int skippedCollision = 0;
            long phaseDeadline = Math.addExact(System.currentTimeMillis(), PHASE_BUDGET_MS);
            FunctionManager functions = currentProgram.getFunctionManager();
            PropertyMapManager properties = currentProgram.getUsrPropertyManager();
            PalTasksSupport.ThumbOwnershipState ownershipState = pass2State.thumbOwnership();
            StringPropertyMap ownership = ownershipState.registry;
            List<PalTasksSupport.MapCreation> verified = new ArrayList<>();
            List<Planned> planned = new ArrayList<>();
            AddressSet reserved = new AddressSet();

            // Complete classification preflight. No registry, context,
            // instruction, function, or symbol mutation occurs until every
            // candidate has reached exactly one replay/skip/planned outcome.
            for (PalTasksSupport.MapCreation creation : map.creations) {
            Address entry = PalTasksSupport.programAddress(currentProgram, creation.entry);
            TimeoutTaskMonitor preflightMonitor = phaseMonitor(phaseDeadline, entry);
            PalTasksSupport.validateThumbCreationExecution(
                    currentProgram, preflightMonitor, creation);
            if (preflightMonitor.didTimeout()) {
                fail("the ApplyThumbNames preflight budget was exhausted at " + entry);
            }
            try {
                SymbolUtilities.validateName(creation.finalPrimary);
            }
            catch (ghidra.util.exception.InvalidInputException rejected) {
                skippedCollision++;
                phaseRemaining(phaseDeadline, entry);
                continue;
            }
            Function existing = functions.getFunctionAt(entry);
            PalTasksSupport.ThumbCreationOwnership owned = ownershipState.at(creation.entry);
            SourceType wantedSource = "user_defined".equals(creation.finalSource)
                    ? SourceType.USER_DEFINED : SourceType.ANALYSIS;
            if (existing != null) {
                if (owned != null) {
                    TimeoutTaskMonitor replayMonitor = phaseMonitor(phaseDeadline, entry);
                    PalTasksSupport.validateOwnedThumbCreation(
                            currentProgram, replayMonitor, owned, creation);
                    if (replayMonitor.didTimeout()) {
                        fail("the ApplyThumbNames replay preflight budget was exhausted at "
                                + entry);
                    }
                    reapplied++;
                    verified.add(creation);
                }
                else if (existing.getName().equals(creation.finalPrimary)
                        && PalTasksSupport.primarySource(existing.getSymbol().getSource())
                                .equals(creation.finalSource)) {
                    fail("an exact Thumb creation replay lacks ownership at " + entry);
                }
                else {
                    skippedExisting++;
                }
                phaseRemaining(phaseDeadline, entry);
                continue;
            }
            if (owned != null) {
                fail("the Thumb creation registry names a missing function at " + entry);
            }

            AddressSet authenticated = new AddressSet();
            for (PalTasksSupport.ExecutionRangeWire range : creation.decodeRanges) {
                authenticated.add(PalTasksSupport.programAddress(currentProgram, range.start),
                        PalTasksSupport.programAddress(currentProgram, range.end - 1));
            }

            // A current or earlier-planned function overlapping the
            // authenticated span must never be damaged by a later carve.
            boolean overlap = reserved.intersects(authenticated);
            overlap |= functions.getFunctionsOverlapping(authenticated).hasNext();
            overlap |= hasStraddlingCodeUnit(authenticated);
            if (overlap) {
                skippedExisting++;
                phaseRemaining(phaseDeadline, entry);
                continue;
            }
            boolean nameCollision = false;
            for (Symbol ignored : currentProgram.getSymbolTable().getSymbols(
                    creation.finalPrimary, currentProgram.getGlobalNamespace())) {
                nameCollision = true;
                break;
            }
            if (nameCollision) {
                skippedCollision++;
                phaseRemaining(phaseDeadline, entry);
                continue;
            }
            reserved.add(authenticated);
            planned.add(new Planned(creation, entry, wantedSource, authenticated));
            phaseRemaining(phaseDeadline, entry);
            }
            long projectedFunctions = Math.addExact(
                    (long) functions.getFunctionCount(), (long) planned.size());
            if (projectedFunctions > PalTasksSupport.MAX_FUNCTIONS) {
                fail("the planned creations exceed the terminal function limit");
            }

            if (!ownershipState.migrations.isEmpty()) {
                if (ownership == null) {
                    fail("Thumb ownership migration requires its registry");
                }
                final StringPropertyMap migrationRegistry = ownership;
                for (PalTasksSupport.ThumbOwnershipMigration migration
                        : ownershipState.migrations) {
                    undoJournal.add(() -> migrationRegistry.add(
                            migration.entry, migration.priorValue));
                    migrationRegistry.add(migration.entry, migration.currentValue);
                }
            }
            if (!planned.isEmpty() && ownership == null) {
                ownership = properties.createStringPropertyMap(
                        PalTasksSupport.THUMB_CREATION_OWNERSHIP_MAP);
                undoJournal.add(() -> {
                    if (!properties.removePropertyMap(
                            PalTasksSupport.THUMB_CREATION_OWNERSHIP_MAP)) {
                        throw new Exception("the Thumb creation ownership map was not removed");
                    }
                });
            }
            final StringPropertyMap activeOwnership = ownership;
            for (Planned plan : planned) {
                PalTasksSupport.MapCreation creation = plan.creation;
                Address entry = plan.entry;
                SourceType wantedSource = plan.wantedSource;
                AddressSet authenticated = plan.authenticated;
                TimeoutTaskMonitor monitor = phaseMonitor(phaseDeadline, entry);

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
                    clearContainedCodeUnits(authenticated);
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
                if (!authenticated.contains(disassembledSet)
                        || !disassembledSet.contains(entry)) {
                    fail("disassembly left authenticated creation memory at " + entry);
                }
                createdBytes = Math.addExact(createdBytes, disassembledSet.getNumAddresses());
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

                // 3. Create exactly the returned disassembly set, then name it.
                CreateFunctionCmd create =
                        new CreateFunctionCmd(null, entry, disassembledSet, SourceType.ANALYSIS);
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
                    fail("the creation rename to " + creation.finalPrimary + " failed at "
                            + entry + ": " + error.getMessage());
                }

                // 4. The created function must stay inside the authenticated
                // producer ranges and begin with a real Thumb instruction.
                if (currentProgram.getListing().getInstructionAt(entry) == null) {
                    fail("the created function has no instruction at the entry " + entry);
                }
                if (!authenticated.contains(function.getBody())) {
                    fail("the created function body leaves authenticated memory at " + entry);
                }
                if (activeOwnership == null) {
                    fail("the Thumb creation ownership map is missing at " + entry);
                }
                String ownershipValue = PalTasksSupport.thumbCreationOwnershipValue(
                        map, creation, function, monitor);
                if (monitor.didTimeout()) {
                    fail("the per-entry ApplyThumbNames ownership budget was exhausted at "
                            + entry);
                }
                activeOwnership.add(entry, ownershipValue);
                undoJournal.add(() -> activeOwnership.remove(entry));
                if (monitor.didTimeout()) {
                    fail("the per-entry ApplyThumbNames ownership budget was exhausted at "
                            + entry);
                }
                verified.add(creation);
                created++;
            }

            // Postflight: every created or reapplied function still has its
            // exact ownership, function/symbol identity, primary/source,
            // projection, memory, and execution digest.
            for (PalTasksSupport.MapCreation creation : verified) {
                Address entry = PalTasksSupport.programAddress(currentProgram, creation.entry);
                TimeoutTaskMonitor postflightMonitor = phaseMonitor(phaseDeadline, entry);
                PalTasksSupport.validateOwnedThumbCreation(currentProgram, postflightMonitor,
                        activeOwnership, map, creation);
                if (postflightMonitor.didTimeout()) {
                    fail("the ApplyThumbNames postflight budget was exhausted at " + entry);
                }
            }
            int classified = Math.addExact(Math.addExact(created, reapplied),
                    Math.addExact(skippedExisting, skippedCollision));
            if (classified != map.creations.size()) {
                fail("the ApplyThumbNames classification did not conserve candidates");
            }
            pass2State.validate(ExceptionRootsSupport.Pass2MapPhase.BEFORE_MUTATION);
            pass2State.verifyRetainedFiles();
            pass2State.close();

            JsonObject payload = new JsonObject();
            payload.addProperty("image", label);
            payload.addProperty("status", "ok");
            payload.addProperty("candidates", map.creations.size());
            payload.addProperty("created", created);
            payload.addProperty("reapplied", reapplied);
            payload.addProperty("skipped_existing", skippedExisting);
            payload.addProperty("skipped_collision", skippedCollision);
            String summary = "ApplyThumbNames: " + payload;
            phaseRemaining(phaseDeadline,
                    PalTasksSupport.programAddress(currentProgram, map.imageBase));
            System.out.println(summary);
            println(summary);
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
            try {
                end(false);
            }
            catch (Throwable abortFailure) {
                suppress(original, abortFailure);
            }
            try {
                pass2State.close();
            }
            catch (Throwable closeFailure) {
                suppress(original, closeFailure);
            }
            if (original instanceof PalTasksSupport.PalError pal) {
                throw pal;
            }
            if (original instanceof Exception exception) {
                throw exception;
            }
            throw new Exception(original);
        }
    }
}
