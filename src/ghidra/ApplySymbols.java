// ApplySymbols.java — strict transactional pass-2 symbol application for
// pixel-modem-extractor.
//
// Arg[0]  = canonical import-kit root.
// Arg[1]  = expected image label.
// Arg[2]  = expected image BLAKE3.
// Arg[3]  = expected exception-root identity or "none".
// Arg[4]  = canonical exception-root manifest or "-".
// Arg[5]  = expected PAL identity or "none".
// Arg[6]  = canonical task manifest or "-" under the ApplyPalTasks rule.
// Arg[7]  = canonical scatter manifest or "-" under both manifest rules.
// Arg[8]  = canonical retained pass-1 functions.json.
// Arg[9]  = expected lowercase functions.json BLAKE3.
// Arg[10] = canonical symbol_map.json.
// Arg[11] = expected lowercase symbol-map BLAKE3.
//
// A strict HeadlessScript: exactly twelve arguments, every retained file opened
// and hashed once through PalTasksSupport, the map's image/PAL cross-fields
// verified against the current program state, and every decision's current
// body and primary verified BEFORE the first mutation. Application is
// transactional: a rename may displace only a registry-bound pal_owned task
// primary (recording the exact pal_owned -> pass2_owned transition in the
// ownership registry), reserved labels, the owned repeatable comment, and the
// core registry fields are verified unchanged after mutation, and
// PixelModemExtractor.SymbolPass2 is set to
// "v3:<map-blake3>:<pass1-functions-blake3>:<execution-count>" only after the
// full postflight. Every pre-existing skip case (missing function, invalid
// name, collision, unauthorized disposition) now throws; there is no
// print-and-continue path. On any throwable the mutation is undone in reverse
// order, the script transaction is aborted with end(false), and the original
// failure is rethrown.
//
// Success prints exactly one summary line:
//   ApplySymbols: image=<label> applied N names, M plate comments over E executions
//@category PixelModem
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.StringPropertyMap;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class ApplySymbols extends HeadlessScript {
    private static final long METADATA_PER_EXECUTION = 64L;
    private static final long METADATA_PER_RANGE = 16L;

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

    private static void rethrow(Throwable failure) throws Exception {
        if (failure instanceof Exception) {
            throw (Exception) failure;
        }
        if (failure instanceof Error) {
            throw (Error) failure;
        }
        throw new RuntimeException(failure);
    }

    @Override
    public void run() throws Exception {
        Preflight preflight = preflight();
        Mutation mutation = new Mutation(preflight);
        try {
            mutation.applyAll();
        }
        catch (Throwable failure) {
            mutation.rollback(failure);
            rethrow(failure);
        }
    }

    // ---------------------------------------------------------------------
    // Preflight: complete validation before any mutation
    // ---------------------------------------------------------------------

    private final class Preflight {
        final PalTasksSupport.SymbolMap map;
        final String label;
        final ExceptionRootsSupport.Pass2MapState pass2State;
        final String palIdentity;
        final boolean palPresent;
        final List<Planned> planned;
        final StringPropertyMap exceptionRegistry;
        final StringPropertyMap palRegistry;

        Preflight(PalTasksSupport.SymbolMap map, String label,
                ExceptionRootsSupport.Pass2MapState pass2State,
                String palIdentity, boolean palPresent, List<Planned> planned,
                StringPropertyMap exceptionRegistry, StringPropertyMap palRegistry) {
            this.map = map;
            this.label = label;
            this.pass2State = pass2State;
            this.palIdentity = palIdentity;
            this.palPresent = palPresent;
            this.planned = planned;
            this.exceptionRegistry = exceptionRegistry;
            this.palRegistry = palRegistry;
        }
    }

    /** One authorized decision with its current-state verification. */
    private final class Planned {
        final PalTasksSupport.MapExecution execution;
        final PalTasksSupport.MapDecision decision;
        final Function function;
        final boolean rename;
        final boolean exceptionTransition;
        final boolean palTransition;
        final boolean thunk;

        Planned(PalTasksSupport.MapExecution execution, PalTasksSupport.MapDecision decision,
                Function function, boolean rename) {
            this.execution = execution;
            this.decision = decision;
            this.function = function;
            this.rename = rename;
            this.exceptionTransition = decision.exceptionTransitionAuthority != null;
            this.palTransition = decision.palTransition;
            this.thunk = function.isThunk();
        }
    }

    private Preflight preflight() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 12) {
            fail("expected exactly twelve arguments: kit root, image label, image BLAKE3, "
                    + "exception identity, exception manifest, PAL identity, task manifest, "
                    + "scatter manifest, retained functions.json, "
                    + "its BLAKE3, symbol map, its BLAKE3");
        }
        File kitRoot = new File(args[0]);
        String label = args[1];
        String imageBlake3 = args[2];
        String exceptionIdentity = args[3];
        File exceptionManifest = "-".equals(args[4]) ? null : new File(args[4]);
        String palIdentity = args[5];
        File taskManifest = "-".equals(args[6]) ? null : new File(args[6]);
        File scatterManifest = "-".equals(args[7]) ? null : new File(args[7]);
        File functionsFile = new File(args[8]);
        String functionsHash = args[9];
        File mapFile = new File(args[10]);
        String mapHash = args[11];

        ExceptionRootsSupport.Pass2MapState pass2State =
                ExceptionRootsSupport.retainPass2MapState(
                        currentProgram, monitor, kitRoot, label, imageBlake3,
                        exceptionIdentity, exceptionManifest,
                        scatterManifest == null ? "-" : scatterManifest.getPath(),
                        functionsFile, functionsHash, mapFile, mapHash,
                        ExceptionRootsSupport.Pass2MapPhase.BEFORE_MUTATION);
        PalTasksSupport.SymbolMap map = pass2State.map;
        try {
            verifyImageBlock(map);

        boolean exceptionPresent = !PalTasksSupport.NONE_IDENTITY.equals(exceptionIdentity);

        boolean palPresent = !PalTasksSupport.NONE_IDENTITY.equals(palIdentity);
        if (palPresent) {
            if (taskManifest == null) {
                fail("a present PAL identity requires the task manifest argument");
            }
            PalTasksSupport.PalManifest manifest =
                    PalTasksSupport.readPal(kitRoot, label, taskManifest, scatterManifest);
            String identity = PalTasksSupport.expectedPalIdentity(manifest);
            if (!identity.equals(palIdentity)) {
                fail("the expected PAL identity does not match the manifest");
            }
            if (!palIdentity.equals(map.palIdentity)) {
                fail("the symbol map PAL identity does not match the expected identity");
            }
            if (!manifest.manifestBlake3.equals(map.manifestBlake3)) {
                fail("the symbol map manifest BLAKE3 does not match the manifest");
            }
            if (!java.util.Objects.equals(manifest.scatterLoadMapBlake3,
                    map.scatterLoadMapBlake3)) {
                fail("the symbol map scatter dependency does not match the manifest");
            }
            PalTasksSupport.validateApplied(currentProgram, manifest, palIdentity);
        }
        else {
            if (taskManifest != null) {
                fail("identity none requires the literal '-' task manifest");
            }
            if (!PalTasksSupport.NONE_IDENTITY.equals(map.palIdentity)) {
                fail("the symbol map binds a PAL identity the invocation does not declare");
            }
            PalTasksSupport.validateAbsent(currentProgram);
        }

        StringPropertyMap palRegistry = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
        if (palPresent && palRegistry == null) {
            fail("the ownership registry is missing under a present identity");
        }
        StringPropertyMap exceptionRegistry = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap(ExceptionRootsSupport.OWNERSHIP_MAP);
        if (exceptionPresent && exceptionRegistry == null) {
            fail("the exception ownership registry is missing under a present identity");
        }
        if (!pass2State.thumbOwnership().migrations.isEmpty()) {
            fail("ApplyThumbNames did not migrate predecessor Thumb ownership");
        }

        FunctionManager functions = currentProgram.getFunctionManager();
        List<Planned> planned = new ArrayList<Planned>();
        long metadata = 0;
        for (int index = 0; index < map.executions.size(); index++) {
            PalTasksSupport.MapExecution execution = map.executions.get(index);
            PalTasksSupport.MapDecision decision = map.decisions.get(index);
            metadata = Math.addExact(metadata, METADATA_PER_EXECUTION
                    + Math.multiplyExact(METADATA_PER_RANGE, execution.decodeRanges.size()));
            if (metadata > PalTasksSupport.MAX_APPLY_PREFLIGHT_METADATA) {
                fail("the apply preflight metadata exceeds the 128 MiB limit");
            }
            Address entry = PalTasksSupport.programAddress(currentProgram, execution.entry);
            Function function = functions.getFunctionAt(entry);
            if (function == null) {
                fail("no function exists at the map execution entry " + entry);
            }
            verifyCurrentBody(execution, function);
            verifyAndAuthorize(execution, decision, function, exceptionRegistry, palRegistry);
            boolean rename = "rename".equals(decision.action)
                    && !function.getName().equals(decision.finalPrimary);
            planned.add(new Planned(execution, decision, function, rename));
        }
        return new Preflight(map, label, pass2State, palIdentity, palPresent,
                planned, exceptionRegistry, palRegistry);
        }
        catch (Throwable error) {
            try {
                pass2State.close();
            }
            catch (Throwable closeFailure) {
                suppress(error, closeFailure);
            }
            rethrow(error);
            return null;
        }
    }

    /**
     * The raw image block must exactly match the map's declared image range;
     * a present manifest re-authenticates the image bytes themselves through
     * readPal during preflight.
     */
    private void verifyImageBlock(PalTasksSupport.SymbolMap map) {
        Address base = PalTasksSupport.programAddress(currentProgram, map.imageBase);
        Address last = PalTasksSupport.programAddress(currentProgram,
                Math.addExact(map.imageBase, map.imageSize) - 1);
        MemoryBlock block = currentProgram.getMemory().getBlock(base);
        if (block == null || !block.getStart().equals(base) || !block.getEnd().equals(last)
                || !block.isInitialized()) {
            fail("the program raw image block does not match the symbol map image range");
        }
    }

    /**
     * The current function body must still produce the map's exact
     * authenticated execution identity: every decode range, its memory hash,
     * and the recomputed domain-separated digest.
     */
    private void verifyCurrentBody(PalTasksSupport.MapExecution execution, Function function)
            throws Exception {
        PalTasksSupport.DecodeProjection projection =
                PalTasksSupport.decodeProjection(currentProgram, monitor, function);
        if (!projection.errors.isEmpty()) {
            fail("the current decode projection is quarantined at "
                    + function.getEntryPoint());
        }
        if (projection.ranges.size() != execution.decodeRanges.size()) {
            fail("the decode range count changed at " + function.getEntryPoint());
        }
        for (int index = 0; index < projection.ranges.size(); index++) {
            PalTasksSupport.DecodeRange current = projection.ranges.get(index);
            PalTasksSupport.ExecutionRangeWire expected = execution.decodeRanges.get(index);
            if (current.start != expected.start || current.end != expected.end
                    || !current.isa.equals(expected.isa) || !current.blake3.equals(expected.blake3)) {
                fail("the decode range changed at " + function.getEntryPoint());
            }
        }
        if (!PalTasksSupport.currentExecutionDigest(currentProgram, monitor, function)
                .equals(execution.executionBlake3)) {
            fail("the execution identity changed at " + function.getEntryPoint());
        }
    }

    /**
     * The current primary must match the map's expectation (the retained
     * original on first application, the final value on an idempotent
     * replay), and every rename must be authorized: only a default-sourced
     * primary, a non-registry analysis-sourced primary, or an exact
     * registry-bound exception_owned/pal_owned transition may be displaced.
     */
    private void verifyAndAuthorize(PalTasksSupport.MapExecution execution,
            PalTasksSupport.MapDecision decision, Function function,
            StringPropertyMap exceptionRegistry, StringPropertyMap palRegistry) {
        Address entry = function.getEntryPoint();
        String currentName = function.getName();
        String currentSource =
                PalTasksSupport.primarySource(function.getSymbol().getSource());

        if (currentName.equals(decision.finalPrimary)
                && currentSource.equals(decision.finalSource)) {
            // Already applied (a preserve decision, or a completed rename).
            if (decision.exceptionTransitionAuthority != null) {
                ExceptionRootsSupport.RegistryEntry retained =
                        ExceptionRootsSupport.parseRegistry(
                                exceptionRegistry == null ? null
                                        : exceptionRegistry.getString(entry));
                ExceptionRootsSupport.validatePass2Transition(
                        currentProgram, retained, execution, decision, entry);
            }
            if (decision.palTransition) {
                requirePalRegistryDisposition(palRegistry, entry, "pass2_owned");
            }
            return;
        }
        if (!currentName.equals(decision.originalPrimary)
                || !currentSource.equals(decision.originalSource)) {
            fail("the current primary changed at " + entry + ": expected ("
                    + decision.originalPrimary + "," + decision.originalSource + ") found ("
                    + currentName + "," + currentSource + ")");
        }
        if (!"rename".equals(decision.action)) {
            return; // preserve: the identical-primary check above is exhaustive
        }

        String exceptionDisposition = exceptionRegistryDisposition(exceptionRegistry, entry);
        if (exceptionDisposition != null) {
            switch (exceptionDisposition) {
                case "exception_owned":
                    if (decision.exceptionTransitionAuthority == null) {
                        fail("an exception-owned primary may be renamed only through the exact "
                                + "stronger-evidence transition at " + entry);
                    }
                    if (!decision.finalSource.equals("user_defined")) {
                        fail("an exception transition must produce a user_defined primary at "
                                + entry);
                    }
                    validateFreshExceptionTransition(
                            execution, decision, function, exceptionRegistry);
                    return;
                case "preserved":
                case "not_requested":
                    fail("a registry " + exceptionDisposition
                            + " exception primary is not replaceable at " + entry);
                    return;
                case "pass2_owned":
                    fail("a registry pass2_owned exception primary does not match the map "
                            + "decision at " + entry);
                    return;
                default:
                    fail("an unknown exception registry disposition blocks the rename at "
                            + entry);
                    return;
            }
        }
        String palDisposition = palRegistryDisposition(palRegistry, entry);
        if (palDisposition != null) {
            switch (palDisposition) {
                case "pal_owned":
                    if (!decision.palTransition) {
                        fail("a registry pal_owned primary may be renamed only through the "
                                + "exact PAL transition at " + entry);
                    }
                    if (!decision.finalSource.equals("user_defined")) {
                        fail("a PAL transition rename must produce a user_defined primary at "
                                + entry);
                    }
                    return;
                case "preserved":
                    fail("a registry preserved primary is not replaceable at " + entry);
                    return;
                case "pass2_owned":
                    fail("a registry pass2_owned primary does not match the map decision at "
                            + entry);
                    return;
                default:
                    fail("an unknown registry disposition blocks the rename at " + entry);
                    return;
            }
        }
        // No PAL ownership: fresh defaults and Ghidra-analysis primaries may
        // be displaced (recovered and provisional names apply over them);
        // genuine imported or user-defined names remain protected.
        if (!currentSource.equals("default") && !currentSource.equals("analysis")) {
            fail("an unauthorized rename targets a " + currentSource + " primary at " + entry);
        }
        if (decision.palTransition) {
            fail("a PAL transition decision has no registry binding at " + entry);
        }
        if (decision.exceptionTransitionAuthority != null) {
            fail("an exception transition decision has no registry binding at " + entry);
        }
    }

    private static String palRegistryDisposition(StringPropertyMap registry, Address entry) {
        if (registry == null) {
            return null;
        }
        String value = registry.getString(entry);
        if (value == null) {
            return null;
        }
        return PalTasksSupport.parseRegistry(value).primaryDisposition;
    }

    private void validateFreshExceptionTransition(PalTasksSupport.MapExecution execution,
            PalTasksSupport.MapDecision decision, Function function,
            StringPropertyMap registry) {
        Address entry = function.getEntryPoint();
        ExceptionRootsSupport.RegistryEntry retained = ExceptionRootsSupport.parseRegistry(
                registry == null ? null : registry.getString(entry));
        PalTasksSupport.MapPrimaryIdentity original =
                decision.exceptionTransitionOriginal;
        PalTasksSupport.MapPrimaryIdentity target = decision.exceptionTransitionFinal;
        if (original == null || target == null
                || !"exception_owned".equals(retained.primaryDisposition)
                || retained.entry != execution.entry
                || !retained.isa.equals(execution.decodeRanges.get(0).isa)
                || retained.primaryId == null
                || retained.primaryId.longValue() != original.symbolId
                || retained.primaryId.longValue() != target.symbolId
                || !retained.primarySource.equals(original.source)
                || !retained.primaryNameBlake3.equals(original.nameBlake3)
                || function.getSymbol().getID() != original.symbolId
                || !function.getName().equals(original.name)
                || !PalTasksSupport.primarySource(function.getSymbol().getSource()).equals(
                        original.source)
                || !decision.finalPrimary.equals(target.name)
                || !decision.finalSource.equals(target.source)) {
            fail("fresh exception transition does not exactly bind the registry at " + entry);
        }
    }

    private static String exceptionRegistryDisposition(
            StringPropertyMap registry, Address entry) {
        if (registry == null) {
            return null;
        }
        String value = registry.getString(entry);
        if (value == null) {
            return null;
        }
        return ExceptionRootsSupport.parseRegistry(value).primaryDisposition;
    }

    private static void requirePalRegistryDisposition(StringPropertyMap registry, Address entry,
            String disposition) {
        String actual = palRegistryDisposition(registry, entry);
        if (!disposition.equals(actual)) {
            fail("the registry disposition at " + entry + " is " + actual
                    + " where " + disposition + " is required");
        }
    }

    // ---------------------------------------------------------------------
    // Transactional application
    // ---------------------------------------------------------------------

    @FunctionalInterface
    private interface Undo {
        void run() throws Exception;
    }

    private final class Mutation {
        private final Preflight preflight;
        private final List<Undo> undoJournal = new ArrayList<Undo>();
        private int renames;
        private int comments;

        Mutation(Preflight preflight) {
            this.preflight = preflight;
        }

        private void journal(Undo step) {
            undoJournal.add(step);
        }

        void applyAll() throws Exception {
            // Ghidra mirrors a referenced function's post-rename primary onto
            // its thunks, so every non-thunk rename is applied before any
            // thunk mutation: an authorized independent thunk rename then
            // deterministically overrides the mirror, and a `mirror`
            // decision (rename == false) only ever verifies the mirrored
            // primary at postflight.
            for (Planned plan : preflight.planned) {
                if (!plan.thunk) {
                    applyOne(plan);
                }
            }
            for (Planned plan : preflight.planned) {
                if (plan.thunk) {
                    applyOne(plan);
                }
            }

            // Postflight: complete exception/PAL state still validates, every
            // decision's final primary is current, reserved labels, the owned
            // comment, and the core registry fields are unchanged (the shared
            // validator re-derives them), and only then is the property set.
            preflight.pass2State.validate(
                    ExceptionRootsSupport.Pass2MapPhase.AFTER_MUTATION);
            if (preflight.palPresent) {
                PalTasksSupport.validateAppliedIdentity(currentProgram, preflight.palIdentity);
            }
            else {
                PalTasksSupport.validateAbsent(currentProgram);
            }
            for (Planned plan : preflight.planned) {
                String current = plan.function.getName();
                String source =
                        PalTasksSupport.primarySource(plan.function.getSymbol().getSource());
                // A `mirror` decision covers Ghidra's thunk-name mirroring,
                // which follows the renamed target only while the thunk
                // still carries its auto-derived primary (a custom thunk
                // name — e.g. an applied PAL task label — is left alone).
                // Both deterministic outcomes are accepted: the mirrored
                // final primary or the untouched original; the source must
                // stay the thunk's own either way.
                boolean primaryOk = current.equals(plan.decision.finalPrimary)
                        || ("mirror".equals(plan.decision.action)
                                && current.equals(plan.decision.originalPrimary));
                if (!primaryOk || !source.equals(plan.decision.finalSource)) {
                    fail("verification lost the applied primary at "
                            + plan.function.getEntryPoint());
                }
            }
            preflight.pass2State.verifyRetainedFiles();
            preflight.pass2State.close();
            currentProgram.getOptions(Program.PROGRAM_INFO)
                    .setString(PalTasksSupport.SYMBOL_PASS2_PROPERTY,
                            PalTasksSupport.expectedSymbolPass2Property(preflight.map));
            // Bypass GhidraScript.println (which routes through Msg.info and
            // gets wrapped as "INFO  ApplySymbols.java> ... (GhidraScript)"):
            // emit on stdout verbatim so the Rust driver's parse_pass2_summary
            // can strip_prefix("ApplySymbols:").
            String summary = "ApplySymbols: image=" + preflight.label + " applied " + renames
                    + " names, " + comments + " plate comments over "
                    + preflight.map.executions.size() + " executions";
            System.out.println(summary);
            println(summary);
        }

        private void applyOne(Planned plan) throws Exception {
            Listing listing = currentProgram.getListing();
            Address entry = plan.function.getEntryPoint();
            if (plan.rename) {
                final Function function = plan.function;
                final String priorName = function.getName();
                final SourceType priorSource = function.getSymbol().getSource();
                final String finalName = plan.decision.finalPrimary;
                final SourceType finalSource = plan.decision.finalSource.equals("user_defined")
                        ? SourceType.USER_DEFINED : SourceType.ANALYSIS;
                try {
                    function.setName(finalName, finalSource);
                }
                catch (ghidra.util.exception.DuplicateNameException
                        | ghidra.util.exception.InvalidInputException error) {
                    fail("the pass-2 rename to " + finalName + " failed at " + entry
                            + ": " + error.getMessage());
                }
                journal(() -> function.setName(priorName, priorSource));
                renames++;
            }
            if (plan.exceptionTransition && plan.rename) {
                applyExceptionRegistryTransition(plan);
            }
            else if (plan.palTransition && plan.rename) {
                applyPalRegistryTransition(plan);
            }
            if (!plan.decision.annotations.isEmpty()) {
                StringBuilder text = new StringBuilder();
                for (String annotation : plan.decision.annotations) {
                    if (text.length() > 0) {
                        text.append("\n// ");
                    }
                    text.append(annotation);
                }
                CodeUnit unit = listing.getCodeUnitContaining(entry);
                if (unit == null) {
                    fail("no code unit exists at the annotation entry " + entry);
                }
                final CodeUnit finalUnit = unit;
                final String priorComment = unit.getComment(CommentType.PLATE);
                final String newComment = text.toString();
                finalUnit.setComment(CommentType.PLATE, newComment);
                journal(() -> finalUnit.setComment(CommentType.PLATE, priorComment));
                comments++;
            }
        }

        /**
         * Rewrites only the registry's primary subrecord for the authorized
         * transition: pal_owned -> pass2_owned with the final source and name
         * digest. Reserved labels, the owned comment digest, the function
         * identity, and the manifest binding are carried over verbatim and
         * verified unchanged by the postflight.
         */
        private void applyPalRegistryTransition(Planned plan) {
            Address entry = plan.function.getEntryPoint();
            String value = preflight.palRegistry.getString(entry);
            if (value == null) {
                fail("the registry entry is missing at " + entry);
            }
            PalTasksSupport.RegistryEntry prior = PalTasksSupport.parseRegistry(value);
            if (!"pal_owned".equals(prior.primaryDisposition)) {
                fail("the registry disposition at " + entry + " is "
                        + prior.primaryDisposition + ", not pal_owned");
            }
            Symbol symbol = plan.function.getSymbol();
            if (prior.primarySymbolId != symbol.getID()) {
                fail("the registry primary symbol ID changed during the rename at " + entry);
            }
            String updated = PalTasksSupport.registryValue(new PalTasksSupport.RegistryEntry(
                    prior.manifestBlake3, prior.isa, prior.functionId,
                    prior.functionDisposition, prior.commentBlake3, "pass2_owned",
                    prior.primarySymbolId, plan.decision.finalSource,
                    PalTasksSupport.primaryDigestHex(plan.decision.finalPrimary),
                    prior.labelCount, prior.labelsBlake3));
            final StringPropertyMap registry = preflight.palRegistry;
            final String priorValue = value;
            registry.add(entry, updated);
            journal(() -> registry.add(entry, priorValue));
        }

        private void applyExceptionRegistryTransition(Planned plan) {
            Address entry = plan.function.getEntryPoint();
            String value = preflight.exceptionRegistry.getString(entry);
            if (value == null) {
                fail("the exception registry entry is missing at " + entry);
            }
            ExceptionRootsSupport.RegistryEntry prior =
                    ExceptionRootsSupport.parseRegistry(value);
            if (!"exception_owned".equals(prior.primaryDisposition)) {
                fail("the exception registry disposition at " + entry + " is "
                        + prior.primaryDisposition + ", not exception_owned");
            }
            Symbol symbol = plan.function.getSymbol();
            PalTasksSupport.MapPrimaryIdentity original =
                    plan.decision.exceptionTransitionOriginal;
            PalTasksSupport.MapPrimaryIdentity target =
                    plan.decision.exceptionTransitionFinal;
            if (original == null || target == null
                    || prior.primaryId == null
                    || prior.primaryId.longValue() != symbol.getID()
                    || prior.primaryId.longValue() != original.symbolId
                    || prior.primaryId.longValue() != target.symbolId
                    || !prior.primarySource.equals(original.source)
                    || !prior.primaryNameBlake3.equals(original.nameBlake3)
                    || symbol.getID() != target.symbolId
                    || !plan.function.getName().equals(target.name)
                    || !PalTasksSupport.primarySource(symbol.getSource()).equals(target.source)
                    || !ExceptionRootsSupport.primaryNameDigest(target.name).equals(
                            target.nameBlake3)) {
                fail("the exception primary symbol ID changed during the rename at " + entry);
            }
            String updated = ExceptionRootsSupport.registryValue(
                    new ExceptionRootsSupport.RegistryEntry(
                            prior.manifestBlake3, prior.entry, prior.isa,
                            prior.instructionBlake3, prior.functionId,
                            prior.functionDisposition, "pass2_owned", prior.primaryId,
                            target.source, target.nameBlake3,
                            plan.decision.exceptionTransitionAuthority,
                            original.nameBlake3, prior.labelIds,
                            prior.labelsBlake3));
            final StringPropertyMap registry = preflight.exceptionRegistry;
            final String priorValue = value;
            registry.add(entry, updated);
            journal(() -> registry.add(entry, priorValue));
        }

        void rollback(Throwable original) {
            for (int index = undoJournal.size() - 1; index >= 0; index--) {
                try {
                    undoJournal.get(index).run();
                }
                catch (Throwable cleanupFailure) {
                    suppress(original, cleanupFailure);
                }
            }
            try {
                // Ghidra commits a failed script transaction; abort it so no
                // unreturned partial mutation survives executeNormal's end(true).
                end(false);
            }
            catch (Throwable abortFailure) {
                suppress(original, abortFailure);
            }
            try {
                preflight.pass2State.close();
            }
            catch (Throwable closeFailure) {
                suppress(original, closeFailure);
            }
        }
    }
}
