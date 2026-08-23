// ApplyPalTasks.java - transactional PAL task seeding pre-script.
//
// Arg[0] = canonical import-kit root.
// Arg[1] = expected image label.
// Arg[2] = canonical PAL task-manifest path.
// Arg[3] = canonical scatter load-map path, or "-" when PAL discovery ran
//          without a scatter LoadPlan and the manifest declares a null
//          dependency.
//
// A failed HeadlessScript aborts follow-on analysis/scripts. Complete
// preflight (strict parsing through PalTasksSupport plus memory, storage,
// name/application, and existing function/code/symbol validation) runs
// before any mutation; this script owns no second parser or digest.
// Mutation processes applications by (entry, isa): set TMode over the
// declared entry instruction, run a flow-enabled DisassembleCommand and
// CreateFunctionCmd with incremental code analysis disabled under a
// 30-second per-entry monitor inside one 15-minute phase deadline, use
// authenticated initialized byte-backed memory (every initialized block
// except zero-fill scatter destinations) as the hard address set, charge
// the exact newly-defined address union once against 64 MiB, prove the
// resulting body stays inside authenticated memory without crossing an
// ISA-conflicting entry, then create the reserved-namespace labels, the
// owned repeatable-comment section, and the ownership-registry record,
// verifying each application immediately. On any throwable the mutation
// is undone in reverse order, the script transaction is aborted with
// end(false), cleanup failures are suppressed onto the original, and the
// original is rethrown - no partial PAL state survives. Success runs the
// shared complete postflight, sets the program PAL property, commits,
// and prints exactly one machine-readable summary line:
//
// ApplyPalTasks: {"image":<json>,"status":"ok","identity":<json>,
//   "tasks":<records>,"entries":<applications>,"functions_created":<n>,
//   "functions_existing":<n>,"names_applied":<n>,"names_preserved":<n>,
//   "shared_entries":<n>}
//
// functions_created/functions_existing count this run's mutations; every
// other counter describes the resulting applied state, so reapplying the
// same manifest prints the same summary except those two counters and
// creates no new functions, labels, registry entries, or comments.
//@category PixelModem
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.task.TimeoutTaskMonitor;
import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class ApplyPalTasks extends HeadlessScript {
    private static final long PER_ENTRY_BUDGET_MS = 30_000L;
    private static final long PHASE_BUDGET_MS = 15 * 60_000L;
    private static final long MAX_NEWLY_DEFINED_BYTES = 64L * 1024L * 1024L;

    private static final String ZERO_SCATTER_PREFIX = "SCATTER_ZERO_";

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
        final PalTasksSupport.PalManifest manifest;
        final String identity;
        final boolean reapplication;
        final Map<Address, PalTasksSupport.RegistryEntry> priorRegistry;
        final AddressSet authenticated;
        final Register tMode;

        Preflight(PalTasksSupport.PalManifest manifest, String identity, boolean reapplication,
                Map<Address, PalTasksSupport.RegistryEntry> priorRegistry,
                AddressSet authenticated, Register tMode) {
            this.manifest = manifest;
            this.identity = identity;
            this.reapplication = reapplication;
            this.priorRegistry = priorRegistry;
            this.authenticated = authenticated;
            this.tMode = tMode;
        }
    }

    private Preflight preflight() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) {
            fail("expected exactly four arguments: kit root, image label, task manifest, "
                    + "scatter map or -");
        }
        File kitRoot = new File(args[0]);
        String label = args[1];
        File palFile = new File(args[2]);
        File scatterFile = "-".equals(args[3]) ? null : new File(args[3]);
        PalTasksSupport.PalManifest manifest =
                PalTasksSupport.readPal(kitRoot, label, palFile, scatterFile);
        if (!label.equals(currentProgram.getName())) {
            fail("the expected image label does not match the current program name");
        }
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        if (tMode == null) {
            fail("the language lacks the TMode context register");
        }
        String identity = PalTasksSupport.expectedPalIdentity(manifest);

        String property = currentProgram.getOptions(Program.PROGRAM_INFO)
                .getString(PalTasksSupport.PAL_PROPERTY, null);
        boolean reapplication;
        Map<Address, PalTasksSupport.RegistryEntry> priorRegistry = new HashMap<>();
        if (property == null || PalTasksSupport.NONE_IDENTITY.equals(property)) {
            PalTasksSupport.validateAbsent(currentProgram);
            reapplication = false;
        }
        else if (property.equals(identity)) {
            PalTasksSupport.validateAppliedIdentity(currentProgram, identity);
            reapplication = true;
            StringPropertyMap registry = currentProgram.getUsrPropertyManager()
                    .getStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
            if (registry == null) {
                fail("the ownership registry is missing under a present identity");
            }
            ghidra.program.model.address.AddressIterator entries =
                    registry.getPropertyIterator();
            while (entries.hasNext()) {
                Address registered = entries.next();
                priorRegistry.put(registered,
                        PalTasksSupport.parseRegistry(registry.getString(registered)));
            }
        }
        else {
            fail("stale PAL property: expected " + identity + " or "
                    + PalTasksSupport.NONE_IDENTITY + " but found " + property);
            return null;
        }

        AddressSet authenticated = validateMemory(manifest);
        validateApplications(manifest, authenticated, tMode);
        return new Preflight(manifest, identity, reapplication, priorRegistry, authenticated,
                tMode);
    }

    /**
     * Validates the raw image block, builds the authenticated initialized
     * byte-backed address set (every initialized block except zero-fill
     * scatter destinations), and proves every declared storage span plus
     * the derived slot table region lives in initialized memory.
     */
    private AddressSet validateMemory(PalTasksSupport.PalManifest manifest) {
        Memory memory = currentProgram.getMemory();
        long imageEnd = Math.addExact(manifest.imageBase, manifest.imageSize);
        Address imageStart = toAddr(manifest.imageBase);
        Address imageLast = toAddr(imageEnd - 1);
        MemoryBlock rawBlock = memory.getBlock(imageStart);
        if (rawBlock == null || !rawBlock.getStart().equals(imageStart)
                || !rawBlock.getEnd().equals(imageLast)
                || rawBlock.getSize() != manifest.imageSize || !rawBlock.isInitialized()) {
            fail("the raw image block does not exactly match the declared image range");
        }

        AddressSet authenticated = new AddressSet();
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isInitialized() && !block.getName().startsWith(ZERO_SCATTER_PREFIX)) {
                authenticated.addRange(block.getStart(), block.getEnd());
            }
        }

        List<PalTasksSupport.PalSpan> spans = new ArrayList<>();
        for (PalTasksSupport.PalTask task : manifest.tasks) {
            spans.addAll(task.slotStorage);
            spans.addAll(task.nameStorage);
            spans.addAll(task.entryStorage);
        }
        for (PalTasksSupport.PalSpan span : spans) {
            requireInitialized(span.address, span.size, "task storage");
        }
        long tableBytes = Math.multiplyExact(manifest.taskRecords, manifest.stride);
        long tableEnd = Math.addExact(manifest.slotBase, tableBytes);
        requireInitialized(manifest.slotBase, tableBytes, "slot table");
        requireInitialized(tableEnd, manifest.stride, "terminal slot");
        return authenticated;
    }

    private void requireInitialized(long start, long size, String what) {
        Memory memory = currentProgram.getMemory();
        long end = Math.addExact(start, size);
        Address cursor = toAddr(start);
        Address limit = toAddr(end - 1);
        while (cursor.compareTo(limit) <= 0) {
            MemoryBlock block = memory.getBlock(cursor);
            if (block == null || !block.isInitialized()) {
                fail(what + " escapes initialized memory at " + cursor);
            }
            if (block.getEnd().compareTo(limit) >= 0) {
                return;
            }
            cursor = block.getEnd().add(1);
        }
    }

    /**
     * Validates per-application entry bytes and existing function, code,
     * and symbol state. Rejects entry instructions in the wrong ISA
     * context, functions that contain an entry without beginning there,
     * and desired primaries colliding with unrelated global symbols.
     */
    private void validateApplications(PalTasksSupport.PalManifest manifest,
            AddressSetView authenticated, Register tMode) {
        FunctionManager functions = currentProgram.getFunctionManager();
        for (PalTasksSupport.PalTask task : manifest.tasks) {
            Address entry = toAddr(task.entry);
            long instructionEnd = Math.addExact(task.entry, task.instructionSize);
            if (!authenticated.contains(entry, toAddr(instructionEnd - 1))) {
                fail("the entry instruction escapes authenticated memory at " + entry);
            }
            byte[] instruction = new byte[(int) task.instructionSize];
            try {
                int read = currentProgram.getMemory()
                        .getBytes(entry, instruction, 0, instruction.length);
                if (read != instruction.length) {
                    fail("the entry instruction could not be read at " + entry);
                }
            }
            catch (MemoryAccessException error) {
                fail("the entry instruction could not be read at " + entry);
            }
            if (!PalTasksSupport.blake3Hex(new byte[0], instruction)
                    .equals(task.instructionBlake3)) {
                fail("the entry instruction bytes do not match the manifest at " + entry);
            }
        }
        for (PalTasksSupport.PalApplication application : manifest.applications) {
            Address entry = toAddr(application.entry);
            Instruction instruction = currentProgram.getListing().getInstructionAt(entry);
            if (instruction != null) {
                requireInstructionIsa(instruction, application.isa, entry, tMode);
            }
            if (functions.getFunctionAt(entry) == null
                    && functions.getFunctionContaining(entry) != null) {
                fail("a function contains the task entry but does not begin there: " + entry);
            }
            Function existing = functions.getFunctionAt(entry);
            boolean willApplyPrimary = existing == null
                    || existing.getSymbol().getSource() == SourceType.DEFAULT;
            if (willApplyPrimary) {
                for (Symbol symbol : currentProgram.getSymbolTable()
                        .getSymbols(application.desiredPrimary,
                                currentProgram.getGlobalNamespace())) {
                    if (!symbol.getAddress().equals(entry)) {
                        fail("the desired primary collides with an unrelated symbol: "
                                + application.desiredPrimary);
                    }
                }
            }
        }
    }

    private void requireInstructionIsa(Instruction instruction, String isa, Address entry,
            Register tMode) {
        RegisterValue value = instruction.getRegisterValue(tMode);
        BigInteger mode = value == null || !value.hasValue() ? null : value.getUnsignedValue();
        BigInteger expected = "thumb".equals(isa) ? BigInteger.ONE : BigInteger.ZERO;
        if (mode == null || !mode.equals(expected)) {
            fail("the entry ISA context does not match the declared " + isa + " at " + entry);
        }
    }

    // ---------------------------------------------------------------------
    // Bounded mutation
    // ---------------------------------------------------------------------

    @FunctionalInterface
    private interface Undo {
        void run() throws Exception;
    }

    private final class Mutation {
        private final Preflight preflight;
        private final long phaseDeadline;
        private final List<Undo> undoJournal = new ArrayList<>();
        private final AddressSet chargedAddresses = new AddressSet();
        private long chargedBytes;
        private Namespace reservedNamespace;
        private StringPropertyMap registry;
        private int createdFunctions;
        private int existingFunctions;

        Mutation(Preflight preflight) {
            this.preflight = preflight;
            this.phaseDeadline = Math.addExact(System.currentTimeMillis(), PHASE_BUDGET_MS);
        }

        private void journal(Undo step) {
            undoJournal.add(step);
        }

        void applyAll() throws Exception {
            registry = findOrCreateRegistry();
            int appliedCount = 0;
            for (PalTasksSupport.PalApplication application : preflight.manifest.applications) {
                applyApplication(application, appliedCount);
                appliedCount++;
            }
            currentProgram.getOptions(Program.PROGRAM_INFO)
                    .setString(PalTasksSupport.PAL_PROPERTY, preflight.identity);
            PalTasksSupport.AppliedState state = PalTasksSupport.validateApplied(currentProgram,
                    preflight.manifest, preflight.identity);
            printSummary(state);
        }

        private void applyApplication(PalTasksSupport.PalApplication application,
                int appliedCount) throws Exception {
            Address entry = toAddr(application.entry);
            if (System.currentTimeMillis() >= phaseDeadline) {
                fail("the PAL phase budget was exhausted before " + entry);
            }
            PalTasksSupport.PalTask firstTask =
                    preflight.manifest.tasks.get(application.taskIndices.get(0).intValue());

            // 1. Declare the ISA context over the entry instruction.
            ProgramContext context = currentProgram.getProgramContext();
            BigInteger expected =
                    "thumb".equals(application.isa) ? BigInteger.ONE : BigInteger.ZERO;
            RegisterValue prior = context.getRegisterValue(preflight.tMode, entry);
            if (prior == null || !prior.hasValue()
                    || !expected.equals(prior.getUnsignedValue())) {
                Address rangeEnd =
                        toAddr(Math.addExact(application.entry, firstTask.instructionSize) - 1);
                try {
                    context.setValue(preflight.tMode, entry, rangeEnd, expected);
                }
                catch (ghidra.program.model.listing.ContextChangeException error) {
                    fail("the entry ISA context could not be declared at " + entry);
                }
                final RegisterValue priorFinal = prior;
                final Address rangeEndFinal = rangeEnd;
                journal(() -> {
                    context.remove(entry, rangeEndFinal, preflight.tMode);
                    if (priorFinal != null && priorFinal.hasValue()) {
                        context.setValue(preflight.tMode, entry, rangeEndFinal,
                                priorFinal.getUnsignedValue());
                    }
                });
            }

            // 2. Bounded flow-enabled disassembly over authenticated memory.
            long remainingPhaseMs =
                    Math.subtractExact(phaseDeadline, System.currentTimeMillis());
            TimeoutTaskMonitor entryMonitor = newEntryMonitor(remainingPhaseMs);
            DisassembleCommand disassemble =
                    new DisassembleCommand(entry, preflight.authenticated, true);
            disassemble.enableCodeAnalysis(false);
            boolean disassembleCompleted = disassemble.applyTo(currentProgram, entryMonitor);
            if (entryMonitor.didTimeout()) {
                fail("the per-entry PAL budget was exhausted at " + entry);
            }
            if (!disassembleCompleted) {
                fail("disassembly failed at " + entry + ": " + disassemble.getStatusMsg());
            }
            AddressSetView disassembled = disassemble.getDisassembledAddressSet();
            final AddressSetView toClear = disassembled;
            journal(() -> clearAddressSet(toClear));
            chargeNewlyDefinedAddresses(disassembled);

            // 3. Create the function at the exact entry when absent.
            FunctionManager functions = currentProgram.getFunctionManager();
            Function function = functions.getFunctionAt(entry);
            boolean created = false;
            if (function == null) {
                CreateFunctionCmd create =
                        new CreateFunctionCmd(null, entry, null, SourceType.ANALYSIS);
                boolean createdOk = create.applyTo(currentProgram, entryMonitor);
                if (entryMonitor.didTimeout()) {
                    fail("the per-entry PAL budget was exhausted at " + entry);
                }
                if (!createdOk) {
                    fail("function creation failed at " + entry + ": " + create.getStatusMsg());
                }
                function = functions.getFunctionAt(entry);
                created = true;
                journal(() -> currentProgram.getFunctionManager().removeFunction(entry));
            }
            if (function == null) {
                fail("no function exists at the task entry " + entry);
            }
            if (!function.getEntryPoint().equals(entry)) {
                fail("the function does not begin at the task entry " + entry);
            }
            AddressSetView body = function.getBody();
            if (!preflight.authenticated.contains(body)) {
                fail("the function body leaves authenticated memory at " + entry);
            }
            for (PalTasksSupport.PalApplication other : preflight.manifest.applications) {
                if (other.entry == application.entry && other.isa.equals(application.isa)) {
                    continue;
                }
                if (!other.isa.equals(application.isa)
                        && body.contains(toAddr(other.entry))) {
                    fail("the function body at " + entry
                            + " crosses the ISA-conflicting entry " + toAddr(other.entry));
                }
            }
            if (created) {
                createdFunctions++;
            }
            else {
                existingFunctions++;
            }

            // 4. Global primary: apply when default or newly created,
            //    otherwise preserve the meaningful existing name. This must
            //    precede label creation: a reserved-namespace label created
            //    over a still-dynamic function symbol would absorb that
            //    symbol into the namespace (Ghidra converts dynamic symbols
            //    in place), so the primary has to be made concrete first.
            Symbol primary = function.getSymbol();
            String functionDisposition;
            String primaryDisposition;
            if (preflight.reapplication) {
                PalTasksSupport.RegistryEntry priorEntry = preflight.priorRegistry.get(entry);
                if (priorEntry == null) {
                    fail("the prior registry entry is missing at " + entry);
                }
                functionDisposition = priorEntry.functionDisposition;
                primaryDisposition = priorEntry.primaryDisposition;
            }
            else {
                functionDisposition = created ? "created" : "preexisting";
                if (created || primary.getSource() == SourceType.DEFAULT) {
                    final String priorName = primary.getName();
                    final SourceType priorSource = primary.getSource();
                    final Function functionFinal = function;
                    try {
                        function.setName(application.desiredPrimary, SourceType.ANALYSIS);
                    }
                    catch (ghidra.util.exception.DuplicateNameException
                            | ghidra.util.exception.InvalidInputException error) {
                        fail("the desired primary could not be applied: "
                                + application.desiredPrimary);
                    }
                    journal(() -> functionFinal.setName(priorName, priorSource));
                    primaryDisposition = "pal_owned";
                }
                else {
                    primaryDisposition = "preserved";
                }
            }

            // 5. Reserved-namespace task labels.
            ensureReservedNamespace();
            for (PalTasksSupport.PalLabel label : application.labels) {
                Symbol symbol = currentProgram.getSymbolTable()
                        .getSymbol(label.label, entry, reservedNamespace);
                if (symbol == null) {
                    try {
                        symbol = currentProgram.getSymbolTable().createLabel(entry, label.label,
                                reservedNamespace, SourceType.ANALYSIS);
                    }
                    catch (ghidra.util.exception.InvalidInputException error) {
                        fail("the reserved label could not be created: " + label.label);
                    }
                    final Symbol createdSymbol = symbol;
                    journal(createdSymbol::delete);
                }
                else if (symbol.getSource() != SourceType.ANALYSIS) {
                    fail("an existing reserved label does not carry ANALYSIS source: "
                            + label.label);
                }
            }

            // 6. Owned repeatable-comment section, preserving surroundings.
            List<PalTasksSupport.PalTask> attached = new ArrayList<>();
            for (long index : application.taskIndices) {
                attached.add(preflight.manifest.tasks.get((int) index));
            }
            String section = PalTasksSupport.ownedCommentSection(
                    preflight.manifest.manifestBlake3, attached);
            String currentComment = function.getRepeatableComment();
            String newComment = mergeOwnedSection(currentComment, section, entry);
            if (!newComment.equals(currentComment)) {
                final Function functionFinal = function;
                final String priorComment = currentComment;
                function.setRepeatableComment(newComment);
                journal(() -> functionFinal.setRepeatableComment(priorComment));
            }

            // 7. Ownership-registry record.
            List<PalTasksSupport.LabelEntry> labelEntries = new ArrayList<>();
            for (PalTasksSupport.PalLabel label : application.labels) {
                Symbol symbol = currentProgram.getSymbolTable()
                        .getSymbol(label.label, entry, reservedNamespace);
                if (symbol == null) {
                    fail("the applied reserved label is missing: " + label.label);
                }
                labelEntries.add(
                        new PalTasksSupport.LabelEntry(symbol.getID(), symbol.getName()));
            }
            primary = function.getSymbol();
            String value = PalTasksSupport.registryValue(new PalTasksSupport.RegistryEntry(
                    preflight.manifest.manifestBlake3, application.isa, primary.getID(),
                    functionDisposition, PalTasksSupport.commentDigestHex(section),
                    primaryDisposition, primary.getID(),
                    PalTasksSupport.primarySource(primary.getSource()),
                    PalTasksSupport.primaryDigestHex(primary.getName()), labelEntries.size(),
                    PalTasksSupport.labelsDigestHex(labelEntries)));
            registry.add(entry, value);
            journal(() -> registry.remove(entry));

            // 8. Immediate per-application verification.
            verifyApplication(application, function, section);
        }

        private String mergeOwnedSection(String currentComment, String section, Address entry) {
            if (currentComment == null || currentComment.isEmpty()) {
                return section;
            }
            String existingSection = PalTasksSupport.findOwnedSection(currentComment);
            if (existingSection == null) {
                if (currentComment.contains(PalTasksSupport.COMMENT_CLOSE_MARKER)) {
                    fail("a stray owned-comment closing marker exists at " + entry);
                }
                return currentComment + "\n" + section;
            }
            int open = currentComment.indexOf(PalTasksSupport.COMMENT_OPEN_MARKER);
            int closeEnd = open + existingSection.length();
            return currentComment.substring(0, open) + section
                    + currentComment.substring(closeEnd);
        }

        private void ensureReservedNamespace() throws Exception {
            if (reservedNamespace != null) {
                return;
            }
            SymbolTable symbols = currentProgram.getSymbolTable();
            Namespace existing = symbols.getNamespace(PalTasksSupport.RESERVED_NAMESPACE,
                    currentProgram.getGlobalNamespace());
            if (existing != null) {
                reservedNamespace = existing;
                return;
            }
            try {
                reservedNamespace = symbols.createNameSpace(currentProgram.getGlobalNamespace(),
                        PalTasksSupport.RESERVED_NAMESPACE, SourceType.ANALYSIS);
            }
            catch (ghidra.util.exception.DuplicateNameException
                    | ghidra.util.exception.InvalidInputException error) {
                fail("the reserved namespace could not be created");
            }
            final Namespace created = reservedNamespace;
            journal(() -> {
                Symbol namespaceSymbol = created.getSymbol();
                if (namespaceSymbol != null) {
                    namespaceSymbol.delete();
                }
            });
        }

        private TimeoutTaskMonitor newEntryMonitor(long remainingPhaseMs) {
            long budget = Math.min(PER_ENTRY_BUDGET_MS, Math.max(remainingPhaseMs, 1L));
            return TimeoutTaskMonitor.timeoutIn(budget, TimeUnit.MILLISECONDS, monitor);
        }

        private void chargeNewlyDefinedAddresses(AddressSetView disassembled) {
            AddressSetView newly = chargedAddresses.isEmpty() ? disassembled
                    : disassembled.subtract(chargedAddresses);
            chargedAddresses.add(newly);
            chargedBytes = Math.addExact(chargedBytes, newly.getNumAddresses());
            if (chargedBytes > MAX_NEWLY_DEFINED_BYTES) {
                fail("the newly-defined address budget was exhausted");
            }
        }

        private void clearAddressSet(AddressSetView set) throws Exception {
            for (AddressRange range : set) {
                currentProgram.getListing().clearCodeUnits(range.getMinAddress(),
                        range.getMaxAddress(), false);
            }
        }

        private StringPropertyMap findOrCreateRegistry() throws Exception {
            StringPropertyMap existing = currentProgram.getUsrPropertyManager()
                    .getStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
            if (existing != null) {
                return existing;
            }
            try {
                return currentProgram.getUsrPropertyManager()
                        .createStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
            }
            catch (Exception duplicate) {
                fail("the ownership registry could not be created");
                return null;
            }
        }

        private void verifyApplication(PalTasksSupport.PalApplication application,
                Function function, String section) throws Exception {
            Address entry = toAddr(application.entry);
            if (!function.getEntryPoint().equals(entry)) {
                fail("verification lost the function entry at " + entry);
            }
            Instruction instruction = currentProgram.getListing().getInstructionAt(entry);
            if (instruction == null) {
                fail("no instruction exists at the task entry after disassembly: " + entry);
            }
            requireInstructionIsa(instruction, application.isa, entry, preflight.tMode);

            String stored = registry.getString(entry);
            if (stored == null) {
                fail("the registry entry is missing at " + entry);
            }
            PalTasksSupport.RegistryEntry parsed = PalTasksSupport.parseRegistry(stored);
            Symbol primary = function.getSymbol();
            if (parsed.functionId != primary.getID()
                    || parsed.primarySymbolId != primary.getID()
                    || !parsed.primarySource
                            .equals(PalTasksSupport.primarySource(primary.getSource()))
                    || !parsed.primaryNameBlake3
                            .equals(PalTasksSupport.primaryDigestHex(primary.getName()))) {
                fail("the registry binding does not match the current primary at " + entry);
            }
            if ("pal_owned".equals(parsed.primaryDisposition)
                    && !primary.getName().equals(application.desiredPrimary)) {
                fail("a pal_owned primary does not carry the desired task name at " + entry);
            }

            List<PalTasksSupport.LabelEntry> actual = new ArrayList<>();
            Set<String> leaves = new HashSet<>();
            ghidra.program.model.symbol.SymbolIterator symbols =
                    currentProgram.getSymbolTable().getSymbolsAsIterator(entry);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                if (symbol.getParentNamespace().equals(reservedNamespace)) {
                    if (symbol.getSource() != SourceType.ANALYSIS) {
                        fail("a reserved label does not carry ANALYSIS source at " + entry);
                    }
                    actual.add(new PalTasksSupport.LabelEntry(symbol.getID(),
                            symbol.getName()));
                    leaves.add(symbol.getName());
                }
            }
            Set<String> expectedLeaves = new HashSet<>();
            for (PalTasksSupport.PalLabel label : application.labels) {
                expectedLeaves.add(label.label);
            }
            if (!leaves.equals(expectedLeaves)
                    || actual.size() != parsed.labelCount
                    || !parsed.labelsBlake3
                            .equals(PalTasksSupport.labelsDigestHex(actual))) {
                fail("the reserved label set does not match the registry at " + entry);
            }

            String comment = function.getRepeatableComment();
            String found = PalTasksSupport.findOwnedSection(comment);
            if (found == null || !found.equals(section) || !parsed.commentBlake3
                    .equals(PalTasksSupport.commentDigestHex(found))) {
                fail("the owned comment section is not exact at " + entry);
            }
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
        }

        private void printSummary(PalTasksSupport.AppliedState state) {
            long sharedEntries = 0;
            for (PalTasksSupport.PalApplication application : preflight.manifest.applications) {
                if (application.taskIndices.size() > 1) {
                    sharedEntries++;
                }
            }
            // Bypass GhidraScript.println (which routes through Msg.info and
            // gets wrapped as "INFO  ApplyPalTasks.java> ... (GhidraScript)")
            // for the machine line: emit on stdout verbatim so the Rust
            // driver's parse_apply_pal_tasks_summary can
            // strip_prefix("ApplyPalTasks: "); println keeps the human log.
            String summary = "ApplyPalTasks: {\"image\":\"" + preflight.manifest.imageLabel
                    + "\",\"status\":\"ok\",\"identity\":\"" + preflight.identity
                    + "\",\"tasks\":" + preflight.manifest.taskRecords
                    + ",\"entries\":" + state.applications
                    + ",\"functions_created\":" + createdFunctions
                    + ",\"functions_existing\":" + existingFunctions
                    + ",\"names_applied\":" + state.palOwnedPrimaries
                    + ",\"names_preserved\":" + state.preservedPrimaries
                    + ",\"shared_entries\":" + sharedEntries + "}";
            System.out.println(summary);
            println(summary);
        }
    }
}
