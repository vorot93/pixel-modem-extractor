// ApplyExceptionRoots.java - strict pass-1 architectural exception-root
// seeding. The complete manifest and current program are classified before
// the script-owned transaction. Any failure runs the reverse journal and
// aborts that transaction; no partial prefix is authoritative.
//@category PixelModem
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ApplyExceptionRoots extends HeadlessScript {
    private static final int MAX_SUMMARY_BYTES = 256 * 1024;
    @FunctionalInterface
    private interface Undo {
        void run() throws Exception;
    }

    private static final class Counts {
        int functionsCreated;
        int functionsReapplied;
        int functionsExisting;
        int namesApplied;
        int namesReapplied;
        int namesPreserved;
        int namesNotRequested;
    }

    private static final class ContextRun {
        final Address start;
        Address end;
        final RegisterValue value;

        ContextRun(Address start, Address end, RegisterValue value) {
            this.start = start;
            this.end = end;
            this.value = value;
        }
    }

    private final List<Undo> undo = new ArrayList<Undo>();
    private Namespace reservedNamespace;
    private StringPropertyMap registry;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5) {
            fail("expected kit root, image label, manifest, scatter map or '-', and identity");
        }
        File kitRoot = new File(args[0]);
        String image = args[1];
        File manifest = new File(args[2]);
        String scatter = args[3];
        String expectedIdentity = args[4];

        ExceptionRootsSupport.Validated validated = null;
        boolean transactionEnded = false;
        try {
            validated = ExceptionRootsSupport.preflight(currentProgram, monitor, kitRoot, image,
                    manifest, scatter, expectedIdentity);
            Counts counts = new Counts();
            applyAll(validated, counts);
            ExceptionRootsSupport.AppliedState state = ExceptionRootsSupport.validateApplied(
                    currentProgram, validated.manifest, validated.identity);
            ExceptionRootsSupport.validatePass2Lineage(currentProgram);
            validated.verifyRetainedFiles();
            requireConservation(validated, counts, state);
            String summary = summary(validated, counts);

            end(true);
            transactionEnded = true;
            validated.close();
            validated = null;
            System.out.println("ApplyExceptionRoots: " + summary);
        }
        catch (Throwable error) {
            if (!transactionEnded) {
                rollback(error);
                try {
                    end(false);
                }
                catch (Throwable abortFailure) {
                    suppress(error, abortFailure);
                }
            }
            close(validated, error);
            rethrow(error);
        }
    }

    private void applyAll(ExceptionRootsSupport.Validated validated, Counts counts)
            throws Exception {
        registry = findOrCreateRegistry();
        for (ExceptionRootsSupport.Plan plan : validated.plans) {
            applyOne(validated, plan, counts);
        }
    }

    private void applyOne(ExceptionRootsSupport.Validated validated,
            ExceptionRootsSupport.Plan plan, Counts counts) throws Exception {
        Address entry = toAddr(plan.application.entry);
        Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
        boolean created = false;

        if (plan.prior == null && function == null) {
            Address end = toAddr(Math.addExact(
                    plan.root.entry, plan.root.instructionSize) - 1);
            AddressSet instructionRange = new AddressSet(entry, end);
            if (currentProgram.getListing().getInstructionAt(entry) == null) {
                declareContext(validated, plan.root, entry);
                DisassembleCommand disassemble =
                        new DisassembleCommand(entry, instructionRange, false);
                disassemble.enableCodeAnalysis(false);
                journal(() -> clear(instructionRange));
                if (!disassemble.applyTo(currentProgram, monitor)) {
                    fail("exception-root disassembly failed at " + entry + ": "
                            + disassemble.getStatusMsg());
                }
                AddressSetView disassembled = disassemble.getDisassembledAddressSet();
                if (!disassembled.contains(instructionRange)
                        || disassembled.getNumAddresses() != instructionRange.getNumAddresses()) {
                    fail("exception-root disassembly did not define exactly one instruction at "
                            + entry);
                }
            }
            CreateFunctionCmd create = new CreateFunctionCmd(
                    null, entry, instructionRange, SourceType.ANALYSIS);
            journal(() -> {
                Function partial = currentProgram.getFunctionManager().getFunctionAt(entry);
                if (partial != null
                        && !currentProgram.getFunctionManager().removeFunction(entry)) {
                    fail("exception-root partial function could not be rolled back at " + entry);
                }
            });
            if (!create.applyTo(currentProgram, monitor)) {
                fail("exception-root function creation failed at " + entry + ": "
                        + create.getStatusMsg());
            }
            function = currentProgram.getFunctionManager().getFunctionAt(entry);
            if (function == null || !function.getBody().equals(instructionRange)) {
                fail("exception-root function was not created with the exact entry body at "
                        + entry);
            }
            created = true;
        }
        if (function == null) fail("exception-root function is missing at " + entry);
        Instruction instruction = currentProgram.getListing().getInstructionAt(entry);
        if (instruction == null) fail("exception-root instruction is missing at " + entry);
        ExceptionRootsSupport.requireInstruction(
                instruction, plan.root, validated.tMode);

        String functionDisposition;
        String primaryDisposition;
        if (plan.prior != null) {
            functionDisposition = plan.prior.functionDisposition;
            primaryDisposition = plan.prior.primaryDisposition;
            if ("created".equals(functionDisposition)) counts.functionsReapplied++;
            else counts.functionsExisting++;
            if ("exception_owned".equals(primaryDisposition)
                    || "pass2_owned".equals(primaryDisposition)) counts.namesReapplied++;
            else if ("preserved".equals(primaryDisposition)) counts.namesPreserved++;
            else counts.namesNotRequested++;
        }
        else {
            functionDisposition = created ? "created" : "foreign";
            if (created) counts.functionsCreated++;
            else counts.functionsExisting++;
            primaryDisposition = plan.freshPrimaryDisposition;
            if ("exception_owned".equals(primaryDisposition)) {
                Symbol prior = function.getSymbol();
                String priorName = prior.getName();
                SourceType priorSource = prior.getSource();
                Function applied = function;
                journal(() -> applied.setName(priorName, priorSource));
                try {
                    function.setName(plan.application.desiredPrimary, SourceType.ANALYSIS);
                }
                catch (ghidra.util.exception.DuplicateNameException
                        | ghidra.util.exception.InvalidInputException error) {
                    fail("exception primary could not be applied at " + entry);
                }
                counts.namesApplied++;
            }
            else if ("preserved".equals(primaryDisposition)) {
                counts.namesPreserved++;
            }
            else {
                counts.namesNotRequested++;
            }
        }

        // Ghidra converts a DEFAULT function symbol in place when the first
        // higher-source label is added at its entry. Make it concrete only
        // while creating role labels, then restore the exact dynamic primary.
        String deferredDefaultName = null;
        if (plan.prior == null && "not_requested".equals(primaryDisposition)
                && function.getSymbol().getSource() == SourceType.DEFAULT) {
            deferredDefaultName = function.getName();
            Function guarded = function;
            String priorName = deferredDefaultName;
            journal(() -> guarded.setName(priorName, SourceType.DEFAULT));
            function.setName(ExceptionRootsSupport.primaryGuardName(
                    plan.application.entry), SourceType.ANALYSIS);
        }
        ensureNamespace();
        if (plan.prior == null) {
            for (String leaf : plan.application.roleLabels) {
                journal(() -> {
                    Symbol partial = currentProgram.getSymbolTable().getSymbol(
                            leaf, entry, reservedNamespace);
                    if (partial != null && !partial.delete()) {
                        fail("exception role label could not be rolled back: " + leaf);
                    }
                });
                Symbol symbol = currentProgram.getSymbolTable().createLabel(
                        entry, leaf, reservedNamespace, SourceType.ANALYSIS);
                if (symbol == null) fail("exception role label was not created: " + leaf);
            }
        }
        if (deferredDefaultName != null) {
            function.setName(deferredDefaultName, SourceType.DEFAULT);
        }

        List<ExceptionRootsSupport.LabelEntry> labels = ExceptionRootsSupport.labelsAt(
                currentProgram, reservedNamespace, entry);
        if (labels.size() != plan.application.roleLabels.size()) {
            fail("exception role-label count changed at " + entry);
        }
        List<Long> labelIds = new ArrayList<Long>();
        for (ExceptionRootsSupport.LabelEntry label : labels) labelIds.add(label.id);
        Symbol primary = function.getSymbol();
        Long primaryId = primary.getID();
        String primarySource = PmeScriptSupport.primarySource(primary.getSource());
        String primaryHash = PmeScriptSupport.blake3Hex(PmeScriptSupport.boundedUtf8(
                primary.getName(), ExceptionRootsSupport.MAX_SYMBOL_UTF8_BYTES,
                "exception primary"));
        ExceptionRootsSupport.RegistryEntry ownership =
                new ExceptionRootsSupport.RegistryEntry(
                        validated.manifest.manifestBlake3, plan.application.entry,
                        plan.application.isa, plan.root.instructionBlake3, function.getID(),
                        functionDisposition, primaryDisposition, primaryId, primarySource,
                        primaryHash,
                        plan.prior == null ? null : plan.prior.transitionAuthority,
                        plan.prior == null ? null : plan.prior.transitionOriginalPrimaryBlake3,
                        Collections.unmodifiableList(labelIds),
                        ExceptionRootsSupport.labelsDigest(labels));
        String priorValue = registry.getString(entry);
        String value = ExceptionRootsSupport.registryValue(ownership);
        if (plan.prior == null) {
            journal(() -> registry.remove(entry));
            registry.add(entry, value);
        }
        else if (!value.equals(priorValue)) {
            fail("exception-root replay would change ownership at " + entry);
        }
    }

    private void declareContext(ExceptionRootsSupport.Validated validated,
            ExceptionRootsSupport.Root root, Address entry) throws Exception {
        ProgramContext context = currentProgram.getProgramContext();
        Address end = toAddr(Math.addExact(root.entry, root.instructionSize) - 1);
        BigInteger wanted = "thumb".equals(root.isa) ? BigInteger.ONE : BigInteger.ZERO;
        List<ContextRun> prior = snapshotContext(context, validated.tMode, entry, end);
        journal(() -> restoreContext(context, validated.tMode, entry, end, prior));
        context.setRegisterValue(entry, end, new RegisterValue(validated.tMode, wanted));
    }

    private List<ContextRun> snapshotContext(ProgramContext context,
            ghidra.program.model.lang.Register register, Address start, Address end) {
        List<ContextRun> runs = new ArrayList<ContextRun>();
        Address cursor = start;
        while (true) {
            RegisterValue value = context.getNonDefaultValue(register, cursor);
            if (value != null) {
                ContextRun prior = runs.isEmpty() ? null : runs.get(runs.size() - 1);
                if (prior != null && prior.end.next().equals(cursor)
                        && prior.value.equals(value)) {
                    prior.end = cursor;
                }
                else {
                    runs.add(new ContextRun(cursor, cursor, value));
                }
            }
            if (cursor.equals(end)) break;
            cursor = cursor.next();
            if (cursor == null) fail("exception-root context snapshot wrapped the address space");
        }
        return Collections.unmodifiableList(runs);
    }

    private void restoreContext(ProgramContext context,
            ghidra.program.model.lang.Register register, Address start, Address end,
            List<ContextRun> runs) throws Exception {
        context.remove(start, end, register);
        for (ContextRun run : runs) {
            context.setRegisterValue(run.start, run.end, run.value);
        }
    }

    private StringPropertyMap findOrCreateRegistry() throws Exception {
        StringPropertyMap existing = ExceptionRootsSupport.currentRegistry(currentProgram);
        if (existing != null) return existing;
        PropertyMapManager manager = currentProgram.getUsrPropertyManager();
        try {
            journal(() -> {
                if (ExceptionRootsSupport.currentRegistry(currentProgram) != null
                        && !manager.removePropertyMap(ExceptionRootsSupport.OWNERSHIP_MAP)) {
                    fail("exception-root ownership registry could not be rolled back");
                }
            });
            StringPropertyMap created =
                    manager.createStringPropertyMap(ExceptionRootsSupport.OWNERSHIP_MAP);
            return created;
        }
        catch (Exception error) {
            fail("exception-root ownership registry could not be created");
            return null;
        }
    }

    private void ensureNamespace() throws Exception {
        if (reservedNamespace != null) return;
        Namespace existing = ExceptionRootsSupport.currentNamespace(currentProgram);
        if (existing != null) {
            reservedNamespace = existing;
            return;
        }
        SymbolTable symbols = currentProgram.getSymbolTable();
        journal(() -> {
            Namespace partial = ExceptionRootsSupport.currentNamespace(currentProgram);
            if (partial != null) {
                Symbol symbol = partial.getSymbol();
                if (symbol != null && !symbol.delete()) {
                    fail("exception-root namespace could not be rolled back");
                }
            }
        });
        try {
            reservedNamespace = symbols.createNameSpace(
                    currentProgram.getGlobalNamespace(),
                    ExceptionRootsSupport.RESERVED_NAMESPACE, SourceType.ANALYSIS);
        }
        catch (ghidra.util.exception.DuplicateNameException
                | ghidra.util.exception.InvalidInputException error) {
            fail("exception-root reserved namespace could not be created");
        }
    }

    private void clear(AddressSetView addresses) throws Exception {
        for (AddressRange range : addresses) {
            currentProgram.getListing().clearCodeUnits(
                    range.getMinAddress(), range.getMaxAddress(), false);
        }
    }

    private void journal(Undo action) {
        undo.add(action);
    }

    private void rollback(Throwable primary) {
        for (int index = undo.size() - 1; index >= 0; index--) {
            try {
                undo.get(index).run();
            }
            catch (Throwable rollbackFailure) {
                suppress(primary, rollbackFailure);
            }
        }
    }

    private void close(AutoCloseable closeable, Throwable primary) {
        if (closeable == null) return;
        try {
            closeable.close();
        }
        catch (Throwable closeFailure) {
            suppress(primary, closeFailure);
        }
    }

    private void suppress(Throwable primary, Throwable cleanupFailure) {
        if (primary == cleanupFailure) return;
        try {
            primary.addSuppressed(cleanupFailure);
        }
        catch (Throwable ignored) {
            // Preserve the original terminal failure.
        }
    }

    private void rethrow(Throwable failure) throws Exception {
        if (failure instanceof Exception) throw (Exception) failure;
        if (failure instanceof Error) throw (Error) failure;
        throw new Exception(failure);
    }

    private void requireConservation(ExceptionRootsSupport.Validated validated,
            Counts counts, ExceptionRootsSupport.AppliedState state) {
        int entries = validated.manifest.applications.size();
        int functions = Math.addExact(counts.functionsCreated,
                Math.addExact(counts.functionsReapplied, counts.functionsExisting));
        int names = Math.addExact(counts.namesApplied,
                Math.addExact(counts.namesReapplied,
                        Math.addExact(counts.namesPreserved, counts.namesNotRequested)));
        if (functions != entries || names != entries
                || state.sharedEntries > counts.namesNotRequested) {
            fail("exception-root terminal counts do not conserve entries");
        }
    }

    private String summary(ExceptionRootsSupport.Validated validated, Counts counts) {
        int roles = Math.multiplyExact(
                validated.manifest.tables.size(), ExceptionRootsSupport.SLOTS_PER_TABLE);
        int shared = 0;
        for (ExceptionRootsSupport.Application application :
                validated.manifest.applications) {
            if (ExceptionRootsSupport.isSharedEntry(application)) shared++;
        }
        String symbolPass2 = currentProgram.getOptions(Program.PROGRAM_INFO)
                .getString(PalTasksSupport.SYMBOL_PASS2_PROPERTY, null);
        PalTasksSupport.validateSymbolPass2Property(symbolPass2);
        int functionsCreated = 0;
        int functionsReapplied = 0;
        int functionsExisting = 0;
        int namesApplied = 0;
        int namesReapplied = 0;
        int namesPreserved = 0;
        int namesNotRequested = 0;
        StringBuilder applications = new StringBuilder("[");
        long previousEntry = -1;
        String previousIsa = null;
        for (int index = 0; index < validated.plans.size(); index++) {
            ExceptionRootsSupport.Plan plan = validated.plans.get(index);
            if (previousEntry > plan.application.entry
                    || (previousEntry == plan.application.entry
                            && previousIsa.compareTo(plan.application.isa) >= 0)) {
                fail("exception application summary order is not strict");
            }
            previousEntry = plan.application.entry;
            previousIsa = plan.application.isa;
            Address entry = toAddr(plan.application.entry);
            Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
            if (function == null) fail("exception summary function is missing at " + entry);
            ExceptionRootsSupport.RegistryEntry retained = ExceptionRootsSupport.parseRegistry(
                    registry.getString(entry));
            String functionResult;
            if (plan.prior == null && "created".equals(retained.functionDisposition)) {
                functionResult = "created";
                functionsCreated++;
            }
            else if (plan.prior != null && "created".equals(retained.functionDisposition)) {
                functionResult = "reapplied";
                functionsReapplied++;
            }
            else {
                functionResult = "existing";
                functionsExisting++;
            }
            String nameResult;
            switch (retained.primaryDisposition) {
                case "exception_owned":
                    if (plan.prior == null) {
                        nameResult = "applied";
                        namesApplied++;
                    }
                    else {
                        nameResult = "reapplied";
                        namesReapplied++;
                    }
                    break;
                case "pass2_owned":
                    nameResult = "reapplied";
                    namesReapplied++;
                    break;
                case "preserved":
                    nameResult = "preserved";
                    namesPreserved++;
                    break;
                case "not_requested":
                    nameResult = "not_requested";
                    namesNotRequested++;
                    break;
                default:
                    fail("exception summary carries an unknown primary disposition");
                    return null;
            }
            Symbol current = function.getSymbol();
            String currentName = current.getName();
            String currentSource = PmeScriptSupport.primarySource(current.getSource());
            String currentDigest = ExceptionRootsSupport.primaryNameDigest(currentName);
            if (retained.primaryId == null || retained.primaryId.longValue() != current.getID()
                    || !retained.primarySource.equals(currentSource)
                    || !retained.primaryNameBlake3.equals(currentDigest)) {
                fail("exception summary primary identity is stale at " + entry);
            }
            if (index != 0) applications.append(',');
            applications.append("{\"entry\":")
                    .append(PmeScriptSupport.jsonString(
                            ExceptionRootsSupport.canonicalAddress(plan.application.entry)))
                    .append(",\"isa\":")
                    .append(PmeScriptSupport.jsonString(plan.application.isa))
                    .append(",\"function_result\":")
                    .append(PmeScriptSupport.jsonString(functionResult))
                    .append(",\"name_result\":")
                    .append(PmeScriptSupport.jsonString(nameResult))
                    .append(",\"shared\":")
                    .append(ExceptionRootsSupport.isSharedEntry(plan.application))
                    .append(",\"primary_disposition\":")
                    .append(PmeScriptSupport.jsonString(retained.primaryDisposition))
                    .append(",\"current_primary\":")
                    .append(primaryIdentity(current.getID(), currentSource, currentName,
                            currentDigest))
                    .append(",\"transition\":");
            if ("pass2_owned".equals(retained.primaryDisposition)) {
                if (plan.application.desiredPrimary == null
                        || retained.transitionAuthority == null
                        || !ExceptionRootsSupport.primaryNameDigest(
                                plan.application.desiredPrimary).equals(
                                        retained.transitionOriginalPrimaryBlake3)) {
                    fail("exception summary transition is incomplete at " + entry);
                }
                applications.append("{\"authority\":")
                        .append(PmeScriptSupport.jsonString(retained.transitionAuthority))
                        .append(",\"original_primary\":")
                        .append(primaryIdentity(current.getID(), "analysis",
                                plan.application.desiredPrimary,
                                retained.transitionOriginalPrimaryBlake3))
                        .append('}');
            }
            else {
                applications.append("null");
            }
            applications.append('}');
        }
        applications.append(']');
        if (functionsCreated != counts.functionsCreated
                || functionsReapplied != counts.functionsReapplied
                || functionsExisting != counts.functionsExisting
                || namesApplied != counts.namesApplied
                || namesReapplied != counts.namesReapplied
                || namesPreserved != counts.namesPreserved
                || namesNotRequested != counts.namesNotRequested) {
            fail("exception summary rows do not rederive the aggregate counts");
        }
        String summary = "{\"image\":" + PmeScriptSupport.jsonString(
                validated.manifest.image.label)
                + ",\"status\":\"ok\",\"identity\":"
                + PmeScriptSupport.jsonString(validated.identity)
                + ",\"symbol_pass2\":"
                + (symbolPass2 == null ? "null" : PmeScriptSupport.jsonString(symbolPass2))
                + ",\"tables\":" + validated.manifest.tables.size()
                + ",\"roles\":" + roles
                + ",\"entries\":" + validated.manifest.applications.size()
                + ",\"functions_created\":" + counts.functionsCreated
                + ",\"functions_reapplied\":" + counts.functionsReapplied
                + ",\"functions_existing\":" + counts.functionsExisting
                + ",\"names_applied\":" + counts.namesApplied
                + ",\"names_reapplied\":" + counts.namesReapplied
                + ",\"names_preserved\":" + counts.namesPreserved
                + ",\"names_not_requested\":" + counts.namesNotRequested
                + ",\"shared_entries\":" + shared
                + ",\"applications\":" + applications + "}";
        if (summary.getBytes(StandardCharsets.UTF_8).length > MAX_SUMMARY_BYTES) {
            fail("ApplyExceptionRoots summary exceeds the 256 KiB limit");
        }
        return summary;
    }

    private String primaryIdentity(long symbolId, String source, String name, String digest) {
        PmeScriptSupport.boundedUtf8(name, ExceptionRootsSupport.MAX_SYMBOL_UTF8_BYTES,
                "exception summary primary");
        return "{\"symbol_id\":" + symbolId
                + ",\"source\":" + PmeScriptSupport.jsonString(source)
                + ",\"name\":" + PmeScriptSupport.jsonString(name)
                + ",\"name_blake3\":" + PmeScriptSupport.jsonString(digest) + "}";
    }

    private void fail(String message) {
        throw new ExceptionRootsSupport.RootError(message);
    }
}
