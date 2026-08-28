// ApplyExceptionRoots.java - strict pass-1 architectural exception-root
// seeding. The complete manifest and current program are classified before
// one explicit transaction. Any failure runs the reverse journal and aborts
// the transaction; no partial prefix is authoritative.
//@category PixelModem
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ApplyExceptionRoots extends GhidraScript {
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

        String summary;
        try (ExceptionRootsSupport.Validated validated = ExceptionRootsSupport.preflight(
                currentProgram, monitor, kitRoot, image, manifest, scatter,
                expectedIdentity)) {
            Counts counts = new Counts();
            int transaction = currentProgram.startTransaction("Apply exception roots");
            boolean commit = false;
            Throwable failure = null;
            try {
                applyAll(validated, counts);
                validated.verifyRetainedFiles();
                ExceptionRootsSupport.AppliedState state =
                        ExceptionRootsSupport.validateApplied(
                                currentProgram, validated.manifest, validated.identity);
                requireConservation(validated, counts, state);
                validated.close();
                commit = true;
            }
            catch (Throwable error) {
                failure = error;
                rollback(error);
            }
            finally {
                currentProgram.endTransaction(transaction, commit);
            }
            if (failure != null) {
                if (failure instanceof Exception) throw (Exception) failure;
                if (failure instanceof Error) throw (Error) failure;
                throw new Exception(failure);
            }
            summary = summary(validated, counts);
        }
        System.out.println("ApplyExceptionRoots: " + summary);
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
                if (!disassemble.applyTo(currentProgram, monitor)) {
                    fail("exception-root disassembly failed at " + entry + ": "
                            + disassemble.getStatusMsg());
                }
                AddressSetView disassembled = disassemble.getDisassembledAddressSet();
                if (!disassembled.isEmpty()) journal(() -> clear(disassembled));
                if (!disassembled.contains(instructionRange)
                        || disassembled.getNumAddresses() != instructionRange.getNumAddresses()) {
                    fail("exception-root disassembly did not define exactly one instruction at "
                            + entry);
                }
            }
            CreateFunctionCmd create = new CreateFunctionCmd(
                    null, entry, instructionRange, SourceType.ANALYSIS);
            if (!create.applyTo(currentProgram, monitor)) {
                fail("exception-root function creation failed at " + entry + ": "
                        + create.getStatusMsg());
            }
            function = currentProgram.getFunctionManager().getFunctionAt(entry);
            if (function == null || !function.getBody().equals(instructionRange)) {
                fail("exception-root function was not created with the exact entry body at "
                        + entry);
            }
            journal(() -> {
                if (!currentProgram.getFunctionManager().removeFunction(entry)) {
                    fail("exception-root function could not be rolled back at " + entry);
                }
            });
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
            if ("exception_owned".equals(primaryDisposition)) counts.namesReapplied++;
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
                try {
                    function.setName(plan.application.desiredPrimary, SourceType.ANALYSIS);
                }
                catch (ghidra.util.exception.DuplicateNameException
                        | ghidra.util.exception.InvalidInputException error) {
                    fail("exception primary could not be applied at " + entry);
                }
                journal(() -> applied.setName(priorName, priorSource));
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
            function.setName(ExceptionRootsSupport.primaryGuardName(
                    plan.application.entry), SourceType.ANALYSIS);
            journal(() -> guarded.setName(priorName, SourceType.DEFAULT));
        }
        ensureNamespace();
        if (plan.prior == null) {
            for (String leaf : plan.application.roleLabels) {
                Symbol symbol = currentProgram.getSymbolTable().createLabel(
                        entry, leaf, reservedNamespace, SourceType.ANALYSIS);
                if (symbol == null) fail("exception role label was not created: " + leaf);
                journal(() -> {
                    if (!symbol.delete()) {
                        fail("exception role label could not be rolled back: " + leaf);
                    }
                });
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
        Long primaryId = null;
        String primarySource = null;
        String primaryHash = null;
        if (!"not_requested".equals(primaryDisposition)) {
            primaryId = primary.getID();
            primarySource = PmeScriptSupport.primarySource(primary.getSource());
            primaryHash = PmeScriptSupport.blake3Hex(PmeScriptSupport.boundedUtf8(
                    primary.getName(), ExceptionRootsSupport.MAX_SYMBOL_UTF8_BYTES,
                    "exception primary"));
        }
        ExceptionRootsSupport.RegistryEntry ownership =
                new ExceptionRootsSupport.RegistryEntry(
                        validated.manifest.manifestBlake3, plan.application.entry,
                        plan.application.isa, plan.root.instructionBlake3, function.getID(),
                        functionDisposition, primaryDisposition, primaryId, primarySource,
                        primaryHash, Collections.unmodifiableList(labelIds),
                        ExceptionRootsSupport.labelsDigest(labels));
        String priorValue = registry.getString(entry);
        String value = ExceptionRootsSupport.registryValue(ownership);
        if (plan.prior == null) {
            registry.add(entry, value);
            journal(() -> registry.remove(entry));
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
        RegisterValue prior = context.getRegisterValue(validated.tMode, entry);
        context.setValue(validated.tMode, entry, end, wanted);
        journal(() -> {
            context.remove(entry, end, validated.tMode);
            if (prior != null && prior.hasValue()) {
                context.setValue(validated.tMode, entry, end, prior.getUnsignedValue());
            }
        });
    }

    private StringPropertyMap findOrCreateRegistry() throws Exception {
        StringPropertyMap existing = ExceptionRootsSupport.currentRegistry(currentProgram);
        if (existing != null) return existing;
        PropertyMapManager manager = currentProgram.getUsrPropertyManager();
        try {
            StringPropertyMap created =
                    manager.createStringPropertyMap(ExceptionRootsSupport.OWNERSHIP_MAP);
            journal(() -> {
                if (!manager.removePropertyMap(ExceptionRootsSupport.OWNERSHIP_MAP)) {
                    fail("exception-root ownership registry could not be rolled back");
                }
            });
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
        try {
            reservedNamespace = symbols.createNameSpace(
                    currentProgram.getGlobalNamespace(),
                    ExceptionRootsSupport.RESERVED_NAMESPACE, SourceType.ANALYSIS);
        }
        catch (ghidra.util.exception.DuplicateNameException
                | ghidra.util.exception.InvalidInputException error) {
            fail("exception-root reserved namespace could not be created");
        }
        Namespace created = reservedNamespace;
        journal(() -> {
            Symbol symbol = created.getSymbol();
            if (symbol != null && !symbol.delete()) {
                fail("exception-root namespace could not be rolled back");
            }
        });
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
                primary.addSuppressed(rollbackFailure);
            }
        }
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
        return "{\"image\":" + PmeScriptSupport.jsonString(
                validated.manifest.image.label)
                + ",\"status\":\"ok\",\"identity\":"
                + PmeScriptSupport.jsonString(validated.identity)
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
                + ",\"shared_entries\":" + shared + "}";
    }

    private void fail(String message) {
        throw new ExceptionRootsSupport.RootError(message);
    }
}
