// ApplyStartupMetadata.java - pass-2 labels, ownership registry, and gated
// no-return for Phase 3B startup metadata. Present only when startup state
// is Present. Does not rename primaries. Does not open a nested transaction.
// Does not call analysis or flow-repair APIs. Never clear no-return on
// unrelated functions.
//
// Arguments in order: kit-root, label, image-blake3, startup-identity,
// startup-manifest, scatter-map-or-dash, functions-json, functions-blake3.
//@category PixelModem
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class ApplyStartupMetadata extends HeadlessScript {
    @FunctionalInterface
    private interface Undo {
        void run() throws Exception;
    }

    private static final class Counts {
        int labeled;
        int skippedExistingLabel;
        int noReturnRequested;
        int noReturnApplied;
        int noReturnSkipped;
    }

    private final List<Undo> undo = new ArrayList<Undo>();
    private Namespace reservedNamespace;
    private StringPropertyMap registry;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 8) {
            fail("expected kit root, label, image blake3, identity, manifest, "
                    + "scatter map or '-', functions.json, and functions blake3");
        }
        File kitRoot = new File(args[0]);
        String image = args[1];
        String imageBlake3 = args[2];
        String expectedIdentity = args[3];
        File manifest = new File(args[4]);
        String scatter = args[5];
        File functions = new File(args[6]);
        String functionsBlake3 = args[7];

        StartupMetadataSupport.Validated validated = null;
        boolean transactionEnded = false;
        try {
            try {
                validated = StartupMetadataSupport.preflight(currentProgram, monitor, kitRoot,
                        image, imageBlake3, expectedIdentity, manifest, scatter, functions,
                        functionsBlake3);
            }
            catch (StartupMetadataSupport.StartupError | PmeScriptSupport.SupportError error) {
                emitError(image, error.getMessage());
                closeQuietly(validated);
                return;
            }

            Counts counts = new Counts();
            applyAll(validated, counts);
            StartupMetadataSupport.validateApplied(
                    currentProgram, validated.manifest, validated.identity);
            validated.verifyRetainedFiles();
            requireConservation(validated, counts);
            String summary = summary(validated, counts);

            end(true);
            transactionEnded = true;
            validated.close();
            validated = null;
            emit(summary);
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
            closeQuietly(validated, error);
            rethrow(error);
        }
    }

    private void applyAll(StartupMetadataSupport.Validated validated, Counts counts)
            throws Exception {
        // Empty-application Present (BOOT/VSS/APM applications: []) still
        // creates the reserved namespace and ownership map so validateApplied's
        // empty bijection succeeds. Task 15 must drive this on real Ghidra.
        ensureNamespace();
        registry = findOrCreateRegistry();
        for (StartupMetadataSupport.Application application : validated.manifest.applications) {
            applyOne(validated, application, counts);
        }
    }

    private void applyOne(StartupMetadataSupport.Validated validated,
            StartupMetadataSupport.Application application, Counts counts) throws Exception {
        Address entry = toAddr(application.entry);
        Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
        if (function == null) {
            fail("startup metadata target function is missing at " + entry);
        }
        ensureNamespace();

        SymbolTable symbols = currentProgram.getSymbolTable();
        Symbol existing = symbols.getSymbol(application.roleLabel, entry, reservedNamespace);
        if (existing != null) {
            if (existing.getSource() != SourceType.ANALYSIS) {
                fail("an existing startup role label does not carry ANALYSIS source: "
                        + application.roleLabel);
            }
            counts.skippedExistingLabel++;
        }
        else {
            journal(() -> {
                Symbol created = currentProgram.getSymbolTable()
                        .getSymbol(application.roleLabel, entry, reservedNamespace);
                if (created != null && !created.delete()) {
                    fail("startup metadata role label could not be rolled back");
                }
            });
            try {
                symbols.createLabel(entry, application.roleLabel, reservedNamespace,
                        SourceType.ANALYSIS);
            }
            catch (ghidra.util.exception.InvalidInputException error) {
                fail("the reserved startup label could not be created: "
                        + application.roleLabel);
            }
            counts.labeled++;
        }

        if (application.setNoReturn) {
            counts.noReturnRequested++;
            if (function.hasNoReturn()) {
                counts.noReturnSkipped++;
            }
            else {
                final Function target = function;
                final boolean priorNoReturn = function.hasNoReturn();
                journal(() -> target.setNoReturn(priorNoReturn));
                function.setNoReturn(true);
                counts.noReturnApplied++;
            }
        }

        Symbol label = symbols.getSymbol(application.roleLabel, entry, reservedNamespace);
        if (label == null) {
            fail("the applied startup role label is missing at " + entry);
        }
        Symbol primary = function.getSymbol();
        String value = StartupMetadataSupport.registryValue(
                new StartupMetadataSupport.RegistryEntry(
                        validated.manifest.manifestBlake3, application.entry, application.isa,
                        function.getID(), primary.getID(),
                        PmeScriptSupport.primarySource(primary.getSource()),
                        StartupMetadataSupport.primaryNameDigest(primary.getName()),
                        application.setNoReturn, label.getID()));
        final Address registryEntry = entry;
        final String prior = registry.getString(entry);
        journal(() -> {
            if (prior == null) {
                registry.remove(registryEntry);
            }
            else {
                registry.add(registryEntry, prior);
            }
        });
        registry.add(entry, value);
    }

    private void requireConservation(StartupMetadataSupport.Validated validated, Counts counts) {
        int candidates = validated.manifest.applications.size();
        int labeled = Math.addExact(counts.labeled, counts.skippedExistingLabel);
        int noReturn = Math.addExact(counts.noReturnApplied, counts.noReturnSkipped);
        if (labeled != candidates || counts.noReturnRequested != noReturn) {
            fail("startup metadata terminal counts do not conserve candidates");
        }
    }

    private String summary(StartupMetadataSupport.Validated validated, Counts counts) {
        int candidates = validated.manifest.applications.size();
        return "{\"image\":" + PmeScriptSupport.jsonString(validated.manifest.image.label)
                + ",\"status\":\"ok\",\"identity\":"
                + PmeScriptSupport.jsonString(validated.identity)
                + ",\"candidates\":" + candidates
                + ",\"labeled\":" + counts.labeled
                + ",\"skipped_existing_label\":" + counts.skippedExistingLabel
                + ",\"no_return_requested\":" + counts.noReturnRequested
                + ",\"no_return_applied\":" + counts.noReturnApplied
                + ",\"no_return_skipped\":" + counts.noReturnSkipped + "}";
    }

    private void emitError(String image, String reason) {
        String summary = "{\"image\":" + PmeScriptSupport.jsonString(image)
                + ",\"status\":\"error\",\"error\":"
                + PmeScriptSupport.jsonString(StartupMetadataSupport.boundReason(reason))
                + "}";
        emit(summary);
    }

    private void emit(String summary) {
        String line = "ApplyStartupMetadata: " + summary;
        System.out.println(line);
        println(line);
    }

    private StringPropertyMap findOrCreateRegistry() throws Exception {
        StringPropertyMap existing = StartupMetadataSupport.currentRegistry(currentProgram);
        if (existing != null) return existing;
        PropertyMapManager manager = currentProgram.getUsrPropertyManager();
        journal(() -> {
            if (StartupMetadataSupport.currentRegistry(currentProgram) != null
                    && !manager.removePropertyMap(StartupMetadataSupport.OWNERSHIP_MAP)) {
                fail("startup metadata ownership registry could not be rolled back");
            }
        });
        try {
            return manager.createStringPropertyMap(StartupMetadataSupport.OWNERSHIP_MAP);
        }
        catch (Exception error) {
            fail("startup metadata ownership registry could not be created");
            return null;
        }
    }

    private void ensureNamespace() throws Exception {
        if (reservedNamespace != null) return;
        Namespace existing = StartupMetadataSupport.currentNamespace(currentProgram);
        if (existing != null) {
            reservedNamespace = existing;
            return;
        }
        SymbolTable symbols = currentProgram.getSymbolTable();
        journal(() -> {
            Namespace partial = StartupMetadataSupport.currentNamespace(currentProgram);
            if (partial != null) {
                Symbol symbol = partial.getSymbol();
                if (symbol != null && !symbol.delete()) {
                    fail("startup metadata namespace could not be rolled back");
                }
            }
        });
        try {
            reservedNamespace = symbols.createNameSpace(
                    currentProgram.getGlobalNamespace(),
                    StartupMetadataSupport.RESERVED_NAMESPACE, SourceType.ANALYSIS);
        }
        catch (ghidra.util.exception.DuplicateNameException
                | ghidra.util.exception.InvalidInputException error) {
            fail("startup metadata reserved namespace could not be created");
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

    private void closeQuietly(AutoCloseable closeable) {
        if (closeable == null) return;
        try {
            closeable.close();
        }
        catch (Throwable ignored) {
            // Map-error close failures must not hide the emitted error summary.
        }
    }

    private void closeQuietly(AutoCloseable closeable, Throwable primary) {
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

    private void fail(String message) {
        throw new StartupMetadataSupport.StartupError(message);
    }
}
