//! Self-contained end-to-end test of the `--run` path: craft a tiny ARM blob in a
//! valid TOC, drive real Ghidra headless, and assert the export. Gated on locating
//! Ghidra ($GHIDRA_INSTALL_DIR or /opt/ghidra); skips cleanly otherwise. No
//! proprietary firmware needed.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;

fn find_ghidra_home() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("GHIDRA_INSTALL_DIR") {
        let p = PathBuf::from(dir);
        if p.join("support").join("analyzeHeadless").exists() {
            return Some(p);
        }
    }
    let opt = PathBuf::from("/opt/ghidra");
    if opt.join("support").join("analyzeHeadless").exists() {
        return Some(opt);
    }
    None
}

/// Minimal valid `modem.bin`: TOC + one embedded image (index 1, "BOOT", base 0).
fn craft_modem_bin(payload: &[u8]) -> Vec<u8> {
    let entry_off = 0x20usize;
    let payload_off = entry_off + 0x20; // one 32-byte entry
    let mut buf = vec![0u8; payload_off + payload.len()];
    buf[0..4].copy_from_slice(b"TOC\0");
    buf[0x1c..0x20].copy_from_slice(&1u32.to_le_bytes()); // count
    buf[entry_off..entry_off + 4].copy_from_slice(b"BOOT"); // name
    buf[entry_off + 12..entry_off + 16].copy_from_slice(&(payload_off as u32).to_le_bytes()); // offset
    buf[entry_off + 16..entry_off + 20].copy_from_slice(&0u32.to_le_bytes()); // load_addr
    buf[entry_off + 20..entry_off + 24].copy_from_slice(&(payload.len() as u32).to_le_bytes()); // size
    buf[entry_off + 28..entry_off + 32].copy_from_slice(&1u32.to_le_bytes()); // index
    buf[payload_off..].copy_from_slice(payload);
    buf
}

fn relative_spelling_from_current(path: &std::path::Path) -> PathBuf {
    let current = std::fs::canonicalize(".").unwrap();
    let target = std::fs::canonicalize(path).unwrap();
    let current_components: Vec<_> = current.components().collect();
    let target_components: Vec<_> = target.components().collect();
    let shared = current_components
        .iter()
        .zip(&target_components)
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    for _ in shared..current_components.len() {
        relative.push("..");
    }
    for component in &target_components[shared..] {
        relative.push(component.as_os_str());
    }
    relative
}

fn prepared_pass2_map(
    path: &std::path::Path,
    count: usize,
) -> pixel_modem_extractor::decompile::PreparedPass2Map {
    let relative = relative_spelling_from_current(path);
    assert!(relative.is_relative());
    pixel_modem_extractor::decompile::PreparedPass2Map::new(
        &relative,
        NonZeroUsize::new(count).unwrap(),
    )
    .unwrap()
}

#[test]
fn run_drives_ghidra_end_to_end() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    // ARM: `add r0, r0, r1` ; `bx lr`  (little-endian)
    let arm = [0x01u8, 0x00, 0x80, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
    let modem = craft_modem_bin(&arm);

    let dir = std::env::temp_dir().join(format!("pme_decompile_e2e_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");

    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    pixel_modem_extractor::decompile::run(&modem_path, &opts, &out).unwrap();

    let exp = out.join("export").join("00_BOOT");
    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(!c.trim().is_empty(), "decompiled.c is empty");
    let lst = std::fs::read_to_string(exp.join("disasm.lst")).unwrap();
    assert!(!lst.trim().is_empty(), "disasm.lst is empty");
    // §5.3 format "address: bytes  mnemonic": the first ARM word's bytes (01 00 80 e0) appear.
    assert!(
        lst.contains("010080e0"),
        "disasm.lst missing the instruction-bytes column:\n{lst}"
    );
    let funcs: serde_json::Value =
        serde_json::from_slice(&std::fs::read(exp.join("functions.json")).unwrap()).unwrap();
    assert!(
        funcs.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "functions.json has no functions: {funcs}"
    );
    let first = funcs
        .as_array()
        .and_then(|a| a.first())
        .expect("functions.json has at least one function");
    assert!(
        first
            .get("end")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "functions.json entry missing end: {first}"
    );
    assert!(
        first
            .get("data_refs")
            .and_then(serde_json::Value::as_array)
            .is_some(),
        "functions.json entry missing data_refs array: {first}"
    );
    assert_eq!(
        first["decode_ranges"],
        serde_json::json!([{"isa":"arm", "start":"0x0", "end":"0x4"}]),
        "the normal A32 fixture must export its exact instruction-backed range: {first}"
    );
    assert_eq!(first["decode_range_errors"], serde_json::json!([]));

    // generation artifacts exist alongside the export
    assert!(out.join("ghidra_load.json").exists());
    assert!(out.join("run_ghidra.sh").exists());
    assert!(out.join("scripts").join("ExportDecomp.java").exists());
    assert!(out.join("images").join("00_BOOT").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn exporter_quarantines_instruction_when_tmode_register_is_missing() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let modem = craft_modem_bin(&[0xc3]); // x86 `ret`; language has no ARM TMode register.
    let dir = std::env::temp_dir().join(format!(
        "pme_decompile_missing_tmode_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");
    let report = pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: true,
            image: None,
            ghidra_home: Some(home),
            processor: "x86:LE:32:default".to_string(),
            no_thumb_decompile: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: false,
        },
        &out,
    )
    .unwrap();
    let boot = report
        .images
        .iter()
        .find(|image| image.label == "00_BOOT")
        .unwrap();
    assert_eq!(boot.ghidra_execution_accepted, Some(0));
    assert_eq!(boot.ghidra_execution_quarantined, Some(1));
    let functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("export/00_BOOT/functions.json")).unwrap())
            .unwrap();
    assert_eq!(functions.as_array().unwrap().len(), 1, "{functions}");
    assert_eq!(functions[0]["decode_ranges"], serde_json::json!([]));
    assert_eq!(
        functions[0]["decode_range_errors"],
        serde_json::json!([
            {"kind":"empty_projection","address":"0x0","end":null},
            {"kind":"missing_isa_context","address":"0x0","end":"0x1"}
        ])
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saved_program_exports_mixed_isa_ranges_and_preserves_body_gap() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let payload = [
        0x1eu8, 0xff, 0x2f, 0xe1, // A32: bx lr
        0, 0, 0, 0, // exact Function-body gap
        0x70, 0x47, // T32: bx lr
    ];
    let modem = craft_modem_bin(&payload);
    let dir = std::env::temp_dir().join(format!("pme_decompile_mixed_gap_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");
    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let pass1 = pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();

    // Fixture-only replacement: run_two_pass executes this against the saved
    // temporary project before the shipping ExportDecomp.java post-script.
    std::fs::write(
        out.join("scripts/ApplySymbols.java"),
        r#"//@category PixelModemTest
import java.math.BigInteger;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.SourceType;

public class ApplySymbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager functions = currentProgram.getFunctionManager();
        while (functions.getFunctionCount() != 0) {
            FunctionIterator iterator = functions.getFunctions(true);
            Function function = iterator.next();
            functions.removeFunction(function.getEntryPoint());
        }
        Address arm = toAddr(0);
        Address thumb = toAddr(8);
        clearListing(arm, toAddr(9));
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        ProgramContext context = currentProgram.getProgramContext();
        context.setValue(tMode, arm, toAddr(3), BigInteger.ZERO);
        if (!disassemble(arm)) throw new Exception("failed to disassemble A32 fixture");
        context.setValue(tMode, thumb, toAddr(9), BigInteger.ONE);
        if (!disassemble(thumb)) throw new Exception("failed to disassemble T32 fixture");
        AddressSet body = new AddressSet();
        body.addRange(arm, toAddr(3));
        body.addRange(thumb, toAddr(9));
        functions.createFunction("mixed_gap", arm, body, SourceType.USER_DEFINED);
        println("ApplySymbols: applied 1 names, 0 plate comments, skipped 0");
    }
}
"#,
    )
    .unwrap();
    let map = out.join("mixed-gap-map.json");
    std::fs::write(&map, b"{}").unwrap();
    let inputs = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: Some(prepared_pass2_map(&map, 1)),
            global_map: None,
            global_types_map: None,
        },
    )]);
    let pass2 =
        pixel_modem_extractor::decompile::run_two_pass(pass1, &opts, &out, &inputs).unwrap();
    assert_eq!(
        pass2.outcomes["00_BOOT"],
        pixel_modem_extractor::decompile::Pass2ProcessOutcome::ProcessSucceeded
    );

    let functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("export/00_BOOT/functions.json")).unwrap())
            .unwrap();
    assert_eq!(functions.as_array().unwrap().len(), 1, "{functions}");
    assert_eq!(functions[0]["name"], "mixed_gap");
    assert_eq!(functions[0]["entry"], "0x0");
    assert_eq!(functions[0]["end"], "0xa");
    assert_eq!(functions[0]["size"], 6);
    assert_eq!(
        functions[0]["decode_ranges"],
        serde_json::json!([
            {"isa":"arm", "start":"0x0", "end":"0x4"},
            {"isa":"thumb", "start":"0x8", "end":"0xa"}
        ])
    );
    assert_eq!(functions[0]["decode_range_errors"], serde_json::json!([]));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saved_program_quarantines_when_same_isa_merge_makes_entry_interior() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let payload = [
        0x1eu8, 0xff, 0x2f, 0xe1, // A32: bx lr before the function entry
        0x1e, 0xff, 0x2f, 0xe1, // A32: bx lr at the function entry
    ];
    let modem = craft_modem_bin(&payload);
    let dir = std::env::temp_dir().join(format!(
        "pme_decompile_entry_interior_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");
    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let pass1 = pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();

    std::fs::write(
        out.join("scripts/ApplySymbols.java"),
        r#"//@category PixelModemTest
import java.math.BigInteger;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.SourceType;

public class ApplySymbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager functions = currentProgram.getFunctionManager();
        while (functions.getFunctionCount() != 0) {
            FunctionIterator iterator = functions.getFunctions(true);
            Function function = iterator.next();
            functions.removeFunction(function.getEntryPoint());
        }
        clearListing(toAddr(0), toAddr(7));
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        ProgramContext context = currentProgram.getProgramContext();
        context.setValue(tMode, toAddr(0), toAddr(7), BigInteger.ZERO);
        if (!disassemble(toAddr(0)) || !disassemble(toAddr(4))) {
            throw new Exception("failed to disassemble adjacent A32 fixture");
        }
        AddressSet body = new AddressSet(toAddr(0), toAddr(7));
        functions.createFunction(
            "entry_interior", toAddr(4), body, SourceType.USER_DEFINED);
        println("ApplySymbols: applied 1 names, 0 plate comments, skipped 0");
    }
}
"#,
    )
    .unwrap();
    let map = out.join("entry-interior-map.json");
    std::fs::write(&map, b"{}").unwrap();
    let inputs = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: Some(prepared_pass2_map(&map, 1)),
            global_map: None,
            global_types_map: None,
        },
    )]);
    let pass2 =
        pixel_modem_extractor::decompile::run_two_pass(pass1, &opts, &out, &inputs).unwrap();
    assert_eq!(
        pass2.outcomes["00_BOOT"],
        pixel_modem_extractor::decompile::Pass2ProcessOutcome::ProcessSucceeded
    );

    let functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("export/00_BOOT/functions.json")).unwrap())
            .unwrap();
    assert_eq!(functions.as_array().unwrap().len(), 1, "{functions}");
    assert_eq!(functions[0]["entry"], "0x4");
    assert_eq!(functions[0]["decode_ranges"], serde_json::json!([]));
    assert_eq!(
        functions[0]["decode_range_errors"],
        serde_json::json!([
            {"kind":"entry_not_range_start","address":"0x4","end":null}
        ])
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saved_program_rejects_instruction_free_body_range_outside_u32() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let modem = craft_modem_bin(&[0xc3]); // x86-64 `ret`
    let dir = std::env::temp_dir().join(format!(
        "pme_decompile_body_outside_u32_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");
    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home),
        processor: "x86:LE:64:default".to_string(),
        no_thumb_decompile: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let pass1 = pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();

    std::fs::write(
        out.join("scripts/ApplySymbols.java"),
        r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class ApplySymbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager functions = currentProgram.getFunctionManager();
        while (functions.getFunctionCount() != 0) {
            FunctionIterator iterator = functions.getFunctions(true);
            Function function = iterator.next();
            functions.removeFunction(function.getEntryPoint());
        }
        Address entry = toAddr(0);
        clearListing(entry, entry);
        if (!disassemble(entry)) throw new Exception("failed to disassemble x86 fixture");
        Address high = toAddr(0x1_0000_0000L);
        currentProgram.getMemory().createInitializedBlock(
            "outside_u32", high, 4, (byte) 0, monitor, false);
        AddressSet body = new AddressSet(entry, entry);
        body.addRange(high, high.add(3));
        functions.createFunction(
            "body_outside_u32", entry, body, SourceType.USER_DEFINED);
        println("ApplySymbols: applied 1 names, 0 plate comments, skipped 0");
    }
}
"#,
    )
    .unwrap();
    let map = out.join("body-outside-u32-map.json");
    std::fs::write(&map, b"{}").unwrap();
    let inputs = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: Some(prepared_pass2_map(&map, 1)),
            global_map: None,
            global_types_map: None,
        },
    )]);
    let _pass2 =
        pixel_modem_extractor::decompile::run_two_pass(pass1, &opts, &out, &inputs).unwrap();
    let functions = std::fs::read(out.join("export/00_BOOT/functions.json")).unwrap();
    assert!(
        serde_json::from_slice::<serde_json::Value>(&functions).is_err(),
        "an instruction-free out-of-domain body range must abort before a complete inventory is emitted"
    );
    let application_log = read_ghidra_application_log(&out);
    assert!(
        application_log.contains("unassignable producer address outside u32"),
        "missing producer-integrity failure in application log:\n{application_log}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saved_program_quarantines_complete_defective_records_and_continues() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let mut payload = Vec::new();
    for _ in 0..7 {
        payload.extend([0x1e, 0xff, 0x2f, 0xe1]); // A32: bx lr
    }
    let modem = craft_modem_bin(&payload);
    let dir = std::env::temp_dir().join(format!("pme_decompile_quarantine_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");
    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let pass1 = pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();
    std::fs::write(
        out.join("scripts/ApplySymbols.java"),
        r#"//@category PixelModemTest
import java.math.BigInteger;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.SourceType;

public class ApplySymbols extends GhidraScript {
    private AddressSet body(long min, long max) {
        AddressSet body = new AddressSet();
        body.addRange(toAddr(min), toAddr(max));
        return body;
    }

    @Override
    public void run() throws Exception {
        FunctionManager functions = currentProgram.getFunctionManager();
        while (functions.getFunctionCount() != 0) {
            FunctionIterator iterator = functions.getFunctions(true);
            Function function = iterator.next();
            functions.removeFunction(function.getEntryPoint());
        }
        clearListing(toAddr(0), toAddr(27));
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        ProgramContext context = currentProgram.getProgramContext();
        context.setValue(tMode, toAddr(0), toAddr(27), BigInteger.ZERO);
        for (long address : new long[] {0, 8, 12, 20, 24}) {
            if (!disassemble(toAddr(address))) {
                throw new Exception("failed to disassemble fixture at " + address);
            }
        }
        Instruction overridden = currentProgram.getListing().getInstructionAt(toAddr(8));
        overridden.setLengthOverride(2);
        functions.createFunction("accepted_before", toAddr(0), body(0, 3), SourceType.USER_DEFINED);
        functions.createFunction("overridden", toAddr(8), body(8, 11), SourceType.USER_DEFINED);
        functions.createFunction("body_escape", toAddr(12), body(12, 13), SourceType.USER_DEFINED);
        AddressSet missingEntryBody = body(16, 16);
        missingEntryBody.addRange(toAddr(20), toAddr(23));
        functions.createFunction("missing_entry", toAddr(16), missingEntryBody, SourceType.USER_DEFINED);
        functions.createFunction("accepted_after", toAddr(24), body(24, 27), SourceType.USER_DEFINED);
        println("ApplySymbols: applied 1 names, 0 plate comments, skipped 0");
    }
}
"#,
    )
    .unwrap();
    let map = out.join("quarantine-map.json");
    std::fs::write(&map, b"{}").unwrap();
    let inputs = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: Some(prepared_pass2_map(&map, 1)),
            global_map: None,
            global_types_map: None,
        },
    )]);
    let pass2 =
        pixel_modem_extractor::decompile::run_two_pass(pass1, &opts, &out, &inputs).unwrap();
    assert_eq!(
        pass2.outcomes["00_BOOT"],
        pixel_modem_extractor::decompile::Pass2ProcessOutcome::ProcessSucceeded
    );
    let functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("export/00_BOOT/functions.json")).unwrap())
            .unwrap();
    let by_name: HashMap<&str, &serde_json::Value> = functions
        .as_array()
        .unwrap()
        .iter()
        .map(|function| (function["name"].as_str().unwrap(), function))
        .collect();
    assert_eq!(
        by_name["accepted_before"]["decode_ranges"],
        serde_json::json!([{"isa":"arm","start":"0x0","end":"0x4"}])
    );
    assert_eq!(
        by_name["overridden"]["decode_ranges"],
        serde_json::json!([]),
        "a defective record must not retain a valid-looking range prefix"
    );
    assert_eq!(
        by_name["overridden"]["decode_range_errors"],
        serde_json::json!([
            {"kind":"misaligned_instruction","address":"0x8","end":"0xa"},
            {"kind":"overridden_instruction_length","address":"0x8","end":"0xa"}
        ])
    );
    assert_eq!(
        by_name["body_escape"]["decode_range_errors"],
        serde_json::json!([
            {"kind":"extent_outside_function","address":"0xc","end":"0x10"}
        ])
    );
    assert_eq!(
        by_name["missing_entry"]["decode_range_errors"],
        serde_json::json!([
            {"kind":"missing_instruction_at_entry","address":"0x10","end":null}
        ])
    );
    assert_eq!(
        by_name["accepted_after"]["decode_ranges"],
        serde_json::json!([{"isa":"arm","start":"0x18","end":"0x1c"}]),
        "later functions must still export after record-local quarantines"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Pass-2 application end-to-end: drive pass 1 via `run_report`, then apply a
/// function and strict Recovered globals in the same saved-project process.
/// Subsequent attempts prove non-default preservation and invalid-map isolation.
#[test]
fn pass2_applies_functions_and_strict_globals_in_one_process() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };

    // ARM: `ldr r0, [pc, #0x18]`; `bx lr`; six vector-slot self-branches;
    // one data word at 0x20. The LDR genuinely references 0x20, while the
    // self-branches keep vector analysis from flowing into that data word.
    let mut arm = vec![0x18u8, 0x00, 0x9f, 0xe5, 0x1e, 0xff, 0x2f, 0xe1];
    for _ in 0..6 {
        arm.extend([0xfe, 0xff, 0xff, 0xea]); // b .
    }
    arm.extend([0x78, 0x56, 0x34, 0x12]);
    let modem = craft_modem_bin(&arm);

    let dir = std::env::temp_dir().join(format!("pme_decompile_p2_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");

    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };

    // Pass 1: analyze + initial decompiled.c (with FUN_ placeholder).
    let pass1_report =
        pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();
    assert!(
        pass1_report.images.iter().any(|r| r.label == "00_BOOT"),
        "pass 1 should have analyzed 00_BOOT"
    );
    let pass1_functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("export/00_BOOT/functions.json")).unwrap())
            .unwrap();
    assert!(
        pass1_functions
            .as_array()
            .unwrap()
            .iter()
            .any(|function| function["data_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| reference == "0x20")),
        "fixture did not produce a genuine data reference: {pass1_functions}"
    );
    let pass1_projections: HashMap<String, serde_json::Value> = pass1_functions
        .as_array()
        .unwrap()
        .iter()
        .map(|function| {
            (
                function["entry"].as_str().unwrap().to_string(),
                serde_json::json!({
                    "decode_ranges": function["decode_ranges"],
                    "decode_range_errors": function["decode_range_errors"],
                }),
            )
        })
        .collect();
    let retained_thumb = serde_json::to_vec(&serde_json::json!({
        "format":"pixel-modem-extractor-thumb-functions-v2",
        "functions":[{
            "name":"retained_thumb_fixture", "entry":"0x0", "end":"0x2", "size":2,
            "decode_ranges":[{"isa":"thumb","start":"0x0","end":"0x2"}],
            "decode_range_errors":[], "body_kind":"thumb_disassembly", "body":"", "data_refs":[]
        }]
    }))
    .unwrap();
    std::fs::write(
        out.join("export/00_BOOT/thumb_functions.json"),
        &retained_thumb,
    )
    .unwrap();

    // One-symbol map: rename entry 0x0 -> boot_reset_handler with one annotation.
    // ApplySymbols.java reads `entry`, `name`, `tier=recovered`, and `annotations[]`.
    let maps_dir = out.join("symbol_maps");
    std::fs::create_dir_all(&maps_dir).unwrap();
    let map_path = maps_dir.join("00_BOOT.json");
    let annotation = "evidence: tier=recovered src=arm-db";
    let symbol_map = serde_json::json!({
        "tool_version": "test",
        "image": "00_BOOT",
        "source_blake3": "0",
        "functions_blake3": "0",
        "symbols": [
            {
                "entry": "0x0",
                "arch": "a32",
                "original_name": "FUN_00000000",
                "name": "boot_reset_handler",
                "tier": "recovered",
                "annotations": [annotation],
            },
        ],
    });
    std::fs::write(
        &map_path,
        serde_json::to_string_pretty(&symbol_map).unwrap(),
    )
    .unwrap();

    let global_map_path = maps_dir.join("00_BOOT-globals.json");

    // Characterize ApplyGlobals' fail-whole-map preflight before 0x20 has
    // been renamed: numerically identical selected addresses in different
    // hexadecimal spellings reject the entire map atomically. The script
    // returns normally, so ExportDecomp still completes in this process.
    let duplicate_global_map = serde_json::json!({
        "format": "pixel-modem-extractor-globals-v1",
        "image": "00_BOOT",
        "globals": [
            {
                "address": "0x20",
                "name": "duplicate_first_must_not_apply",
                "tier": "recovered",
            },
            {
                "address": "00000020",
                "name": "duplicate_second_must_not_apply",
                "tier": "recovered",
            },
        ],
    });
    std::fs::write(
        &global_map_path,
        serde_json::to_string_pretty(&duplicate_global_map).unwrap(),
    )
    .unwrap();
    let duplicate_globals_only = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: None,
            global_map: Some(prepared_pass2_map(&global_map_path, 2)),
            global_types_map: None,
        },
    )]);
    let duplicate_run = pixel_modem_extractor::decompile::run_two_pass(
        pass1_report,
        &opts,
        &out,
        &duplicate_globals_only,
    )
    .unwrap();
    let duplicate_report = duplicate_run.report;
    let boot = duplicate_report
        .images
        .iter()
        .find(|r| r.label == "00_BOOT")
        .unwrap();
    assert!(boot.pass2_error.is_none());
    assert!(boot.globals_applied.is_none());
    assert!(boot.globals_apply_skipped.is_none());
    assert!(
        boot.globals_apply_error
            .as_deref()
            .is_some_and(|error| error.contains("duplicate selected address")),
        "globals_apply_error: {:?}",
        boot.globals_apply_error
    );
    let exp = out.join("export").join("00_BOOT");
    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(!c.contains("duplicate_first_must_not_apply"));
    assert!(!c.contains("duplicate_second_must_not_apply"));

    let global_map = serde_json::json!({
        "format": "pixel-modem-extractor-globals-v1",
        "image": "00_BOOT",
        "globals": [
            {
                "address": "0x20",
                "name": "recovered_global_word",
                "tier": "recovered",
            },
            {
                "address": "0x20",
                "name": "provisional_must_not_apply",
                "tier": "provisional",
            },
            {
                "address": "0x1000",
                "name": "outside_memory_global",
                "tier": "recovered",
            },
        ],
    });
    std::fs::write(
        &global_map_path,
        serde_json::to_string_pretty(&global_map).unwrap(),
    )
    .unwrap();

    let inputs = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: Some(prepared_pass2_map(&map_path, 1)),
            global_map: Some(prepared_pass2_map(&global_map_path, 2)),
            global_types_map: None,
        },
    )]);

    // Pass 2: pass pass1_report in (do NOT re-run pass 1).
    let rep2 =
        pixel_modem_extractor::decompile::run_two_pass(duplicate_report, &opts, &out, &inputs)
            .unwrap()
            .report;

    // (c) pass2_applied == Some(1) — ApplySymbols reports 1 rename.
    let boot = rep2
        .images
        .iter()
        .find(|r| r.label == "00_BOOT")
        .expect("00_BOOT in pass-2 report");
    assert_eq!(
        boot.pass2_applied,
        Some(1),
        "pass2_applied should be Some(1): {:?}",
        boot.pass2_error
    );
    assert!(
        boot.pass2_error.is_none(),
        "pass2_error: {:?}",
        boot.pass2_error
    );
    assert_eq!(boot.globals_applied, Some(1));
    assert_eq!(boot.globals_apply_skipped, Some(1));
    assert!(
        boot.globals_apply_error.is_none(),
        "globals_apply_error: {:?}",
        boot.globals_apply_error
    );

    // (a) renamed function appears in the regenerated decompiled.c.
    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(
        c.contains("boot_reset_handler"),
        "renamed function missing from decompiled.c:\n{c}"
    );
    assert!(
        c.contains("recovered_global_word"),
        "Recovered global missing at the decompiled reference site:\n{c}"
    );
    assert!(!c.contains("provisional_must_not_apply"));
    assert!(!c.contains("outside_memory_global"));

    // (b) annotation appears as a comment line. Ghidra 12's ExportDecomp
    // renders plate comments as `/* ... */` blocks; accept the line-comment
    // rendering as well so the test remains compatible with either exporter
    // representation while requiring the exact annotation text.
    let block = format!("/* {annotation} */");
    let line = format!("// {annotation}");
    assert!(
        c.lines().any(|l| l.trim() == block || l.trim() == line),
        "annotation plate comment missing from decompiled.c \
         (looked for `{block}` or `{line}`):\n{c}"
    );

    // Second attempt: the exact symbol is now USER_DEFINED, so strict
    // ownership preserves it and classifies the candidate as non-default.
    let second_global_map = serde_json::json!({
        "format": "pixel-modem-extractor-globals-v1",
        "image": "00_BOOT",
        "globals": [{
            "address": "0x20",
            "name": "second_attempt_must_not_replace",
            "tier": "recovered",
        }],
    });
    std::fs::write(
        &global_map_path,
        serde_json::to_string_pretty(&second_global_map).unwrap(),
    )
    .unwrap();
    let globals_only = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: None,
            global_map: Some(prepared_pass2_map(&global_map_path, 1)),
            global_types_map: None,
        },
    )]);
    let rep3 = pixel_modem_extractor::decompile::run_two_pass(rep2, &opts, &out, &globals_only)
        .unwrap()
        .report;
    let boot = rep3.images.iter().find(|r| r.label == "00_BOOT").unwrap();
    assert_eq!(boot.globals_applied, Some(0));
    assert_eq!(boot.globals_apply_skipped, Some(1));
    assert!(boot.globals_apply_error.is_none());
    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(c.contains("recovered_global_word"));
    assert!(!c.contains("second_attempt_must_not_replace"));

    // A fail-whole-map preflight error returns normally, allowing the
    // independent function rename and final export to complete in this same
    // process while applying zero globals.
    let invalid_global_map = serde_json::json!({
        "format": "wrong-format",
        "image": "00_BOOT",
        "globals": [{
            "address": "0x20",
            "name": "invalid_map_must_apply_zero",
            "tier": "recovered",
        }],
    });
    std::fs::write(
        &global_map_path,
        serde_json::to_string_pretty(&invalid_global_map).unwrap(),
    )
    .unwrap();
    let third_function_map = serde_json::json!({
        "image": "00_BOOT",
        "symbols": [{
            "entry": "0x0",
            "name": "function_exported_despite_invalid_globals",
            "tier": "recovered",
            "annotations": [],
        }],
    });
    std::fs::write(
        &map_path,
        serde_json::to_string_pretty(&third_function_map).unwrap(),
    )
    .unwrap();
    let invalid_combined = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: Some(prepared_pass2_map(&map_path, 1)),
            global_map: Some(prepared_pass2_map(&global_map_path, 1)),
            global_types_map: None,
        },
    )]);
    let invalid_run =
        pixel_modem_extractor::decompile::run_two_pass(rep3, &opts, &out, &invalid_combined)
            .unwrap();
    assert_eq!(
        invalid_run.outcomes["00_BOOT"],
        pixel_modem_extractor::decompile::Pass2ProcessOutcome::ProcessSucceeded
    );
    let rep4 = invalid_run.report;
    let boot = rep4.images.iter().find(|r| r.label == "00_BOOT").unwrap();
    assert_eq!(boot.pass2_applied, Some(1));
    assert!(boot.pass2_error.is_none());
    assert!(boot.globals_applied.is_none());
    assert!(boot.globals_apply_skipped.is_none());
    assert!(boot.globals_apply_error.is_some());
    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(c.contains("function_exported_despite_invalid_globals"));
    assert!(c.contains("recovered_global_word"));
    assert!(!c.contains("invalid_map_must_apply_zero"));
    let final_functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(exp.join("functions.json")).unwrap()).unwrap();
    for function in final_functions.as_array().unwrap() {
        let entry = function["entry"].as_str().unwrap();
        assert_eq!(
            serde_json::json!({
                "decode_ranges": function["decode_ranges"],
                "decode_range_errors": function["decode_range_errors"],
            }),
            pass1_projections[entry],
            "pass 2 changed mandatory execution projection for {entry}"
        );
    }
    assert_eq!(
        std::fs::read(exp.join("thumb_functions.json")).unwrap(),
        retained_thumb,
        "pass 2 must preserve the retained tagged Thumb sidecar byte-for-byte"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Pass-2 global-types end-to-end: proves `ApplyGlobalTypes.java` widens
/// undefined bytes into an `undefinedN` type against real Ghidra, and that a
/// span colliding with a defined instruction is skipped rather than applied.
///
/// Reuses the exact crafted blob from
/// `pass2_applies_functions_and_strict_globals_in_one_process` (LDR-from-
/// data-word + six vector-slot self-branches), whose comment establishes that
/// address 0x20 is a genuine data word real Ghidra's auto-analysis leaves
/// undefined — the self-branches keep vector/flow analysis from ever reaching
/// it, and it is exactly the `DAT_00000020` address that test's `ApplyGlobals`
/// case renames. That same address is this test's type-application target.
/// Ghidra additionally recognizes the 8x4-byte lead-in as an ARM exception
/// vector table (`Reset`, `UndefinedInstruction`, `SupervisorCall`, ...),
/// which only sharpens the fixture: `Reset` (0x0..0x4) is a real, disassembled
/// instruction (the LDR) that a second type candidate is aimed at to force a
/// span collision.
///
/// Note on the `decompiled.c` assertion below: Ghidra's decompiler infers
/// `undefined4` for the `DAT_00000020` read from the LDR's own 4-byte access
/// size, independent of whatever the Listing's committed data type is — so
/// `decompiled.c` already reads `undefined4` even in the pass-1-only export,
/// before `ApplyGlobalTypes.java` ever runs (verified while developing this
/// test). The authoritative, discriminating proof that real
/// `DataUtilities.createData` calls actually ran against the Listing is the
/// parsed `global_types_applied`/`global_types_apply_skipped` counts below,
/// which can only be `Some(1)`/`Some(1)` if the captured `analyzeHeadless`
/// stdout contained a conserving `ApplyGlobalTypes: {"image":"00_BOOT",
/// "status":"ok",...}` line (see `parse_apply_global_types_summary`) — i.e.
/// one `DataUtilities.createData` call succeeded (0x20, no conflict) and one
/// threw `CodeUnitInsertionException` (0x0, the live LDR instruction), which
/// is only possible if `Undefined.getUndefinedDataType`, `DataUtilities.
/// createData`, `ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA`, and the
/// `CodeUnitInsertionException` catch all resolved and worked as intended
/// under the installed Ghidra. The `decompiled.c` check is kept as the
/// brief's requested supplementary/visible confirmation that the export
/// reflects the applied type at the right site, not as the primary signal.
#[test]
fn pass2_applies_global_types_and_skips_span_collision() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };

    // ldr r0, [pc, #0x18]; bx lr; six vector-slot self-branches; one data word
    // at 0x20 — identical to the ApplyGlobals pass-2 test's fixture.
    let mut arm = vec![0x18u8, 0x00, 0x9f, 0xe5, 0x1e, 0xff, 0x2f, 0xe1];
    for _ in 0..6 {
        arm.extend([0xfe, 0xff, 0xff, 0xea]); // b .
    }
    arm.extend([0x78, 0x56, 0x34, 0x12]);
    let modem = craft_modem_bin(&arm);

    let dir = std::env::temp_dir().join(format!("pme_decompile_gtypes_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");

    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };

    // Pass 1: analyze. Confirm the fixture still produces the genuine 0x20
    // data reference this test's type-application target depends on.
    let pass1 = pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();
    let pass1_functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("export/00_BOOT/functions.json")).unwrap())
            .unwrap();
    assert!(
        pass1_functions
            .as_array()
            .unwrap()
            .iter()
            .any(|function| function["data_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| reference == "0x20")),
        "fixture did not produce a genuine data reference: {pass1_functions}"
    );

    // Two candidates: 0x20 (undefined data word -> applies), 0x0 (the live
    // `Reset` LDR instruction -> its span collides and is skipped).
    let map_path = out.join("global-types-map.json");
    let types_map = serde_json::json!({
        "format": "pixel-modem-extractor-global-types-v1",
        "image": "00_BOOT",
        "types": [
            {"address": "0x20", "width": 4},
            {"address": "0x0", "width": 4},
        ],
    });
    std::fs::write(&map_path, serde_json::to_string_pretty(&types_map).unwrap()).unwrap();

    let inputs = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: None,
            global_map: None,
            global_types_map: Some(prepared_pass2_map(&map_path, 2)),
        },
    )]);
    let pass2 =
        pixel_modem_extractor::decompile::run_two_pass(pass1, &opts, &out, &inputs).unwrap();
    assert_eq!(
        pass2.outcomes["00_BOOT"],
        pixel_modem_extractor::decompile::Pass2ProcessOutcome::ProcessSucceeded
    );
    let boot = pass2
        .report
        .images
        .iter()
        .find(|r| r.label == "00_BOOT")
        .expect("00_BOOT in pass-2 report");
    // Corresponds to a captured analyzeHeadless stdout line
    // `ApplyGlobalTypes: {"image":"00_BOOT","status":"ok","candidates":2,
    // "applied":1,"skipped_outside_memory":0,"skipped_collision":1}` —
    // verified verbatim against real Ghidra while developing this test.
    assert_eq!(
        boot.global_types_applied,
        Some(1),
        "global_types_apply_error: {:?}",
        boot.global_types_apply_error
    );
    assert_eq!(
        boot.global_types_apply_skipped,
        Some(1),
        "expected exactly the 0x0/Reset-instruction span collision to be skipped"
    );
    assert!(
        boot.global_types_apply_error.is_none(),
        "global_types_apply_error: {:?}",
        boot.global_types_apply_error
    );

    // The regenerated export reflects the applied undefined4 at the typed
    // global's reference site (see the doc comment above for why this is
    // supplementary, not the discriminating, proof).
    let c = std::fs::read_to_string(out.join("export/00_BOOT/decompiled.c")).unwrap();
    assert!(
        c.contains("undefined4 Reset(void)") && c.contains("return DAT_00000020;"),
        "decompiled.c missing the undefined4 global at its 0x20 reference site:\n{c}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Hand-assembled minimal Thumb-2 function: `push {r7, lr}; movs r0, #0; pop {r7, pc}`.
/// Used by the Phase-2 mode-dispatch e2e tests below. Under the `ARM:LE:32:v7`
/// language Ghidra does not auto-switch into Thumb mode for these bytes alone
/// (no `BX` with the LSB set, no `__thumb` symbol), so the assertion the tests
/// make is on TameAnalysis's `mode=` log line rather than on Ghidra's
/// interpretation of the payload — see the per-test notes.
fn thumb_function_bytes() -> Vec<u8> {
    // push {r7, lr}   -> 0xb580 (LE: 80 b5)
    // movs r0, #0     -> 0x2000 (LE: 00 20)
    // pop {r7, pc}    -> 0xbd80 (LE: 80 bd)
    vec![0x80, 0xb5, 0x00, 0x20, 0x80, 0xbd]
}

/// Locate Ghidra's per-run `application.log`, written under
/// `<out>/ghidra_config/user-ghidra/ghidra_<VERSION>_DEV/application.log`. The
/// version-segment path component varies with the Ghidra release, so we walk the
/// directory to find it. Returns the parsed log text.
fn read_ghidra_application_log(out: &std::path::Path) -> String {
    let user_ghidra = out.join("ghidra_config").join("user-ghidra");
    let mut found: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&user_ghidra) {
        for entry in entries.flatten() {
            let candidate = entry.path().join("application.log");
            if candidate.exists() {
                found.push(candidate);
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "expected exactly one application.log under {}, found {found:?}",
        user_ghidra.display()
    );
    std::fs::read_to_string(&found[0]).unwrap()
}

/// Phase-2 e2e: under `--thumb-decompile` (default) `run_report` dispatches
/// `TameAnalysis mode=tighten`, the tightened mode emitted by `headless_args`.
/// With the 6-byte Thumb fixture, Ghidra does not auto-discover a Thumb
/// function under `ARM:LE:32:v7` (no mode-switch instruction), so the assertion
/// verifies (a) the run completed and produced a non-empty `decompiled.c`, and
/// (b) TameAnalysis's startup line in `application.log` records `mode=tighten`.
/// Together with `no_thumb_decompile_flag_falls_back_to_datamark` this locks in
/// the per-mode dispatch on the same fixture.
#[test]
fn tightened_tame_analysis_dispatchs_tighten_mode() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };

    let payload = thumb_function_bytes();
    let modem = craft_modem_bin(&payload);

    let dir = std::env::temp_dir().join(format!("pme_decompile_t2_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");

    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let report =
        pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).expect("run_report");

    assert!(
        report.images.iter().any(|r| r.label == "00_BOOT"
            && matches!(
                r.outcome,
                pixel_modem_extractor::decompile::ImageOutcome::Analyzed(_)
            )),
        "tighten run should have analyzed 00_BOOT: {report:?}"
    );

    let exp = out.join("export").join("00_BOOT");
    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(
        !c.trim().is_empty(),
        "tighten run should produce a non-empty decompiled.c"
    );

    let log = read_ghidra_application_log(&out);
    assert!(
        log.contains("TameAnalysis: mode=tighten"),
        "TameAnalysis should have logged mode=tighten; log tail:\n{}",
        log.lines().rev().take(40).collect::<Vec<_>>().join("\n")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Phase-2 e2e: `thumb_enrich` populates `body_c` from a synthetic
/// `decompiled.c` keyed by entry address (Phase 2.1: address-based matching,
/// T-bit normalized), and bumps `format` to v2 on first population. Does not
/// require Ghidra — pure Rust step — grouped with the Ghidra tests as Phase-2
/// contract regression.
#[test]
fn thumb_enrich_populates_body_c() {
    let dir = std::env::temp_dir().join(format!(
        "pme_decompile_enrich_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let c_path = dir.join("decompiled.c");
    std::fs::write(
        &c_path,
        "// FUN_40e00000 @ 00040e00000\nvoid FUN_40e00000(void)\n{\n  return;\n}\n\n",
    )
    .unwrap();
    let thumb_path = dir.join("thumb_functions.json");
    std::fs::write(
        &thumb_path,
        r#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[
            {"entry":"0x40e00000","name":"thumb_40e00000","size":6,
             "body_kind":"thumb_disassembly","body":"bx lr","data_refs":[]}]}"#,
    )
    .unwrap();

    let n = pixel_modem_extractor::decompile::thumb_enrich(&c_path, &thumb_path).unwrap();
    assert_eq!(n, 1, "thumb_enrich should populate exactly one body_c");

    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&thumb_path).unwrap()).unwrap();
    assert_eq!(
        v["format"], "pixel-modem-extractor-thumb-functions-v2",
        "format should bump to v2 after population: {v}"
    );
    assert!(
        v["functions"][0]["body_c"].is_string(),
        "body_c should be a string after population: {v}"
    );
    let body_c = v["functions"][0]["body_c"].as_str().unwrap();
    assert!(
        body_c.contains("FUN_40e00000"),
        "body_c should contain the function body: {body_c:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Phase-2 e2e: the `--no-thumb-decompile` escape hatch flips `TameAnalysis` to
/// `mode=datamark`. The 6-byte fixture is far below the 1 MiB `thumb_regions`
/// threshold, so datamark mode marks no regions (Ghidra's analysis matches the
/// tighten run byte-for-byte); the assertion is therefore on the `mode=datamark`
/// dispatch line in `application.log` — proving the Opts flag wires through to
/// `headless_args` and into the spawned script under real Ghidra.
#[test]
fn no_thumb_decompile_flag_falls_back_to_datamark() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };

    let payload = thumb_function_bytes();
    let modem = craft_modem_bin(&payload);

    let dir = std::env::temp_dir().join(format!("pme_decompile_d2_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");

    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: true,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let _report =
        pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).expect("run_report");

    let log = read_ghidra_application_log(&out);
    assert!(
        log.contains("TameAnalysis: mode=datamark"),
        "TameAnalysis should have logged mode=datamark under --no-thumb-decompile; log tail:\n{}",
        log.lines().rev().take(40).collect::<Vec<_>>().join("\n")
    );
    assert!(
        !log.contains("TameAnalysis: mode=tighten"),
        "datamark run should NOT have logged mode=tighten; log tail:\n{}",
        log.lines().rev().take(40).collect::<Vec<_>>().join("\n")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Uniform pseudo-random blob (xorshift64*, top byte — the same generator as
/// classify.rs's cfg(test) helper, replicated here because integration tests
/// cannot reach pub(crate) cfg(test) items). 256 KiB = 4 full 64-KiB windows,
/// so every battery gate (including the window tests) engages unanimously.
fn uniform_test_blob(len: usize) -> Vec<u8> {
    struct Xorshift64Star(u64);

    impl Xorshift64Star {
        fn byte(&mut self) -> u8 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            (x.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8
        }
    }

    let mut rng = Xorshift64Star(0x9E3779B97F4A7C15);
    (0..len).map(|_| rng.byte()).collect()
}

/// Pins the opaque-skip WIRING at the real seam: `run_report` with `--run`
/// and a located Ghidra install, over a TOC whose only image is unanimously
/// opaque. The skip branch must fire before any Ghidra work, so no
/// `analyzeHeadless` process is ever spawned — observable as no `export/`
/// directory (only ExportDecomp.java creates it) and an empty
/// `ghidra_project/` (a real run writes `pixel-modem.rep` into it). If the
/// skip branch were deleted, Ghidra would import + analyze the blob and every
/// assertion below fails (outcome becomes `Analyzed(0)` with a populated
/// export/project). The battery verdict must also label the row "opaque",
/// agreeing with what manifest.json would record for the same bytes.
#[test]
fn run_report_skips_opaque_image_without_spawning_ghidra() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let dir = std::env::temp_dir().join(format!("pme_opaque_skip_wiring_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, craft_modem_bin(&uniform_test_blob(256 * 1024))).unwrap();
    let out = dir.join("out");

    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let report =
        pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).expect("run_report");

    assert_eq!(report.images.len(), 1, "the sole image must be selected");
    let image = &report.images[0];
    assert!(
        matches!(
            image.outcome,
            pixel_modem_extractor::decompile::ImageOutcome::SkippedOpaque(_)
        ),
        "uniform-blob image must be SkippedOpaque, got {:?}",
        image.outcome
    );
    assert_eq!(image.classification, Some("opaque"));

    assert!(
        !out.join("export").exists(),
        "skip must not create export/ (only ExportDecomp.java does)"
    );
    let project_entries: Vec<_> = std::fs::read_dir(out.join("ghidra_project"))
        .expect("run_report pre-creates ghidra_project")
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        project_entries.is_empty(),
        "no analyzeHeadless run may touch the project dir; found {project_entries:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
