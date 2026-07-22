//! Phase 3.0: recover global variable names from direct textual evidence
//! (assertion / log strings that mention globals by name). For each function
//! in `functions.json` + `thumb_functions.json` with exactly one non-string
//! `data_ref`, scan its string references for a unique identifier token; if
//! exactly one survives, associate it with that data_ref. Conflicts (same
//! `address`, different `name` from different functions) are dropped.
//!
//! Record-only — does NOT touch the Ghidra program. Output is
//! `images/<label>/decompiled/globals.json` per image, format v1.
//!
//! Strict-single-source-of-truth posture (Phase 1's `Tier::Recovered`
//! extended cross-function). No function-name inference, no disassembly-
//! pattern disambiguation (Phase 3.0.1 territory).

use crate::error::{Error, Result};
use crate::source_tree::extract_strings;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

/// Format string for `globals.json` v1. Future revisions add fields without
/// breaking v1 readers (forward-compat posture identical to Phase 2's
/// `thumb_functions.json` v1→v2).
pub const FORMAT_V1: &str = "pixel-modem-extractor-globals-v1";

/// Minimum identifier length. Filters out 1–2 char tokens (`id`, `pt`) that
/// are too generic to be meaningful global names.
const MIN_IDENT_LEN: usize = 3;

/// Generic identifier tokens filtered out of the candidate set. These appear
/// frequently in modem firmware strings (log macros, format specifiers,
/// C keywords) but are extremely unlikely to be global variable names.
/// Extend this set if the pre-check (Task 1) surfaces other generic tokens
/// polluting the results.
const GENERIC_TOKENS: &[&str] = &[
    "NULL", "null", "true", "false", "TRUE", "FALSE", "void", "int", "char", "long", "short",
    "unsigned", "signed", "src", "main", "include", "define", "struct", "union", "enum", "return",
    "sizeof", "static", "const", "extern", "volatile", "ERROR", "WARN", "INFO", "DEBUG", "TRACE",
    "LOG", "LOGE", "LOGW", "LOGI", "LOGD", "LOGV", "err", "error", "status", "ret", "retval",
    "result",
    // Cross-checked against `src/source_tree.rs`'s STOPLIST. Both are
    // underscoreless, so the strict-single-source-of-truth underscore filter
    // already drops them; listed explicitly to document intent and to be in
    // place if Phase 3.0.1 relaxes the underscore requirement.
    "DBT",    // debug-trace macro marker; very high frequency in modem strings
    "ASSERT", // C assert macro / log prefix; never a global variable name
];

/// The arch attribution for a global — driven by which functions contributed
/// evidence. `Mixed` when at least one ARM and one Thumb function contributed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    Arm,
    Thumb,
    Mixed,
}

/// One piece of evidence for a `(address, name)` association. Either a string
/// that mentions the name, or a function whose `data_refs` were used.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind")]
pub enum Evidence {
    /// A string at `address` whose content `value` mentions the global name.
    String { address: String, value: String },
    /// A function at `address` whose `data_refs` produced the association.
    /// `name` is the Ghidra-side `FUN_<addr>` placeholder; `recovered_name`
    /// is present (and serialized) only when Phase 1 supplied a recovered name.
    Function {
        address: String,
        arch: Arch,
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        recovered_name: Option<String>,
    },
}

/// One resolved global: a `(address, name)` pair plus its evidence trail.
#[derive(Debug, Clone, Serialize)]
pub struct Global {
    pub address: String,
    pub arch: Arch,
    pub name: String,
    /// Always `"recovered"` in Phase 3.0. Future Phase 3.0.1 may add
    /// `"provisional"` for function-name-inferred globals.
    pub tier: &'static str,
    /// Always `null` in Phase 3.0 (no type recovery yet). Surfaced as explicit
    /// null so consumers know the field exists and is intentionally absent.
    pub size: Option<usize>,
    pub evidence: Vec<Evidence>,
    /// Empty in Phase 3.0. Reserved for Phase 3.1+ annotations like
    /// `"mmio_candidate"`.
    pub annotations: Vec<String>,
}

/// Per-image outcome of the globals sweep. Returned by `run` so the caller
/// (`decompose::run`) can surface counts in `report.json`.
#[derive(Debug, Default)]
pub struct GlobalsReport {
    /// Count of `Global`s with `tier: "recovered"` written to `globals.json`.
    pub recovered_count: usize,
    /// Number of `(address, name)` associations dropped because a different
    /// name was proposed for the same address by another function. Strict-
    /// single-source-of-truth rule (Phase 1's `Tier::Recovered` extended
    /// cross-function).
    pub conflicts_dropped: usize,
}

impl GlobalsReport {
    pub fn empty() -> Self {
        Self {
            recovered_count: 0,
            conflicts_dropped: 0,
        }
    }
}

/// Phase 3.0: recover global variable names from direct textual evidence.
///
/// Reads `functions.json` + `thumb_functions.json` + `<label>.bin` from
/// `image_dir/decompiled/` and `image_dir/<label>.bin`. Writes
/// `image_dir/decompiled/globals.json` (format v1). Returns the per-image
/// outcome for surfacing in `report.json`.
///
/// `manifest` is the decompose top-level manifest (used to resolve the
/// image's load_addr for vaddr calculation). Mirrors `symbolicate::run`'s
/// signature.
///
/// `recovered_function_names` maps a function entry address (canonical:
/// lowercase hex, no `0x` prefix, no leading zeros, e.g. `"40e18dfe"`) to
/// Phase 1's recovered name. Pass an empty map when Phase 1 cross-reference
/// is unavailable; the resulting globals will simply have
/// `evidence[].recovered_name` absent.
///
/// Strict-single-source-of-truth: only functions with exactly one non-string
/// `data_ref` AND exactly one unique underscored identifier across their
/// string refs produce associations. Conflicts (same `address`, different
/// `name` from different functions) are dropped.
pub fn run(
    image_dir: &Path,
    image_label: &str,
    manifest: &Path,
    recovered_function_names: &HashMap<String, String>,
) -> Result<GlobalsReport> {
    let decompiled = image_dir.join("decompiled");

    // 1. Resolve the image's load_addr from the manifest.
    let toc_name = toc_name(image_label);
    let load_addr = load_load_addr(manifest, &toc_name)?.ok_or_else(|| {
        Error::Serialize(format!(
            "globals: load_addr missing for {image_label} (toc name {toc_name})"
        ))
    })?;

    // 2. Read the raw image bytes (for string extraction). Missing .bin is
    //    treated as an empty image — string_map ends up empty, so the
    //    unique-identifier rule can't match and we return 0 (defensive path).
    let bin_path = image_dir.join(format!("{image_label}.bin"));
    let image_bytes = std::fs::read(&bin_path).unwrap_or_default();

    // 3. Build string_map: {vaddr -> string_content}.
    let mut string_map: HashMap<u64, String> = HashMap::new();
    for (off, s) in extract_strings(&image_bytes, 3) {
        let vaddr = load_addr.wrapping_add(off as u64);
        string_map.insert(vaddr, String::from_utf8_lossy(s).to_string());
    }

    // 4. Read functions.json + thumb_functions.json into a unified list,
    //    enriching each Function's recovered_name from the cross-reference map.
    let mut all_funcs: Vec<Function> = Vec::new();

    let arm_path = decompiled.join("functions.json");
    if arm_path.exists() {
        let arm_text = std::fs::read_to_string(&arm_path)?;
        let arm_v: serde_json::Value = serde_json::from_str(&arm_text)
            .map_err(|e| Error::Serialize(format!("parse functions.json: {e}")))?;
        if let Some(arr) = arm_v.as_array() {
            for f in arr {
                if let Some(parsed) = parse_function(f, Arch::Arm, recovered_function_names) {
                    all_funcs.push(parsed);
                }
            }
        }
    }

    let thumb_path = decompiled.join("thumb_functions.json");
    if thumb_path.exists() {
        let thumb_text = std::fs::read_to_string(&thumb_path)?;
        let thumb_v: serde_json::Value = serde_json::from_str(&thumb_text)
            .map_err(|e| Error::Serialize(format!("parse thumb_functions.json: {e}")))?;
        if let Some(arr) = thumb_v.get("functions").and_then(|f| f.as_array()) {
            for f in arr {
                if let Some(parsed) = parse_function(f, Arch::Thumb, recovered_function_names) {
                    all_funcs.push(parsed);
                }
            }
        }
    }

    // 5. Apply the strict algorithm: per function, collect (addr, name)
    //    associations. Multiple functions reinforcing the same (addr, name)
    //    is fine; conflicts (same addr, different names) are dropped.
    //
    //    Phase 3.0 strict-single-source-of-truth: require at least one
    //    underscore in the identifier. Real modem-firmware globals are
    //    conventionally g_/m_/s_/Asn_-prefixed (Hungarian-ish);
    //    underscoreless CamelCase (fooBar) is rare in this firmware and
    //    Phase 3.0.1 can relax this if coverage is too low.
    let ident_re = regex::Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]{2,}$").unwrap();
    let generic: BTreeSet<&str> = GENERIC_TOKENS.iter().copied().collect();

    // addr -> (name -> Vec<Function>) — tracks which functions proposed which
    // name for each address.
    let mut addr_to_proposals: HashMap<u64, HashMap<String, Vec<Function>>> = HashMap::new();

    for f in &all_funcs {
        // Filter data_refs: candidate_refs are non-string refs that fall
        // inside the image (>= load_addr). Sub-load-addr refs are out-of-image
        // noise (Ghidra occasionally emits linker/relocation artifacts as
        // small integers) and would inflate candidate counts, blocking
        // otherwise-clean recoveries.
        let candidate_refs: Vec<u64> = f
            .data_refs
            .iter()
            .copied()
            .filter(|a| !string_map.contains_key(a))
            .filter(|a| *a >= load_addr)
            .collect();
        if candidate_refs.len() != 1 {
            continue;
        }
        let global_addr = candidate_refs[0];

        // Collect identifier tokens across all string_refs.
        let mut unique_idents: BTreeSet<String> = BTreeSet::new();
        for s_addr in &f.data_refs {
            if let Some(s) = string_map.get(s_addr) {
                for token in s.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                    if token.len() >= MIN_IDENT_LEN
                        && token.contains('_')
                        && ident_re.is_match(token)
                        && !generic.contains(token)
                    {
                        unique_idents.insert(token.to_string());
                    }
                }
            }
        }
        if unique_idents.len() != 1 {
            continue;
        }
        let name = unique_idents.into_iter().next().unwrap();

        addr_to_proposals
            .entry(global_addr)
            .or_default()
            .entry(name)
            .or_default()
            .push(f.clone());
    }

    // 6. Build the output: one entry per (addr, name) where the addr had
    //    exactly one distinct name proposed.
    let mut globals: Vec<Global> = Vec::new();
    let mut conflicts_dropped = 0usize;
    // Iterate by ascending addr for deterministic output ordering.
    let mut sorted_addrs: Vec<u64> = addr_to_proposals.keys().copied().collect();
    sorted_addrs.sort_unstable();
    for addr in sorted_addrs {
        let proposals = addr_to_proposals.remove(&addr).unwrap();
        if proposals.len() != 1 {
            // Conflict: multiple distinct names proposed for the same addr.
            conflicts_dropped += 1;
            continue;
        }
        let (name, mut functions) = proposals.into_iter().next().unwrap();
        // Sort evidence by function address ascending.
        functions.sort_by_key(|f| f.entry);
        // Compute arch attribution.
        let has_arm = functions.iter().any(|f| f.arch == Arch::Arm);
        let has_thumb = functions.iter().any(|f| f.arch == Arch::Thumb);
        let arch = match (has_arm, has_thumb) {
            (true, true) => Arch::Mixed,
            (true, false) => Arch::Arm,
            (false, true) => Arch::Thumb,
            (false, false) => unreachable!("no contributing functions"),
        };
        // One Evidence::Function per contributing function (Phase 3.0 surfaces
        // the function-side audit trail; the String evidence variant is
        // reserved for Phase 3.0.1+ use).
        let evidence: Vec<Evidence> = functions
            .iter()
            .map(|f| Evidence::Function {
                address: format!("0x{:x}", f.entry),
                arch: f.arch,
                name: f.ghidra_name.clone(),
                recovered_name: f.recovered_name.clone(),
            })
            .collect();

        globals.push(Global {
            address: format!("0x{addr:x}"),
            arch,
            name: name.clone(),
            tier: "recovered",
            size: None,
            evidence,
            annotations: Vec::new(),
        });
    }

    let recovered_count = globals.len();

    // 7. Write globals.json. Atomicity: serialize to a String first, then
    //    write. A serialize failure leaves the on-disk file untouched.
    let wrapped = serde_json::json!({
        "format": FORMAT_V1,
        "image": image_label,
        "globals": globals,
    });
    let out = serde_json::to_string_pretty(&wrapped)
        .map_err(|e| Error::Serialize(format!("re-serialize globals.json: {e}")))?;
    std::fs::write(decompiled.join("globals.json"), out)?;

    Ok(GlobalsReport {
        recovered_count,
        conflicts_dropped,
    })
}

/// One unified function record (ARM + Thumb). Internal to the algorithm.
#[derive(Debug, Clone)]
struct Function {
    entry: u64,
    arch: Arch,
    ghidra_name: String,
    recovered_name: Option<String>,
    data_refs: Vec<u64>,
}

/// Parse one entry from `functions.json` or `thumb_functions.json` into a
/// unified `Function`. Returns None on missing required fields (silently
/// skipped — same posture as Phase 1's symbolicate loaders).
/// `recovered_function_names` enriches `Function.recovered_name` if Phase 1
/// supplied a name for this function's entry address.
fn parse_function(
    v: &serde_json::Value,
    arch: Arch,
    recovered_function_names: &HashMap<String, String>,
) -> Option<Function> {
    let entry = v
        .get("entry")
        .and_then(|e| e.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())?;
    let ghidra_name = v
        .get("name")
        .and_then(|n| n.as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("FUN_{entry:x}"));
    let data_refs: Vec<u64> = v
        .get("data_refs")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| r.as_str())
                .filter_map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .collect()
        })
        .unwrap_or_default();
    let canonical = format!("{entry:x}");
    let recovered_name = recovered_function_names.get(&canonical).cloned();
    Some(Function {
        entry,
        arch,
        ghidra_name,
        recovered_name,
        data_refs,
    })
}

/// TOC image name for a decompose label, e.g. "02_MAIN" -> "MAIN".
/// Mirrors `symbolicate::toc_name`.
fn toc_name(label: &str) -> String {
    label
        .split_once('_')
        .map(|(_, n)| n)
        .unwrap_or(label)
        .to_string()
}

/// Resolve the image's load_addr from the decompose manifest. Mirrors
/// `symbolicate::load_load_addr` — read the JSON, find the matching image
/// entry, parse its `load_addr` as hex.
fn load_load_addr(manifest: &Path, toc_name: &str) -> Result<Option<u64>> {
    let bytes = std::fs::read(manifest)?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Serialize(format!("parse manifest: {e}")))?;
    let Some(images) = v.get("images").and_then(|i| i.as_array()) else {
        return Ok(None);
    };
    for img in images {
        let name = img.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if name == toc_name
            && let Some(addr_str) = img.get("load_addr").and_then(|a| a.as_str())
        {
            let addr = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16)
                .map_err(|e| Error::Serialize(format!("parse load_addr: {e}")))?;
            return Ok(Some(addr));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;

    fn tmp_root(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("pme_globals_{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// Build a minimal image_dir with decompiled/functions.json +
    /// thumb_functions.json + <label>.bin + manifest.json, for the algorithm
    /// to read. Each helper below sets up the specific shape its test needs.
    struct Img {
        root: PathBuf,
        label: String,
    }
    impl Img {
        fn new(name: &str) -> Self {
            let root = tmp_root(name);
            let label = "02_MAIN".to_string();
            // Per decompose layout, the algorithm reads
            // `<image_dir>/decompiled/functions.json` where `image_dir` is
            // `<root>/<label>`. So the decompiled dir hangs off the label dir.
            fs::create_dir_all(root.join(&label).join("decompiled")).unwrap();
            // Minimal manifest at the root level.
            fs::write(
                root.join("manifest.json"),
                r#"{"images":[{"name":"MAIN","load_addr":"0x1000"}]}"#,
            )
            .unwrap();
            Self { root, label }
        }
        fn image_dir(&self) -> PathBuf {
            self.root.join(&self.label)
        }
        fn label(&self) -> &str {
            &self.label
        }
        fn manifest(&self) -> PathBuf {
            self.root.join("manifest.json")
        }
        fn write_functions_json(&self, json: &str) {
            fs::write(
                self.image_dir().join("decompiled").join("functions.json"),
                json,
            )
            .unwrap();
        }
        fn write_thumb_functions_json(&self, json: &str) {
            fs::write(
                self.image_dir()
                    .join("decompiled")
                    .join("thumb_functions.json"),
                json,
            )
            .unwrap();
        }
        fn write_image_bin(&self, bytes: &[u8]) {
            // Image file is at <image_dir>/<label>.bin per decompose layout.
            fs::write(self.image_dir().join(format!("{}.bin", self.label)), bytes).unwrap();
        }
        fn write_manifest_load_addr(&self, load_addr: &str) {
            fs::write(
                self.root.join("manifest.json"),
                format!(r#"{{"images":[{{"name":"MAIN","load_addr":"{load_addr}"}}]}}"#),
            )
            .unwrap();
        }
    }

    /// Helper: build a minimal image whose raw bytes contain the strings at
    /// known vaddrs. Strings live at offset (vaddr - load_addr) in the .bin.
    fn image_with_strings(load_addr: u64, strings: &[(u64, &str)]) -> Vec<u8> {
        let max_end = strings
            .iter()
            .map(|(addr, s)| *addr as usize - load_addr as usize + s.len())
            .max()
            .unwrap_or(0)
            .max(1);
        let mut buf = vec![0u8; max_end + 1];
        for (addr, s) in strings {
            let off = *addr as usize - load_addr as usize;
            buf[off..off + s.len()].copy_from_slice(s.as_bytes());
        }
        buf
    }

    fn make_arm_function(entry: u64, data_refs: &[u64]) -> serde_json::Value {
        let refs: Vec<String> = data_refs.iter().map(|a| format!("0x{a:x}")).collect();
        serde_json::json!({
            "name": format!("FUN_{entry:x}"),
            "entry": format!("0x{entry:x}"),
            "end": format!("0x{:x}", entry + 0x10),
            "size": 16,
            "data_refs": refs,
        })
    }

    fn make_thumb_function(entry: u64, data_refs: &[u64]) -> serde_json::Value {
        let refs: Vec<String> = data_refs.iter().map(|a| format!("0x{a:x}")).collect();
        serde_json::json!({
            "entry": format!("0x{entry:x}"),
            "name": format!("thumb_{entry:x}"),
            "size": 8,
            "body_kind": "thumb_disassembly",
            "body": "b5 80 00 20 80 bd",
            "data_refs": refs,
        })
    }

    /// Convenience: call `run` with an empty recovered_function_names map.
    /// (Task 4's tests don't exercise recovered_name enrichment — that's
    /// the decompose stage's responsibility via Task 5's symbols.json loader.)
    fn run_no_names(img: &Img) -> Result<GlobalsReport> {
        let empty = HashMap::new();
        run(&img.image_dir(), img.label(), &img.manifest(), &empty)
    }

    #[test]
    fn recovers_name_when_function_has_single_global_and_unique_identifier() {
        let img = Img::new("happy_path");
        // Function at 0x2000 references: a string at 0x3000 ("g_foo invalid"),
        // and a non-string data_ref at 0x4000 (the global).
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        // Image has the string at vaddr 0x3000; offset 0x3000 - 0x1000 = 0x2000.
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(0x1000, &[(0x3000, "g_foo invalid")]));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);
        assert_eq!(report.conflicts_dropped, 0);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["format"], FORMAT_V1);
        assert_eq!(v["globals"].as_array().unwrap().len(), 1);
        assert_eq!(v["globals"][0]["address"], "0x4000");
        assert_eq!(v["globals"][0]["name"], "g_foo");
        assert_eq!(v["globals"][0]["tier"], "recovered");
        assert_eq!(v["globals"][0]["arch"], "arm");
        assert!(v["globals"][0]["size"].is_null());
        assert_eq!(v["globals"][0]["evidence"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn skips_function_with_multiple_global_candidates() {
        let img = Img::new("multi_global");
        // Two non-string data_refs → ambiguous, skip.
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000, 0x5000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(0x1000, &[(0x3000, "g_foo invalid")]));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 0);
    }

    #[test]
    fn skips_function_with_multiple_identifier_candidates() {
        let img = Img::new("multi_ident");
        // One non-string data_ref, but two distinct identifiers in the strings.
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x3100, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(
            0x1000,
            &[(0x3000, "g_foo invalid"), (0x3100, "g_bar also bad")],
        ));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 0);
    }

    #[test]
    fn drops_conflicting_assignments_same_addr_different_names() {
        let img = Img::new("conflict");
        // Two functions associate different names with addr 0x4000.
        img.write_functions_json(&format!(
            "[{},{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000]), // string "g_foo" → 0x4000
            make_arm_function(0x2100, &[0x3100, 0x4000]), // string "g_bar" → 0x4000
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(
            0x1000,
            &[(0x3000, "g_foo invalid"), (0x3100, "g_bar invalid")],
        ));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 0);
        assert_eq!(report.conflicts_dropped, 1);
    }

    #[test]
    fn reinforces_same_assignment_across_functions() {
        let img = Img::new("reinforce");
        // Two functions associate the SAME name with addr 0x4000.
        img.write_functions_json(&format!(
            "[{},{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000]),
            make_arm_function(0x2100, &[0x3100, 0x4000]),
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(
            0x1000,
            &[(0x3000, "g_foo invalid"), (0x3100, "g_foo also")],
        ));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);
        assert_eq!(report.conflicts_dropped, 0);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        // One entry, two evidence paths.
        assert_eq!(v["globals"].as_array().unwrap().len(), 1);
        assert_eq!(v["globals"][0]["evidence"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn filters_generic_identifiers() {
        let img = Img::new("generic");
        // The only identifier is "NULL" — filtered out by GENERIC_TOKENS.
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(0x1000, &[(0x3000, "NULL is bad")]));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 0);
    }

    #[test]
    fn emits_empty_globals_json_when_nothing_recovers() {
        let img = Img::new("empty");
        // No functions at all → 0 globals. globals.json must still be written.
        img.write_functions_json("[]");
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&[0u8; 16]);

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 0);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["format"], FORMAT_V1);
        assert!(v["globals"].as_array().unwrap().is_empty());
    }

    #[test]
    fn handles_arch_attribute_arm_thumb_mixed() {
        let img = Img::new("arch_mixed");
        // ARM function + Thumb function, same name + addr → arch: mixed.
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000])
        ));
        img.write_thumb_functions_json(&format!(
            r#"{{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[{}]}}"#,
            make_thumb_function(0x2100, &[0x3100, 0x4000])
        ));
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(
            0x1000,
            &[(0x3000, "g_foo invalid"), (0x3100, "g_foo also")],
        ));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["globals"][0]["arch"], "mixed");
    }

    #[test]
    fn evidence_ordered_deterministically_by_function_address() {
        let img = Img::new("ordering");
        // Two functions at 0x2100 and 0x2000 — evidence should sort ascending.
        img.write_functions_json(&format!(
            "[{},{}]",
            make_arm_function(0x2100, &[0x3000, 0x4000]),
            make_arm_function(0x2000, &[0x3100, 0x4000]),
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(
            0x1000,
            &[(0x3000, "g_foo first"), (0x3100, "g_foo second")],
        ));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        let ev = v["globals"][0]["evidence"].as_array().unwrap();
        assert_eq!(ev.len(), 2);
        // First evidence's function address should be the lower one.
        // Both evidence entries are tagged `kind: function` per the algorithm;
        // within them, the function address appears. Find the Function variant.
        let fn_addrs: Vec<&str> = ev
            .iter()
            .filter_map(|e| e.get("address").and_then(|a| a.as_str()))
            .collect();
        assert_eq!(fn_addrs, vec!["0x2000", "0x2100"]);
    }

    #[test]
    fn passes_through_image_without_raw_bytes_returns_ok_zero() {
        let img = Img::new("no_bin");
        // No <label>.bin file — defensive path. Algorithm should treat all
        // data_refs as non-string (since string_map is empty) and process
        // normally; but with no strings, the unique-identifier rule won't
        // match, returning 0. Either way: no panic.
        img.write_functions_json(&format!("[{}]", make_arm_function(0x2000, &[0x4000])));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        // Note: no write_image_bin call.

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 0);
    }

    #[test]
    fn drops_candidate_refs_below_load_addr() {
        let img = Img::new("sub_load_addr");
        // Function at 0x2000 with three data_refs: a sub-load-addr noise ref
        // (0x500), a string ref (0x3000), and the actual global (0x4000).
        // Without the range filter, candidate_refs would be [0x500, 0x4000]
        // (len 2) → ambiguous, skip. With the range filter, 0x500 is dropped
        // as out-of-image noise → candidate_refs = [0x4000] → recover.
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x500, 0x3000, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(0x1000, &[(0x3000, "g_foo invalid")]));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);
        assert_eq!(report.conflicts_dropped, 0);
    }
}
