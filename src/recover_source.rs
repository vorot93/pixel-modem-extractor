use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opts {
    pub inline_bodies: bool,
    pub proximity_window: usize,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            inline_bodies: true,
            proximity_window: 4096,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceOccurrence {
    pub vaddr: u64,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEntry {
    pub path: String,
    pub leaf: PathBuf,
    pub occurrences: Vec<SourceOccurrence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceTreeIndex {
    pub root: PathBuf,
    pub entries: Vec<SourceEntry>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    files: BTreeMap<String, ManifestFile>,
}

#[derive(Debug, Deserialize)]
struct ManifestFile {
    #[serde(default)]
    occurrences: Vec<ManifestOccurrence>,
}

#[derive(Debug, Deserialize)]
struct ManifestOccurrence {
    vaddr: String,
    offset: usize,
}

fn parse_hex_addr(s: &str) -> Result<u64> {
    let trimmed = s.trim();
    let trimmed = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u64::from_str_radix(trimmed, 16)
        .map_err(|e| Error::Serialize(format!("bad hex address {s}: {e}")))
}

fn source_dir_set(files: &BTreeMap<String, ManifestFile>) -> HashSet<String> {
    let mut dir_set = HashSet::new();
    for path in files.keys() {
        let parts: Vec<&str> = path.split('/').collect();
        for k in 1..parts.len() {
            dir_set.insert(parts[..k].join("/"));
        }
    }
    dir_set
}

fn guard_long(rel: &str) -> String {
    rel.split('/')
        .map(|seg| {
            if seg.chars().count() > 200 {
                let h = seg
                    .bytes()
                    .fold(0u32, |a, b| a.wrapping_mul(31).wrapping_add(b as u32));
                let prefix: String = seg.chars().take(180).collect();
                format!("{prefix}~{h:08x}")
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn finalize_rel(
    rel: &str,
    dir_set: &HashSet<String>,
    used_lower: &mut HashMap<String, usize>,
) -> String {
    let mut rel = if dir_set.contains(rel) {
        format!("{rel}.node")
    } else {
        rel.to_string()
    };
    rel = guard_long(&rel);
    let low = rel.to_lowercase();
    if used_lower.contains_key(&low) {
        let (base, ext) = match rel.rsplit_once('.') {
            Some((b, e)) => (b.to_string(), Some(e.to_string())),
            None => (rel.clone(), None),
        };
        let mut n = used_lower[&low];
        loop {
            n += 1;
            let cand = match &ext {
                Some(e) => format!("{base}~{n}.{e}"),
                None => format!("{rel}~{n}"),
            };
            if !used_lower.contains_key(&cand.to_lowercase()) {
                used_lower.insert(low.clone(), n);
                used_lower.insert(cand.to_lowercase(), 0);
                rel = cand;
                break;
            }
        }
    } else {
        used_lower.insert(low, 0);
    }
    rel
}

impl SourceTreeIndex {
    pub fn load(root: &Path) -> Result<Self> {
        let bytes = std::fs::read(root.join("manifest.json"))?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|e| Error::Serialize(e.to_string()))?;
        let dir_set = source_dir_set(&manifest.files);
        let mut used_lower = HashMap::new();
        let mut entries = Vec::new();
        for (path, file) in manifest.files {
            let occurrences = file
                .occurrences
                .into_iter()
                .map(|o| {
                    Ok(SourceOccurrence {
                        vaddr: parse_hex_addr(&o.vaddr)?,
                        offset: o.offset,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let leaf_rel = finalize_rel(&path, &dir_set, &mut used_lower);
            entries.push(SourceEntry {
                leaf: root.join("tree").join(leaf_rel),
                path,
                occurrences,
            });
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(Self {
            root: root.to_path_buf(),
            entries,
        })
    }
}

pub use crate::analysis_tool::AnalysisTool as Tool;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveredFunction {
    pub tool: Tool,
    pub name: String,
    pub entry: u64,
    pub end: u64,
    pub decode_ranges: Option<Vec<(u64, u64)>>,
    pub size: u64,
    pub body_kind: String,
    pub body: String,
    pub source_artifact: String,
    pub data_refs: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Direct,
    Proximity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Attribution {
    pub function: RecoveredFunction,
    pub confidence: Confidence,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AmbiguousAttribution {
    pub function: RecoveredFunction,
    pub confidence: Confidence,
    pub reason: String,
    pub candidate_source_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AttributionResult {
    attrs: BTreeMap<String, Vec<Attribution>>,
    ambiguous: Vec<AmbiguousAttribution>,
}

#[derive(Debug, Serialize)]
struct IndexFunction {
    tool: Tool,
    name: String,
    entry: String,
    end: String,
    size: u64,
    body_kind: String,
    source_artifact: String,
    data_refs: Vec<String>,
}

#[derive(Debug, Serialize)]
struct IndexAttribution {
    tool: Tool,
    name: String,
    entry: String,
    end: String,
    confidence: Confidence,
    reason: String,
    source_artifact: String,
}

#[derive(Debug, Serialize)]
struct IndexAmbiguousAttribution {
    tool: Tool,
    name: String,
    entry: String,
    end: String,
    confidence: Confidence,
    reason: String,
    source_artifact: String,
    candidate_source_paths: Vec<String>,
}

#[derive(Debug, Serialize)]
struct IndexSource {
    leaf: String,
    functions: Vec<IndexAttribution>,
}

#[derive(Debug, Serialize)]
struct SkippedCounts {
    function_entries: usize,
}

#[derive(Debug, Serialize)]
struct RecoveredIndex {
    attribution: String,
    sources: BTreeMap<String, IndexSource>,
    functions: Vec<IndexFunction>,
    ambiguous: Vec<IndexAmbiguousAttribution>,
    skipped: SkippedCounts,
}

fn hx(v: u64) -> String {
    format!("0x{v:x}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredFunctions {
    pub functions: Vec<RecoveredFunction>,
    pub skipped: usize,
}

#[derive(Debug, Deserialize)]
struct GhidraFunctionJson {
    name: String,
    entry: String,
    #[serde(default)]
    end: Option<String>,
    size: u64,
    #[serde(default)]
    data_refs: Vec<String>,
}

fn parse_decompiled_header(line: &str) -> Option<u64> {
    let rest = line.strip_prefix("// ")?;
    let (_, addr) = rest.rsplit_once(" @ ")?;
    parse_hex_addr(addr.trim()).ok()
}

fn parse_decompiled_bodies(text: &str) -> HashMap<u64, String> {
    let mut bodies = HashMap::new();
    let mut current_entry: Option<u64> = None;
    let mut current = String::new();

    for line in text.lines() {
        if let Some(entry) = parse_decompiled_header(line)
            && let Some(previous) = current_entry.replace(entry)
        {
            bodies.insert(previous, current.trim_end().to_string());
            current.clear();
        }

        if current_entry.is_some() {
            current.push_str(line);
            current.push('\n');
        }
    }

    if let Some(entry) = current_entry {
        bodies.insert(entry, current.trim_end().to_string());
    }

    bodies
}

fn is_meaningful_ghidra_body_line(line: &str) -> bool {
    const FAILED_DECOMPILATION_SENTINEL: &str = "// <decompilation failed>";

    let trimmed = line.trim();
    !trimmed.is_empty()
        && parse_decompiled_header(trimmed).is_none()
        && trimmed != FAILED_DECOMPILATION_SENTINEL
}

fn parse_data_refs(raw: &[String]) -> Result<Vec<u64>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for r in raw {
        let addr = parse_hex_addr(r)?;
        if seen.insert(addr) {
            out.push(addr);
        }
    }
    Ok(out)
}

impl RecoveredFunctions {
    pub fn load(dir: &Path) -> Result<Self> {
        let ghidra_reader =
            std::io::BufReader::new(std::fs::File::open(dir.join("functions.json"))?);
        let bodies = parse_decompiled_bodies(&std::fs::read_to_string(dir.join("decompiled.c"))?);
        let mut skipped = 0usize;
        let mut functions = Vec::new();

        let ghidra_file: Vec<GhidraFunctionJson> = serde_json::from_reader(ghidra_reader)
            .map_err(|e| Error::Serialize(format!("functions.json: {e}")))?;
        for f in ghidra_file {
            let Some(function) = recovered_ghidra_function(f, &bodies) else {
                skipped += 1;
                continue;
            };
            functions.push(function);
        }

        let thumb_path = dir.join("thumb_functions.json");
        if thumb_path.exists() {
            // Typed streaming load retains only consumer fields and function
            // bodies while strict v3 metadata resolves each run owner. It never
            // builds the former document-wide `serde_json::Value` tree.
            for owned in crate::thumb_analysis::read_thumb_functions_streaming(&thumb_path)? {
                let Some(function) = recovered_thumb_function(
                    owned.function,
                    owned.producer.into(),
                    owned.legacy_range_semantics,
                ) else {
                    skipped += 1;
                    continue;
                };
                functions.push(function);
            }
        }

        Ok(Self { functions, skipped })
    }
}

fn recovered_ghidra_function(
    f: GhidraFunctionJson,
    bodies: &HashMap<u64, String>,
) -> Option<RecoveredFunction> {
    let entry = parse_hex_addr(&f.entry).ok()?;
    let end = match f.end.as_deref() {
        Some(raw) => parse_hex_addr(raw).ok()?,
        None => entry.saturating_add(f.size),
    };
    let data_refs = parse_data_refs(&f.data_refs).ok()?;
    let body = bodies.get(&entry)?.clone();
    if !body.lines().any(is_meaningful_ghidra_body_line) {
        return None;
    }

    Some(RecoveredFunction {
        tool: Tool::Ghidra,
        name: f.name,
        entry,
        end,
        decode_ranges: None,
        size: f.size,
        body_kind: "decompiled_c".to_string(),
        body,
        source_artifact: "decompiled.c".to_string(),
        data_refs,
    })
}

fn recovered_thumb_function(
    f: crate::thumb_analysis::ThumbFunctionRecord,
    tool: Tool,
    legacy_range_semantics: bool,
) -> Option<RecoveredFunction> {
    let entry = parse_hex_addr(&f.entry).ok()?;
    let end = parse_hex_addr(&f.end).ok()?;
    let data_refs = parse_data_refs(&f.data_refs).ok()?;
    let decode_ranges = if legacy_range_semantics {
        None
    } else {
        Some(
            f.decode_ranges
                .iter()
                .map(|range| Ok((parse_hex_addr(&range.start)?, parse_hex_addr(&range.end)?)))
                .collect::<Result<Vec<_>>>()
                .ok()?,
        )
    };

    Some(RecoveredFunction {
        tool,
        name: f.name,
        entry,
        end,
        decode_ranges,
        size: f.size,
        body_kind: f.body_kind,
        body: f.body,
        source_artifact: "thumb_functions.json".to_string(),
        data_refs,
    })
}

fn direct_match(source: &SourceEntry, function: &RecoveredFunction) -> Option<String> {
    source.occurrences.iter().find_map(|occ| {
        function.data_refs.contains(&occ.vaddr).then(|| {
            format!(
                "function references source-path string at 0x{:x}",
                occ.vaddr
            )
        })
    })
}

fn range_match(source: &SourceEntry, function: &RecoveredFunction) -> Option<String> {
    source.occurrences.iter().find_map(|occ| {
        let matching_range = match &function.decode_ranges {
            Some(ranges) => ranges
                .iter()
                .copied()
                .find(|(start, end)| occ.vaddr >= *start && occ.vaddr < *end),
            None => (occ.vaddr >= function.entry && occ.vaddr < function.end)
                .then_some((function.entry, function.end)),
        };
        matching_range.map(|(start, end)| {
            format!(
                "function range 0x{:x}-0x{:x} contains source-path string at 0x{:x}",
                start, end, occ.vaddr
            )
        })
    })
}

fn cluster_match(
    source: &SourceEntry,
    function: &RecoveredFunction,
    window: usize,
) -> Option<String> {
    let window = window as u64;
    source.occurrences.iter().find_map(|occ| {
        let upper = occ.vaddr.saturating_add(window);
        function.data_refs.iter().find_map(|data_ref| {
            (*data_ref > occ.vaddr && *data_ref <= upper).then(|| {
                format!(
                    "function references bounded string cluster near source-path string at 0x{:x}",
                    occ.vaddr
                )
            })
        })
    })
}

pub fn attribute(
    sources: &[SourceEntry],
    functions: &[RecoveredFunction],
    opts: &Opts,
) -> BTreeMap<String, Vec<Attribution>> {
    attribute_with_ambiguity(sources, functions, opts).attrs
}

fn attribute_with_ambiguity(
    sources: &[SourceEntry],
    functions: &[RecoveredFunction],
    opts: &Opts,
) -> AttributionResult {
    let mut out: BTreeMap<String, Vec<Attribution>> = BTreeMap::new();
    let mut direct_function_indexes = HashSet::new();
    let mut ambiguous = Vec::new();

    for (function_idx, function) in functions.iter().enumerate() {
        let mut direct_claims = BTreeMap::new();
        for source in sources {
            if let Some(reason) = direct_match(source, function) {
                direct_claims.insert(
                    source.path.clone(),
                    Attribution {
                        function: function.clone(),
                        confidence: Confidence::Direct,
                        reason,
                    },
                );
            }
        }

        match direct_claims.len() {
            0 => {}
            1 => {
                let (path, attribution) = direct_claims.into_iter().next().expect("claim exists");
                out.entry(path).or_default().push(attribution);
                direct_function_indexes.insert(function_idx);
            }
            _ => {
                let candidate_source_paths = direct_claims.into_keys().collect();
                ambiguous.push(AmbiguousAttribution {
                    function: function.clone(),
                    confidence: Confidence::Direct,
                    reason: "multiple direct source-path claims".to_string(),
                    candidate_source_paths,
                });
                direct_function_indexes.insert(function_idx);
            }
        }
    }

    let mut proximity_claims: BTreeMap<usize, Vec<(String, Attribution)>> = BTreeMap::new();
    for (function_idx, function) in functions.iter().enumerate() {
        if direct_function_indexes.contains(&function_idx) {
            continue;
        }

        for source in sources {
            let reason = range_match(source, function)
                .or_else(|| cluster_match(source, function, opts.proximity_window));
            if let Some(reason) = reason {
                proximity_claims.entry(function_idx).or_default().push((
                    source.path.clone(),
                    Attribution {
                        function: function.clone(),
                        confidence: Confidence::Proximity,
                        reason,
                    },
                ));
            }
        }
    }

    for (_, claims) in proximity_claims {
        if claims.len() != 1 {
            continue;
        }
        let (path, attribution) = claims.into_iter().next().expect("claim exists");
        out.entry(path).or_default().push(attribution);
    }

    for hits in out.values_mut() {
        hits.sort_by(|a, b| {
            a.function
                .entry
                .cmp(&b.function.entry)
                .then_with(|| a.function.name.cmp(&b.function.name))
        });
    }

    ambiguous.sort_by(|a, b| {
        a.function
            .entry
            .cmp(&b.function.entry)
            .then_with(|| a.function.name.cmp(&b.function.name))
    });

    AttributionResult {
        attrs: out,
        ambiguous,
    }
}

fn format_recovered_section(attrs: &[Attribution], inline_bodies: bool) -> String {
    if attrs.is_empty() {
        return "\n// Recovered code evidence:\n//   no recovered function body was attributed to this source path.\n".to_string();
    }

    let mut out = String::new();
    out.push_str("\n// Recovered code evidence:\n");
    out.push_str("//   attribution: moderate\n");
    out.push_str(&format!("//   functions: {}\n", attrs.len()));
    for (idx, attr) in attrs.iter().enumerate() {
        out.push_str(&format!(
            "\n// --- recovered function {}/{} ---\n",
            idx + 1,
            attrs.len()
        ));
        out.push_str(&format!("// tool       : {:?}\n", attr.function.tool).to_lowercase());
        out.push_str(&format!("// confidence : {:?}\n", attr.confidence).to_lowercase());
        out.push_str(&format!("// reason     : {}\n", attr.reason));
        out.push_str(&format!("// entry      : {}\n", hx(attr.function.entry)));
        out.push_str(&format!(
            "// range      : {}..{}\n",
            hx(attr.function.entry),
            hx(attr.function.end)
        ));
        out.push_str(&format!(
            "// artifact   : {}\n//\n",
            attr.function.source_artifact
        ));
        if inline_bodies {
            if attr.function.body_kind == "thumb_disassembly" {
                out.push_str("// Thumb disassembly:\n");
            }
            out.push_str(&attr.function.body);
            if !attr.function.body.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    out
}

fn rewrite_leaf(path: &Path, attrs: &[Attribution], opts: &Opts) -> Result<()> {
    let original = std::fs::read_to_string(path)?;
    // Idempotent: strip any previously-appended `// Recovered code evidence:` block
    // before re-appending, so re-running `recover_source` (or any caller that doesn't
    // wipe `tree/` first) does not double-, triple-, … -append the same section. Same
    // model as `symbolicate::rewrite_text`'s sentinel.
    const MARKER: &str = "\n// Recovered code evidence:\n";
    let base = match original.find(MARKER) {
        Some(i) => original[..i].to_string(),
        None => original,
    };
    let mut enriched = base;
    if !enriched.ends_with('\n') {
        enriched.push('\n');
    }
    enriched.push_str(&format_recovered_section(attrs, opts.inline_bodies));
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("leaf")
    ));
    std::fs::write(&tmp, &enriched)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

fn build_index(
    source_tree: &SourceTreeIndex,
    recovered: &RecoveredFunctions,
    attrs: &BTreeMap<String, Vec<Attribution>>,
    ambiguous: &[AmbiguousAttribution],
) -> RecoveredIndex {
    let functions = recovered
        .functions
        .iter()
        .map(|f| IndexFunction {
            tool: f.tool,
            name: f.name.clone(),
            entry: hx(f.entry),
            end: hx(f.end),
            size: f.size,
            body_kind: f.body_kind.clone(),
            source_artifact: f.source_artifact.clone(),
            data_refs: f.data_refs.iter().map(|r| hx(*r)).collect(),
        })
        .collect();
    let mut sources = BTreeMap::new();
    for source in &source_tree.entries {
        let items = attrs.get(&source.path).cloned().unwrap_or_default();
        sources.insert(
            source.path.clone(),
            IndexSource {
                leaf: source
                    .leaf
                    .strip_prefix(&source_tree.root)
                    .unwrap_or(&source.leaf)
                    .display()
                    .to_string(),
                functions: items
                    .into_iter()
                    .map(|a| IndexAttribution {
                        tool: a.function.tool,
                        name: a.function.name,
                        entry: hx(a.function.entry),
                        end: hx(a.function.end),
                        confidence: a.confidence,
                        reason: a.reason,
                        source_artifact: a.function.source_artifact,
                    })
                    .collect(),
            },
        );
    }
    let ambiguous = ambiguous
        .iter()
        .map(|a| IndexAmbiguousAttribution {
            tool: a.function.tool,
            name: a.function.name.clone(),
            entry: hx(a.function.entry),
            end: hx(a.function.end),
            confidence: a.confidence,
            reason: a.reason.clone(),
            source_artifact: a.function.source_artifact.clone(),
            candidate_source_paths: a.candidate_source_paths.clone(),
        })
        .collect();
    RecoveredIndex {
        attribution: "moderate".to_string(),
        sources,
        functions,
        ambiguous,
        skipped: SkippedCounts {
            function_entries: recovered.skipped,
        },
    }
}

pub fn run(
    source_tree_dir: &Path,
    decompiled_dir: &Path,
    out_index: &Path,
    opts: &Opts,
) -> Result<PathBuf> {
    let source_tree = SourceTreeIndex::load(source_tree_dir)?;
    let recovered = RecoveredFunctions::load(decompiled_dir)?;
    let attribution = attribute_with_ambiguity(&source_tree.entries, &recovered.functions, opts);
    for source in &source_tree.entries {
        let items = attribution
            .attrs
            .get(&source.path)
            .cloned()
            .unwrap_or_default();
        rewrite_leaf(&source.leaf, &items, opts)?;
    }
    let index = build_index(
        &source_tree,
        &recovered,
        &attribution.attrs,
        &attribution.ambiguous,
    );
    let json = serde_json::to_string_pretty(&index).map_err(|e| Error::Serialize(e.to_string()))?;
    std::fs::write(out_index, json)?;
    Ok(out_index.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pme_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn run_writes_index_and_inline_evidence() {
        let st = temp_dir("recover_run_source_tree");
        std::fs::create_dir_all(st.join("tree/foo")).unwrap();
        std::fs::write(st.join("tree/foo/bar.cc"), b"// source-tree stub\n").unwrap();
        std::fs::write(
            st.join("manifest.json"),
            r#"{
              "files": {
                "foo/bar.cc": {
                  "module": "foo",
                  "raw": ["foo/bar.cc"],
                  "occurrence_count": 1,
                  "occurrences": [{"vaddr": "0x5000", "offset": 80}],
                  "attributed_strings": [],
                  "attribution_confidence": "none"
                },
                "foo/empty.cc": {
                  "module": "foo",
                  "raw": ["foo/empty.cc"],
                  "occurrence_count": 1,
                  "occurrences": [{"vaddr": "0x9000", "offset": 144}],
                  "attributed_strings": [],
                  "attribution_confidence": "none"
                }
              }
            }"#,
        )
        .unwrap();
        std::fs::write(st.join("tree/foo/empty.cc"), b"// empty stub\n").unwrap();

        let decompiled = temp_dir("recover_run_decompiled");
        std::fs::write(
            decompiled.join("functions.json"),
            r#"[{"name":"FUN_4000","entry":"0x4000","end":"0x4010","size":16,"data_refs":["0x5000"]}]"#,
        )
        .unwrap();
        std::fs::write(
            decompiled.join("decompiled.c"),
            "// FUN_4000 @ 4000\nint FUN_4000(void) {\n    return 3;\n}\n\n",
        )
        .unwrap();
        std::fs::write(decompiled.join("disasm.lst"), "4000: 00  nop\n").unwrap();

        let index = st.join("recovered_index.json");
        run(&st, &decompiled, &index, &Opts::default()).unwrap();

        let enriched = std::fs::read_to_string(st.join("tree/foo/bar.cc")).unwrap();
        assert!(enriched.starts_with("// source-tree stub\n"));
        assert!(enriched.contains("// Recovered code evidence:"));
        assert!(enriched.contains("confidence : direct"));
        assert!(enriched.contains("int FUN_4000(void)"));

        let empty = std::fs::read_to_string(st.join("tree/foo/empty.cc")).unwrap();
        assert!(empty.contains("no recovered function body was attributed"));

        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(index).unwrap()).unwrap();
        assert_eq!(
            json["sources"]["foo/bar.cc"]["functions"][0]["entry"],
            "0x4000"
        );
        assert_eq!(json["skipped"]["function_entries"], 0);
    }

    #[test]
    fn run_does_not_attribute_ghidra_entry_without_decompiled_body() {
        let st = temp_dir("recover_run_missing_body_source_tree");
        std::fs::create_dir_all(st.join("tree/foo")).unwrap();
        std::fs::write(st.join("tree/foo/bar.cc"), b"// source-tree stub\n").unwrap();
        std::fs::write(
            st.join("manifest.json"),
            r#"{
              "files": {
                "foo/bar.cc": {
                  "occurrences": [{"vaddr": "0x5000", "offset": 80}]
                }
              }
            }"#,
        )
        .unwrap();

        let decompiled = temp_dir("recover_run_missing_body_decompiled");
        std::fs::write(
            decompiled.join("functions.json"),
            r#"[{"name":"FUN_4000","entry":"0x4000","end":"0x4010","size":16,"data_refs":["0x5000"]}]"#,
        )
        .unwrap();
        std::fs::write(decompiled.join("decompiled.c"), b"").unwrap();
        std::fs::write(decompiled.join("disasm.lst"), "4000: 00  nop\n").unwrap();

        let index = st.join("recovered_index.json");
        run(&st, &decompiled, &index, &Opts::default()).unwrap();

        let enriched = std::fs::read_to_string(st.join("tree/foo/bar.cc")).unwrap();
        assert!(enriched.contains("no recovered function body was attributed"));
        assert!(!enriched.contains("recovered body unavailable"));

        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(index).unwrap()).unwrap();
        assert!(
            json["sources"]["foo/bar.cc"]["functions"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(json["functions"].as_array().unwrap().is_empty());
        assert_eq!(json["skipped"]["function_entries"], 1);
    }

    #[test]
    fn parses_source_tree_manifest_entries() {
        let root = temp_dir("recover_manifest");
        std::fs::create_dir_all(root.join("tree/foo")).unwrap();
        std::fs::write(root.join("tree/foo/bar.cc"), b"// stub\n").unwrap();
        std::fs::write(
            root.join("manifest.json"),
            r#"{
              "files": {
                "foo/bar.cc": {
                  "module": "foo",
                  "raw": ["foo/bar.cc"],
                  "occurrence_count": 1,
                  "occurrences": [{"vaddr": "0x40010100", "offset": 256}],
                  "attributed_strings": ["uecap enabled"],
                  "attribution_confidence": "high"
                }
              }
            }"#,
        )
        .unwrap();

        let idx = SourceTreeIndex::load(&root).unwrap();

        assert_eq!(idx.entries.len(), 1);
        assert_eq!(idx.entries[0].path, "foo/bar.cc");
        assert_eq!(idx.entries[0].leaf, root.join("tree/foo/bar.cc"));
        assert_eq!(idx.entries[0].occurrences[0].vaddr, 0x4001_0100);
        assert_eq!(idx.entries[0].occurrences[0].offset, 256);
    }

    #[test]
    fn source_leaf_uses_node_suffix_when_path_is_also_directory() {
        let root = temp_dir("recover_manifest_dir_collision");
        std::fs::create_dir_all(root.join("tree/foo")).unwrap();
        std::fs::write(root.join("tree/foo.node"), b"// foo leaf\n").unwrap();
        std::fs::write(root.join("tree/foo/bar.cc"), b"// bar leaf\n").unwrap();
        std::fs::write(
            root.join("manifest.json"),
            r#"{
              "files": {
                "foo": {"occurrences": []},
                "foo/bar.cc": {"occurrences": []}
              }
            }"#,
        )
        .unwrap();

        let idx = SourceTreeIndex::load(&root).unwrap();

        assert_eq!(idx.entries[0].path, "foo");
        assert_eq!(idx.entries[0].leaf, root.join("tree/foo.node"));
        assert_eq!(idx.entries[1].path, "foo/bar.cc");
        assert_eq!(idx.entries[1].leaf, root.join("tree/foo/bar.cc"));
    }

    #[test]
    fn source_leaf_disambiguates_case_collisions() {
        let root = temp_dir("recover_manifest_case_collision");
        std::fs::create_dir_all(root.join("tree/foo")).unwrap();
        std::fs::write(root.join("tree/foo/Case.cc"), b"// first leaf\n").unwrap();
        std::fs::write(root.join("tree/foo/case~1.cc"), b"// second leaf\n").unwrap();
        std::fs::write(
            root.join("manifest.json"),
            r#"{
              "files": {
                "foo/Case.cc": {"occurrences": []},
                "foo/case.cc": {"occurrences": []}
              }
            }"#,
        )
        .unwrap();

        let idx = SourceTreeIndex::load(&root).unwrap();

        assert_eq!(idx.entries[0].path, "foo/Case.cc");
        assert_eq!(idx.entries[0].leaf, root.join("tree/foo/Case.cc"));
        assert_eq!(idx.entries[1].path, "foo/case.cc");
        assert_eq!(idx.entries[1].leaf, root.join("tree/foo/case~1.cc"));
        assert_ne!(
            idx.entries[0].leaf.to_string_lossy().to_lowercase(),
            idx.entries[1].leaf.to_string_lossy().to_lowercase()
        );
    }

    #[test]
    fn parses_ghidra_functions_and_bodies() {
        let root = temp_dir("recover_ghidra");
        std::fs::write(
            root.join("functions.json"),
            r#"[
              {"name":"FUN_40010120","entry":"0x40010120","end":"0x40010180","size":96,"data_refs":["0x40010100"]}
            ]"#,
        )
        .unwrap();
        std::fs::write(
            root.join("decompiled.c"),
            "// FUN_40010120 @ 40010120\nint FUN_40010120(void) {\n    return 7;\n}\n\n",
        )
        .unwrap();
        std::fs::write(root.join("disasm.lst"), "40010120: 00  nop\n").unwrap();

        let funcs = RecoveredFunctions::load(&root).unwrap();

        assert_eq!(funcs.functions.len(), 1);
        assert_eq!(funcs.functions[0].tool, Tool::Ghidra);
        assert_eq!(funcs.functions[0].entry, 0x4001_0120);
        assert_eq!(funcs.functions[0].end, 0x4001_0180);
        assert!(funcs.functions[0].body.contains("return 7;"));
        assert_eq!(funcs.functions[0].data_refs, vec![0x4001_0100]);
    }

    #[test]
    fn skips_ghidra_functions_without_decompiled_body() {
        let root = temp_dir("recover_ghidra_missing_body");
        std::fs::write(
            root.join("functions.json"),
            r#"[
              {"name":"FUN_4000","entry":"0x4000","end":"0x4010","size":16,"data_refs":["0x5000"]}
            ]"#,
        )
        .unwrap();
        std::fs::write(root.join("decompiled.c"), b"").unwrap();
        std::fs::write(root.join("disasm.lst"), "4000: 00  nop\n").unwrap();

        let funcs = RecoveredFunctions::load(&root).unwrap();

        assert!(funcs.functions.is_empty());
        assert_eq!(funcs.skipped, 1);
    }

    #[test]
    fn skips_ghidra_functions_with_header_only_body() {
        let root = temp_dir("recover_ghidra_header_only_body");
        std::fs::write(
            root.join("functions.json"),
            r#"[
              {"name":"FUN_4000","entry":"0x4000","end":"0x4010","size":16,"data_refs":["0x5000"]}
            ]"#,
        )
        .unwrap();
        std::fs::write(root.join("decompiled.c"), "// FUN_4000 @ 4000\n\n  \n").unwrap();
        std::fs::write(root.join("disasm.lst"), "4000: 00  nop\n").unwrap();

        let funcs = RecoveredFunctions::load(&root).unwrap();

        assert!(funcs.functions.is_empty());
        assert_eq!(funcs.skipped, 1);
    }

    #[test]
    fn skips_ghidra_functions_with_failed_decompilation_sentinel_body() {
        let root = temp_dir("recover_ghidra_failed_decompilation_body");
        std::fs::write(
            root.join("functions.json"),
            r#"[
              {"name":"FUN_4000","entry":"0x4000","end":"0x4010","size":16,"data_refs":["0x5000"]}
            ]"#,
        )
        .unwrap();
        std::fs::write(
            root.join("decompiled.c"),
            "// FUN_4000 @ 4000\n// <decompilation failed>\n",
        )
        .unwrap();
        std::fs::write(root.join("disasm.lst"), "4000: 00  nop\n").unwrap();

        let funcs = RecoveredFunctions::load(&root).unwrap();

        assert!(funcs.functions.is_empty());
        assert_eq!(funcs.skipped, 1);
    }

    #[test]
    fn parses_optional_radare2_thumb_functions() {
        let root = temp_dir("recover_radare2");
        std::fs::write(root.join("functions.json"), b"[]").unwrap();
        std::fs::write(root.join("decompiled.c"), b"").unwrap();
        std::fs::write(root.join("disasm.lst"), b"").unwrap();
        std::fs::write(
            root.join("thumb_functions.json"),
            r#"{
              "format": "pixel-modem-extractor-thumb-functions-v1",
              "functions": [
                {
                  "name": "sym.thumb_4120",
                  "entry": "0x4120",
                  "end": "0x4150",
                  "size": 48,
                  "body_kind": "thumb_disassembly",
                  "body": "0x4120 push {lr}\n0x4122 bx lr\n",
                  "data_refs": ["0x9000"]
                }
              ]
            }"#,
        )
        .unwrap();

        let funcs = RecoveredFunctions::load(&root).unwrap();

        assert_eq!(funcs.functions.len(), 1);
        assert_eq!(funcs.functions[0].tool, Tool::Radare2);
        assert_eq!(funcs.functions[0].entry, 0x4120);
        assert_eq!(funcs.functions[0].end, 0x4150);
        assert_eq!(funcs.functions[0].body_kind, "thumb_disassembly");
        assert!(funcs.functions[0].body.contains("push"));
        assert_eq!(funcs.functions[0].data_refs, vec![0x9000]);
        assert_eq!(funcs.functions[0].decode_ranges, None);
    }

    #[test]
    fn parses_optional_radare2_thumb_functions_v2() {
        // Legacy v1 golden trees must still parse (covered above); this fixture
        // verifies retained v2 radare2 evidence round-trips identically. Fresh
        // producer output is strict v3 and has separate ownership tests.
        let root = temp_dir("recover_radare2_v2");
        std::fs::write(root.join("functions.json"), b"[]").unwrap();
        std::fs::write(root.join("decompiled.c"), b"").unwrap();
        std::fs::write(root.join("disasm.lst"), b"").unwrap();
        std::fs::write(
            root.join("thumb_functions.json"),
            r#"{
              "format": "pixel-modem-extractor-thumb-functions-v2",
              "functions": [
                {
                  "name": "sym.thumb_4120",
                  "entry": "0x4120",
                  "end": "0x4150",
                  "size": 48,
                  "body_kind": "thumb_disassembly",
                  "body": "0x4120 push {lr}\n0x4122 bx lr\n",
                  "data_refs": ["0x9000"]
                }
              ]
            }"#,
        )
        .unwrap();

        let funcs = RecoveredFunctions::load(&root).unwrap();

        assert_eq!(funcs.functions.len(), 1);
        assert_eq!(funcs.functions[0].tool, Tool::Radare2);
        assert_eq!(funcs.functions[0].entry, 0x4120);
        assert_eq!(funcs.functions[0].end, 0x4150);
        assert_eq!(funcs.functions[0].body_kind, "thumb_disassembly");
        assert!(funcs.functions[0].body.contains("push"));
        assert_eq!(funcs.functions[0].data_refs, vec![0x9000]);
        assert_eq!(funcs.functions[0].decode_ranges, None);

        let sources = vec![source_entry("foo/legacy.cc", 0x4140, 0x100)];
        let map = attribute(&sources, &funcs.functions, &Opts::default());
        assert_eq!(map["foo/legacy.cc"][0].confidence, Confidence::Proximity);
    }

    #[test]
    fn loads_v3_thumb_producer_ownership() {
        let root = temp_dir("recover_thumb_v3_owners");
        std::fs::write(root.join("functions.json"), b"[]").unwrap();
        std::fs::write(root.join("decompiled.c"), b"").unwrap();
        std::fs::write(
            root.join("thumb_functions.json"),
            crate::thumb_analysis::ParsedThumbArtifact::future_multi_run_v3_fixture(),
        )
        .unwrap();

        let funcs = RecoveredFunctions::load(&root).unwrap();

        assert_eq!(funcs.functions.len(), 2);
        assert_eq!(funcs.functions[0].entry, 0x1000);
        assert_eq!(funcs.functions[1].entry, 0x1000);
        assert_eq!(funcs.functions[0].tool, Tool::Radare2);
        assert_eq!(funcs.functions[1].tool, Tool::Rizin);
        assert_eq!(
            funcs.functions[1].decode_ranges,
            Some(vec![(0x1000, 0x1010), (0x1080, 0x1090)])
        );
    }

    #[test]
    fn v3_range_matching_uses_decode_ranges() {
        let root = temp_dir("recover_thumb_v3_decode_ranges");
        std::fs::write(root.join("functions.json"), b"[]").unwrap();
        std::fs::write(root.join("decompiled.c"), b"").unwrap();
        std::fs::write(
            root.join("thumb_functions.json"),
            crate::thumb_analysis::ParsedThumbArtifact::future_multi_run_v3_fixture(),
        )
        .unwrap();
        let funcs = RecoveredFunctions::load(&root).unwrap();
        let rizin = funcs
            .functions
            .into_iter()
            .find(|function| function.tool == Tool::Rizin)
            .unwrap();
        let sources = vec![
            source_entry("foo/gap.cc", 0x1040, 0x100),
            source_entry("foo/covered.cc", 0x1084, 0x120),
        ];

        let map = attribute(&sources, &[rizin], &Opts::default());

        assert!(!map.contains_key("foo/gap.cc"));
        assert_eq!(map["foo/covered.cc"][0].confidence, Confidence::Proximity);
        assert!(map["foo/covered.cc"][0].reason.contains("0x1080-0x1090"));
    }

    #[test]
    fn thumb_function_with_symbolicate_stamps_parses() {
        // The production file carries symbolicate's stamps (`annotations`,
        // `original_name`) and enrich's `body_c`; the typed load ignores
        // unknown fields and never materializes a `serde_json::Value`.
        let root = temp_dir("recover_radare2_stamped");
        std::fs::write(root.join("functions.json"), b"[]").unwrap();
        std::fs::write(root.join("decompiled.c"), b"").unwrap();
        std::fs::write(root.join("disasm.lst"), b"").unwrap();
        std::fs::write(
            root.join("thumb_functions.json"),
            r#"{
              "format": "pixel-modem-extractor-thumb-functions-v2",
              "functions": [
                {
                  "name": "AtiParsePlusCOPS",
                  "original_name": "thumb_4120",
                  "annotations": [],
                  "entry": "0x4120",
                  "end": "0x4150",
                  "size": 48,
                  "body_kind": "thumb_disassembly",
                  "body": "0x4120 push {lr}\n",
                  "body_c": "void AtiParsePlusCOPS(void)\n{\n}\n",
                  "data_refs": ["0x9000"]
                }
              ]
            }"#,
        )
        .unwrap();

        let funcs = RecoveredFunctions::load(&root).unwrap();

        assert_eq!(funcs.functions.len(), 1);
        assert_eq!(funcs.functions[0].name, "AtiParsePlusCOPS");
        assert_eq!(funcs.functions[0].entry, 0x4120);
        assert_eq!(funcs.functions[0].data_refs, vec![0x9000]);
    }

    #[test]
    fn malformed_thumb_record_fails_closed() {
        // A record that does not fit the typed shape is a hard error, not a
        // silent skip: in-pipeline the file is always our canonical writer's
        // output, so a malformed record means corruption upstream.
        let root = temp_dir("recover_radare2_malformed");
        std::fs::write(root.join("functions.json"), b"[]").unwrap();
        std::fs::write(root.join("decompiled.c"), b"").unwrap();
        std::fs::write(root.join("disasm.lst"), b"").unwrap();
        std::fs::write(
            root.join("thumb_functions.json"),
            r#"{
              "format": "pixel-modem-extractor-thumb-functions-v2",
              "functions": [
                {"name": "ok", "entry": "0x4120", "end": "0x4150", "size": 48,
                 "body_kind": "thumb_disassembly", "body": "", "data_refs": []},
                {"name": 7}
              ]
            }"#,
        )
        .unwrap();

        let err = RecoveredFunctions::load(&root).unwrap_err();

        assert!(
            err.to_string().contains("thumb_functions.json"),
            "error must name the artifact: {err}"
        );
    }

    fn source_entry(path: &str, vaddr: u64, offset: usize) -> SourceEntry {
        SourceEntry {
            path: path.to_string(),
            leaf: PathBuf::from(format!("tree/{path}")),
            occurrences: vec![SourceOccurrence { vaddr, offset }],
        }
    }

    fn recovered(name: &str, entry: u64, end: u64, refs: &[u64]) -> RecoveredFunction {
        RecoveredFunction {
            tool: Tool::Ghidra,
            name: name.to_string(),
            entry,
            end,
            decode_ranges: None,
            size: end - entry,
            body_kind: "decompiled_c".to_string(),
            body: format!("int {name}(void) {{\n    return 1;\n}}"),
            source_artifact: "decompiled.c".to_string(),
            data_refs: refs.to_vec(),
        }
    }

    #[test]
    fn direct_xref_wins() {
        let sources = vec![source_entry("foo/bar.cc", 0x5000, 0x100)];
        let funcs = vec![recovered("FUN_direct", 0x4000, 0x4100, &[0x5000])];

        let result = attribute_with_ambiguity(&sources, &funcs, &Opts::default());

        assert!(result.ambiguous.is_empty());
        let hits = result.attrs.get("foo/bar.cc").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].confidence, Confidence::Direct);
        assert!(hits[0].reason.contains("references source-path string"));
    }

    #[test]
    fn function_range_containing_source_path_is_proximity() {
        let sources = vec![source_entry("foo/range.cc", 0x4050, 0x100)];
        let funcs = vec![recovered("FUN_range", 0x4000, 0x4100, &[])];

        let map = attribute(&sources, &funcs, &Opts::default());

        let hits = map.get("foo/range.cc").unwrap();
        assert_eq!(hits[0].confidence, Confidence::Proximity);
        assert!(hits[0].reason.contains("contains source-path string"));
    }

    #[test]
    fn bounded_string_cluster_reference_is_proximity() {
        let sources = vec![source_entry("foo/cluster.cc", 0x8000, 0x200)];
        let funcs = vec![recovered("FUN_cluster", 0x4000, 0x4100, &[0x8800])];

        let map = attribute(&sources, &funcs, &Opts::default());

        let hits = map.get("foo/cluster.cc").unwrap();
        assert_eq!(hits[0].confidence, Confidence::Proximity);
        assert!(hits[0].reason.contains("bounded string cluster"));
    }

    #[test]
    fn same_entry_direct_claim_does_not_suppress_other_function_proximity_claim() {
        let sources = vec![
            source_entry("foo/direct.cc", 0x5000, 0x100),
            source_entry("foo/range.cc", 0x4050, 0x110),
        ];
        let funcs = vec![
            recovered("FUN_direct", 0x4000, 0x4100, &[0x5000]),
            recovered("FUN_range", 0x4000, 0x4100, &[]),
        ];

        let result = attribute_with_ambiguity(&sources, &funcs, &Opts::default());

        assert!(result.ambiguous.is_empty());
        let direct_hits = result.attrs.get("foo/direct.cc").unwrap();
        assert_eq!(direct_hits.len(), 1);
        assert_eq!(direct_hits[0].function.name, "FUN_direct");
        assert_eq!(direct_hits[0].confidence, Confidence::Direct);

        let range_hits = result.attrs.get("foo/range.cc").unwrap();
        assert_eq!(range_hits.len(), 1);
        assert_eq!(range_hits[0].function.name, "FUN_range");
        assert_eq!(range_hits[0].confidence, Confidence::Proximity);
    }

    #[test]
    fn same_entry_proximity_claims_do_not_conflict_across_functions() {
        let sources = vec![
            source_entry("foo/a.cc", 0x8000, 0x100),
            source_entry("foo/b.cc", 0x9000, 0x110),
        ];
        let funcs = vec![
            recovered("FUN_cluster_a", 0x4000, 0x4100, &[0x8001]),
            recovered("FUN_cluster_b", 0x4000, 0x4100, &[0x9001]),
        ];

        let result = attribute_with_ambiguity(&sources, &funcs, &Opts::default());

        assert!(result.ambiguous.is_empty());
        let a_hits = result.attrs.get("foo/a.cc").unwrap();
        assert_eq!(a_hits.len(), 1);
        assert_eq!(a_hits[0].function.name, "FUN_cluster_a");
        assert_eq!(a_hits[0].confidence, Confidence::Proximity);

        let b_hits = result.attrs.get("foo/b.cc").unwrap();
        assert_eq!(b_hits.len(), 1);
        assert_eq!(b_hits[0].function.name, "FUN_cluster_b");
        assert_eq!(b_hits[0].confidence, Confidence::Proximity);
    }

    #[test]
    fn conflicting_proximity_claim_is_suppressed() {
        let sources = vec![
            source_entry("foo/a.cc", 0x8000, 0x100),
            source_entry("foo/b.cc", 0x8010, 0x110),
        ];
        let funcs = vec![recovered("FUN_conflict", 0x4000, 0x4100, &[0x8800])];

        let map = attribute(&sources, &funcs, &Opts::default());

        assert!(!map.contains_key("foo/a.cc"));
        assert!(!map.contains_key("foo/b.cc"));
    }

    #[test]
    fn conflicting_direct_claim_is_suppressed() {
        let sources = vec![
            source_entry("foo/a.cc", 0x4050, 0x100),
            source_entry("foo/b.cc", 0x4060, 0x110),
        ];
        let funcs = vec![recovered(
            "FUN_direct_conflict",
            0x4000,
            0x4100,
            &[0x4050, 0x4060],
        )];

        let map = attribute(&sources, &funcs, &Opts::default());

        assert!(!map.contains_key("foo/a.cc"));
        assert!(!map.contains_key("foo/b.cc"));
    }

    #[test]
    fn run_records_ambiguous_direct_claims_in_index() {
        let st = temp_dir("recover_run_direct_conflict_source_tree");
        std::fs::create_dir_all(st.join("tree/foo")).unwrap();
        std::fs::write(st.join("tree/foo/a.cc"), b"// source a\n").unwrap();
        std::fs::write(st.join("tree/foo/b.cc"), b"// source b\n").unwrap();
        std::fs::write(
            st.join("manifest.json"),
            r#"{
              "files": {
                "foo/a.cc": {"occurrences": [{"vaddr": "0x5000", "offset": 80}]},
                "foo/b.cc": {"occurrences": [{"vaddr": "0x6000", "offset": 96}]}
              }
            }"#,
        )
        .unwrap();

        let decompiled = temp_dir("recover_run_direct_conflict_decompiled");
        std::fs::write(
            decompiled.join("functions.json"),
            r#"[{"name":"FUN_4000","entry":"0x4000","end":"0x4010","size":16,"data_refs":["0x5000","0x6000"]}]"#,
        )
        .unwrap();
        std::fs::write(
            decompiled.join("decompiled.c"),
            "// FUN_4000 @ 4000\nint FUN_4000(void) {\n    return 3;\n}\n\n",
        )
        .unwrap();
        std::fs::write(decompiled.join("disasm.lst"), "4000: 00  nop\n").unwrap();

        let index = st.join("recovered_index.json");
        run(&st, &decompiled, &index, &Opts::default()).unwrap();

        let a = std::fs::read_to_string(st.join("tree/foo/a.cc")).unwrap();
        let b = std::fs::read_to_string(st.join("tree/foo/b.cc")).unwrap();
        assert!(a.contains("no recovered function body was attributed"));
        assert!(b.contains("no recovered function body was attributed"));

        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(index).unwrap()).unwrap();
        assert!(
            json["sources"]["foo/a.cc"]["functions"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            json["sources"]["foo/b.cc"]["functions"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(json["ambiguous"][0]["name"], "FUN_4000");
        assert_eq!(json["ambiguous"][0]["entry"], "0x4000");
        assert_eq!(json["ambiguous"][0]["confidence"], "direct");
        assert_eq!(
            json["ambiguous"][0]["reason"],
            "multiple direct source-path claims"
        );
        assert_eq!(
            json["ambiguous"][0]["candidate_source_paths"],
            serde_json::json!(["foo/a.cc", "foo/b.cc"])
        );
    }

    #[test]
    fn rewrite_leaf_is_idempotent() {
        // Re-running recover_source on an already-enriched leaf must not double-append
        // the `// Recovered code evidence:` block.
        let dir = temp_dir("rewrite_leaf_idempotent");
        let leaf = dir.join("foo.cc");
        std::fs::write(&leaf, b"// original source\nint main() { return 0; }\n").unwrap();

        let attr = Attribution {
            function: RecoveredFunction {
                tool: Tool::Ghidra,
                name: "FUN_40001000".into(),
                entry: 0x40001000,
                end: 0x40001100,
                decode_ranges: None,
                size: 0x100,
                body_kind: "c".into(),
                body: "int FUN_40001000(void) { return 1; }\n".into(),
                source_artifact: "02_MAIN".into(),
                data_refs: vec![],
            },
            confidence: Confidence::Direct,
            reason: "test".into(),
        };
        let opts = Opts {
            inline_bodies: true,
            ..Opts::default()
        };

        rewrite_leaf(&leaf, std::slice::from_ref(&attr), &opts).unwrap();
        let once = std::fs::read_to_string(&leaf).unwrap();
        assert_eq!(
            once.matches("// Recovered code evidence:").count(),
            1,
            "first write should add one section:\n{once}"
        );
        assert!(once.contains("original source"));

        // Second pass — different attrs (different function entry) — must replace the
        // first section, not append alongside it.
        let attr2 = Attribution {
            function: RecoveredFunction {
                tool: Tool::Radare2,
                name: "thumb_40e1200".into(),
                entry: 0x40e1200,
                end: 0x40e1300,
                decode_ranges: None,
                size: 0x100,
                body_kind: "thumb_disassembly".into(),
                body: "push {r7}\n".into(),
                source_artifact: "02_MAIN".into(),
                data_refs: vec![],
            },
            confidence: Confidence::Proximity,
            reason: "test2".into(),
        };
        rewrite_leaf(&leaf, std::slice::from_ref(&attr2), &opts).unwrap();
        let twice = std::fs::read_to_string(&leaf).unwrap();
        assert_eq!(
            twice.matches("// Recovered code evidence:").count(),
            1,
            "second write must replace, not append:\n{twice}"
        );
        // The new evidence (radare2 thumb @ 0x40e1200, "push {r7}") replaces
        // the old (ghidra @ 0x40001000). Section format doesn't print the
        // function name itself — only entry/range/tool/body — so check those.
        assert!(twice.contains("0x40e1200"));
        assert!(twice.contains("push {r7}"));
        assert!(twice.contains("radare2"));
        assert!(!twice.contains("0x40001000"));
        // Original content survives both passes.
        assert!(twice.contains("original source"));
    }
}
