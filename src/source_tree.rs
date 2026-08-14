//! Reconstruct the 02_MAIN firmware source tree from embedded __FILE__ strings.
//! NOT original source — recovers path names/structure only.
use crate::error::{Error, Result};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::LazyLock,
};

pub const BASE: u64 = 0x4001_0000;
const MIN_RUN: usize = 3;
const GAP: usize = 4;
const MAX_FOLLOW: usize = 40;
const MAX_SPAN: usize = 4096;
const MAX_ATTR: usize = 64;
const SHARED_PCT: f64 = 0.05;
const SHARED_ABS: usize = 200;
const STOPLIST: [&str; 5] = ["DBT:", "DBT", "ASSERT", "..", "."];

/// latin1 decode: each byte -> the codepoint with that value (matches Python `.decode("latin1")`).
fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// Offset-ordered maximal runs of printable ASCII (0x20..=0x7e) of length >= min_run.
pub fn extract_strings(data: &[u8], min_run: usize) -> Vec<(usize, &[u8])> {
    let mut out = Vec::new();
    let n = data.len();
    let mut i = 0;
    while i < n {
        if (0x20..=0x7e).contains(&data[i]) {
            let s = i;
            while i < n && (0x20..=0x7e).contains(&data[i]) {
                i += 1;
            }
            if i - s >= min_run {
                out.push((s, &data[s..i]));
            }
        } else {
            i += 1;
        }
    }
    out
}

static SRC_RE: LazyLock<regex::bytes::Regex> = LazyLock::new(|| {
    regex::bytes::Regex::new(
        r"(?i-u)^[A-Za-z0-9_./\\+\-]{3,200}\.(c|cc|cpp|cxx|h|hh|hpp|inc|inl|ipp|asm|s)$",
    )
    .unwrap()
});

fn is_source_path(s: &[u8]) -> bool {
    SRC_RE.is_match(s)
}

/// Whether `s` looks like a `__FILE__` source path (e.g. `src/foo/bar.c`).
/// Public so other modules (e.g. `globals`'s strict-rule path) can reuse the
/// exact same source-path definition instead of duplicating the regex —
/// drift between the two would silently skew `__FILE__`-fragment filtering.
pub fn is_src_path(s: &str) -> bool {
    is_source_path(s.as_bytes())
}

fn collect_followers(
    strings: &[(usize, &[u8])],
    idx: usize,
    src_offsets: &HashSet<usize>,
    gap: usize,
    max_follow: usize,
    max_span: usize,
) -> Vec<String> {
    let (anchor_off, anchor_b) = strings[idx];
    let mut prev_end = anchor_off + anchor_b.len();
    let mut out = Vec::new();
    let mut j = idx + 1;
    while j < strings.len() && out.len() < max_follow {
        let (off, b) = strings[j];
        // `saturating_sub` defends against an invariant change in `extract_strings`
        // (overlap, out-of-order) that would otherwise underflow `usize`. Today
        // the slice is sorted+non-overlapping so this is a no-op on real inputs.
        if off.saturating_sub(prev_end) > gap {
            break;
        }
        if src_offsets.contains(&off) {
            break;
        }
        if off.saturating_sub(anchor_off) > max_span {
            break;
        }
        out.push(latin1(b));
        prev_end = off + b.len();
        j += 1;
    }
    out
}

fn is_boilerplate(
    s: &str,
    doc_count: &HashMap<String, usize>,
    num_paths: usize,
    shared_pct: f64,
    shared_abs: usize,
) -> bool {
    if STOPLIST.contains(&s) {
        return true;
    }
    if s.trim().chars().count() < 3 {
        return true;
    }
    if !s.chars().any(|c| c.is_alphanumeric()) {
        return true;
    }
    let c = *doc_count.get(s).unwrap_or(&0);
    if c > shared_abs {
        return true;
    }
    if num_paths > 0 && (c as f64) / (num_paths as f64) > shared_pct {
        return true;
    }
    false
}

fn attribute(
    strings: &[(usize, &[u8])],
    occurrences: &[Occurrence],
    gap: usize,
    shared_pct: f64,
    shared_abs: usize,
) -> (HashMap<String, Vec<String>>, HashMap<String, String>) {
    let src_offsets: HashSet<usize> = occurrences.iter().map(|o| o.offset).collect();
    let pos: HashMap<usize, usize> = strings
        .iter()
        .enumerate()
        .map(|(i, (off, _))| (*off, i))
        .collect();
    let per_occ: Vec<(String, Vec<String>)> = occurrences
        .iter()
        .map(|o| {
            let f = collect_followers(
                strings,
                pos[&o.offset],
                &src_offsets,
                gap,
                MAX_FOLLOW,
                MAX_SPAN,
            );
            (o.norm.clone(), f)
        })
        .collect();

    // doc_count = number of DISTINCT norms a follower string appears in
    let mut doc_count: HashMap<String, usize> = HashMap::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for (norm, followers) in &per_occ {
        let uniq: HashSet<&String> = followers.iter().collect();
        for s in uniq {
            if seen.insert((norm.clone(), s.clone())) {
                *doc_count.entry(s.clone()).or_insert(0) += 1;
            }
        }
    }
    let num_paths = occurrences
        .iter()
        .map(|o| o.norm.as_str())
        .collect::<HashSet<_>>()
        .len();

    let mut attributed: HashMap<String, Vec<String>> = HashMap::new();
    let mut immediate: HashSet<String> = HashSet::new();
    for (norm, followers) in &per_occ {
        let bucket = attributed.entry(norm.clone()).or_default();
        for s in followers {
            if !is_boilerplate(s, &doc_count, num_paths, shared_pct, shared_abs)
                && !bucket.contains(s)
                && bucket.len() < MAX_ATTR
            {
                bucket.push(s.clone());
            }
        }
        if let Some(first) = followers.first()
            && !is_boilerplate(first, &doc_count, num_paths, shared_pct, shared_abs)
        {
            immediate.insert(norm.clone());
        }
    }
    attributed.retain(|_, v| !v.is_empty());

    let mut confidence: HashMap<String, String> = HashMap::new();
    for o in occurrences {
        let n = &o.norm;
        let conf = if attributed.get(n).is_some_and(|v| !v.is_empty()) {
            if immediate.contains(n) { "high" } else { "low" }
        } else {
            "none"
        };
        confidence.insert(n.clone(), conf.to_string());
    }
    (attributed, confidence)
}

#[derive(Debug, Clone)]
struct Record {
    norm: String,
    module: String,
    raws: Vec<String>,
    occurrences: Vec<(u64, usize)>,
    count: usize,
    attributed: Vec<String>,
    confidence: String,
}

type AggMap = HashMap<String, (HashSet<String>, Vec<(u64, usize)>)>;

fn build_records(
    occurrences: &[Occurrence],
    attributed: &HashMap<String, Vec<String>>,
    confidence: &HashMap<String, String>,
) -> HashMap<String, Record> {
    let mut agg: AggMap = HashMap::new();
    for o in occurrences {
        let e = agg.entry(o.norm.clone()).or_default();
        e.0.insert(o.raw.clone());
        e.1.push((o.vaddr, o.offset));
    }
    let mut records = HashMap::new();
    for (norm, (raws_set, mut occ)) in agg {
        occ.sort_by_key(|t| t.1);
        let mut raws: Vec<String> = raws_set.into_iter().collect();
        raws.sort();
        let module = if norm.contains('/') {
            norm.split('/').next().unwrap().to_string()
        } else {
            "_bare".to_string()
        };
        let count = occ.len();
        records.insert(
            norm.clone(),
            Record {
                module,
                raws,
                occurrences: occ,
                count,
                attributed: attributed.get(&norm).cloned().unwrap_or_default(),
                confidence: confidence
                    .get(&norm)
                    .cloned()
                    .unwrap_or_else(|| "none".into()),
                norm,
            },
        );
    }
    records
}

fn split_tree_bare(
    records: HashMap<String, Record>,
) -> (HashMap<String, Record>, HashMap<String, Record>) {
    records.into_iter().partition(|(n, _)| n.contains('/'))
}

fn render_leaf(rec: &Record) -> String {
    let mut lines = vec![
        "// Reconstructed node — NOT original source. From 02_MAIN __FILE__ strings.".to_string(),
        format!("// normalized : {}", rec.norm),
        format!("// raw        : {}", rec.raws.join(" | ")),
        format!(
            "// module     : {}        occurrences: {}        confidence: {}",
            rec.module, rec.count, rec.confidence
        ),
    ];
    let joined = rec
        .occurrences
        .iter()
        .take(16)
        .map(|(v, o)| format!("0x{v:x}/0x{o:x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sites_line = if rec.occurrences.len() > 16 {
        format!(
            "{}, \u{2026} (+{} more)",
            joined,
            rec.occurrences.len() - 16
        )
    } else {
        joined
    };
    lines.push(format!(
        "// sites      : {sites_line}   (vaddr/file-offset)"
    ));
    if !rec.attributed.is_empty() {
        lines.push(
            "// observable strings (best-effort, proximity-attributed, UNVERIFIED):".to_string(),
        );
        for s in &rec.attributed {
            let esc = s.replace('\\', "\\\\").replace('"', "\\\"");
            lines.push(format!("//   - \"{esc}\""));
        }
    }
    lines.join("\n") + "\n"
}

fn guard_long(rel: &str) -> String {
    rel.split('/')
        .map(|seg| {
            if seg.chars().count() > 200 {
                // Unreachable on this firmware (paths are short); a no-dep short hash keeps the
                // tool dependency-light. Differs from the reference's sha1[:8], but the branch is
                // never hit on the golden, so byte-identity is unaffected.
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

fn materialize_tree(
    tree_records: &HashMap<String, Record>,
    out_root: &Path,
) -> Result<(usize, Vec<String>)> {
    let tree_dir = out_root.join("tree");
    let tmp_dir = out_root.join("tree.tmp");
    if tmp_dir.exists() {
        std::fs::remove_dir_all(&tmp_dir)?;
    }
    std::fs::create_dir_all(&tmp_dir)?;

    let mut dir_set: HashSet<String> = HashSet::new();
    for norm in tree_records.keys() {
        let parts: Vec<&str> = norm.split('/').collect();
        for k in 1..parts.len() {
            dir_set.insert(parts[..k].join("/"));
        }
    }
    let mut used_lower: HashMap<String, usize> = HashMap::new();
    let mut modified = Vec::new();
    let mut norms: Vec<&String> = tree_records.keys().collect();
    norms.sort();
    for norm in norms {
        let rec = &tree_records[norm];
        let rel = finalize_rel(norm, &dir_set, &mut used_lower);
        if &rel != norm {
            modified.push(norm.clone());
        }
        // normalize_path already strips `..` and leading `/`; this is a defense-in-depth backstop.
        if rel.split('/').any(|c| c == "..") || rel.starts_with('/') {
            continue;
        }
        let dest = tmp_dir.join(&rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, render_leaf(rec))?;
    }
    if tree_dir.exists() {
        std::fs::remove_dir_all(&tree_dir)?;
    }
    std::fs::rename(&tmp_dir, &tree_dir)?;
    let written = walk_files(&tree_dir)?.len();
    modified.sort();
    modified.dedup();
    Ok((written, modified))
}

use serde::Serialize;

#[derive(Serialize)]
struct StOcc {
    vaddr: String,
    offset: usize,
}

#[derive(Serialize)]
struct StEntry {
    module: String,
    raw: Vec<String>,
    occurrence_count: usize,
    occurrences: Vec<StOcc>,
    attributed_strings: Vec<String>,
    attribution_confidence: String,
}

fn entry_of(rec: &Record) -> StEntry {
    StEntry {
        module: rec.module.clone(),
        raw: rec.raws.clone(),
        occurrence_count: rec.count,
        occurrences: rec
            .occurrences
            .iter()
            .map(|(v, o)| StOcc {
                vaddr: format!("0x{v:x}"),
                offset: *o,
            })
            .collect(),
        attributed_strings: rec.attributed.clone(),
        attribution_confidence: rec.confidence.clone(),
    }
}

fn sorted_map(recs: &HashMap<String, Record>) -> serde_json::Map<String, serde_json::Value> {
    let mut keys: Vec<&String> = recs.keys().collect();
    keys.sort();
    let mut m = serde_json::Map::new();
    for k in keys {
        m.insert(k.clone(), serde_json::to_value(entry_of(&recs[k])).unwrap());
    }
    m
}

fn write_manifest(
    out_root: &Path,
    meta: serde_json::Value,
    tree: &HashMap<String, Record>,
    bare: &HashMap<String, Record>,
    collisions: &[String],
) -> Result<()> {
    let mut coll = collisions.to_vec();
    coll.sort();
    let obj = serde_json::json!({
        "metadata": meta,
        "counts": {
            "tree_files": tree.len(),
            "bare_filenames": bare.len(),
            "collisions": coll.len(),
            "skipped": 0,
        },
        "files": sorted_map(tree),
        "bare_filenames": sorted_map(bare),
        "collisions": coll,
        "skipped": Vec::<String>::new(),
    });
    let json = serde_json::to_string_pretty(&obj).map_err(|e| Error::Serialize(e.to_string()))?;
    std::fs::write(out_root.join("manifest.json"), json)?;
    Ok(())
}

const NONSRC_EXT: [&str; 18] = [
    "bin", "xml", "cfg", "dat", "txt", "json", "der", "pem", "crt", "tbl", "nv", "efs", "so",
    "elf", "img", "log", "ini", "db",
];

fn write_tree_txt(out_root: &Path, tree: &HashMap<String, Record>) -> Result<()> {
    // build a nested trie
    #[derive(Default)]
    struct Node {
        children: std::collections::BTreeMap<String, Node>,
    }
    let mut root = Node::default();
    let mut norms: Vec<&String> = tree.keys().collect();
    norms.sort();
    for norm in &norms {
        let mut node = &mut root;
        for seg in norm.split('/') {
            node = node.children.entry(seg.to_string()).or_default();
        }
    }
    fn leaf_count(n: &Node) -> usize {
        if n.children.is_empty() {
            1
        } else {
            n.children.values().map(leaf_count).sum()
        }
    }
    let mut lines: Vec<String> = Vec::new();
    fn walk(node: &Node, prefix: &str, lines: &mut Vec<String>) {
        let items: Vec<(&String, &Node)> = node.children.iter().collect();
        for (i, (name, child)) in items.iter().enumerate() {
            let last = i == items.len() - 1;
            let conn = if last { "└── " } else { "├── " };
            let label = if child.children.is_empty() {
                (*name).clone()
            } else {
                format!("{}  ({})", name, leaf_count(child))
            };
            lines.push(format!("{prefix}{conn}{label}"));
            if !child.children.is_empty() {
                let np = format!("{prefix}{}", if last { "    " } else { "│   " });
                walk(child, &np, lines);
            }
        }
    }
    walk(&root, "", &mut lines);
    std::fs::write(out_root.join("tree.txt"), lines.join("\n") + "\n")?;
    Ok(())
}

fn write_summary_md(
    out_root: &Path,
    tree: &HashMap<String, Record>,
    bare: &HashMap<String, Record>,
) -> Result<()> {
    use std::collections::BTreeMap;
    let mut roots: HashMap<String, usize> = HashMap::new();
    let mut exts: HashMap<String, usize> = HashMap::new();
    let mut depths: BTreeMap<usize, usize> = BTreeMap::new();
    let mut conf: BTreeMap<String, usize> = BTreeMap::new();
    for r in tree.values() {
        *roots.entry(r.module.clone()).or_insert(0) += 1;
        if let Some((_, e)) = r.norm.rsplit_once('.') {
            *exts.entry(e.to_lowercase()).or_insert(0) += 1;
        }
        *depths.entry(r.norm.matches('/').count()).or_insert(0) += 1;
        *conf.entry(r.confidence.clone()).or_insert(0) += 1;
    }
    let mut lines = vec![
        "# 02_MAIN reconstructed source tree — summary".to_string(),
        String::new(),
    ];
    lines.push(format!(
        "- tree files (distinct, slash-containing): {}",
        tree.len()
    ));
    lines.push(format!("- bare filenames (no directory): {}", bare.len()));
    lines.push(format!(
        "- attribution confidence: {}",
        conf.iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let table =
        |title: &str, col0: &str, mut rows: Vec<(String, usize)>, by_count: bool| -> Vec<String> {
            if by_count {
                rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            }
            let mut out = vec![
                String::new(),
                format!("## {title}"),
                String::new(),
                format!("| {col0} | files |"),
                "|---|---:|".to_string(),
            ];
            for (k, v) in rows {
                out.push(format!("| {k} | {v} |"));
            }
            out
        };
    lines.extend(table("Roots", "root", roots.into_iter().collect(), true));
    lines.extend(table(
        "Extensions",
        "ext",
        exts.into_iter()
            .map(|(k, v)| (format!(".{k}"), v))
            .collect(),
        true,
    ));
    lines.extend(table(
        "Depth (directories deep)",
        "depth",
        depths
            .into_iter()
            .map(|(d, c)| (d.to_string(), c))
            .collect(),
        false,
    ));
    lines.extend([
        String::new(),
        "## Method & limitations".to_string(),
        String::new(),
        "- Reconstructed from `__FILE__` strings in 02_MAIN; **not original source**.".to_string(),
        "- Observable strings are heuristically proximity-attributed and UNVERIFIED.".to_string(),
        "- Scope: 02_MAIN only.".to_string(),
    ]);
    std::fs::write(out_root.join("summary.md"), lines.join("\n") + "\n")?;
    Ok(())
}

fn write_other_paths(out_root: &Path, strings: &[(usize, &[u8])]) -> Result<()> {
    let re = regex::bytes::Regex::new(r"(?-u)^[A-Za-z0-9_./\\+\-]{4,200}$").unwrap();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (_, b) in strings {
        if !b.contains(&b'/') && !b.contains(&b'\\') {
            continue;
        }
        if !re.is_match(b) {
            continue;
        }
        let s = latin1(b).replace('\\', "/");
        let tail = s.rsplit('/').next().unwrap_or(&s);
        if let Some((_, e)) = tail.rsplit_once('.')
            && NONSRC_EXT.contains(&e.to_lowercase().as_str())
        {
            seen.insert(s);
        }
    }
    std::fs::write(
        out_root.join("other_paths.txt"),
        seen.into_iter().collect::<Vec<_>>().join("\n") + "\n",
    )?;
    Ok(())
}

fn write_readme(out_root: &Path, modem_label: Option<&str>) -> Result<()> {
    let descriptor = match modem_label {
        Some(g) => format!("Samsung Shannon {g} baseband image `02_MAIN`"),
        None => "Samsung Shannon baseband image `02_MAIN`".to_string(),
    };
    let text = format!(
        "\
# 02_MAIN reconstructed source tree

Generated by `pixel-modem-extractor source-tree` from the embedded `__FILE__` path strings in the
{descriptor}.

**This is NOT original source code.** `tree/` mirrors the firmware's source directory layout
(names/structure only). Each leaf is a metadata stub plus best-effort, proximity-attributed
observable strings that are **UNVERIFIED**.

Files: `tree/`, `manifest.json`, `tree.txt`, `summary.md`, `other_paths.txt`.

Re-run: `pixel-modem-extractor source-tree <02_MAIN> --out <dir>`

Scope: 02_MAIN only.
"
    );
    std::fs::write(out_root.join("README.md"), text)?;
    Ok(())
}

// ─── Public interface ──────────────────────────────────────────────────────

/// Tuning parameters for `run`.
pub struct Opts {
    pub no_attribution: bool,
    pub gap: usize,
    pub shared_pct: f64,
    pub min_run: usize,
    /// Modem generation label for the generated README (e.g. "S5300").
    /// `None` → generic wording with no model number.
    pub modem_label: Option<String>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            no_attribution: false,
            gap: GAP,
            shared_pct: SHARED_PCT,
            min_run: MIN_RUN,
            modem_label: None,
        }
    }
}

/// Run the full source-tree pipeline: read `input`, write all outputs under `out`.
/// Returns the path to the generated `manifest.json`.
pub fn run(input: &Path, out: &Path, opts: &Opts) -> Result<PathBuf> {
    let data = std::fs::read(input)?;
    let sha = crate::manifest::sha256_bytes(&data);
    let strings = extract_strings(&data, opts.min_run);
    let occ = detect_occurrences(&strings);
    let (attributed, confidence) = if opts.no_attribution {
        (
            HashMap::new(),
            occ.iter()
                .map(|o| (o.norm.clone(), "none".to_string()))
                .collect(),
        )
    } else {
        attribute(&strings, &occ, opts.gap, opts.shared_pct, SHARED_ABS)
    };
    let records = build_records(&occ, &attributed, &confidence);
    let (tree, bare) = split_tree_bare(records);
    std::fs::create_dir_all(out)?;
    let (_written, collisions) = materialize_tree(&tree, out)?;
    let meta = serde_json::json!({
        "source_image": input.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        "sha256": sha,
        "base": format!("0x{BASE:x}"),
        "size": data.len(),
        "params": {"gap": opts.gap, "shared_pct": opts.shared_pct, "min_run": opts.min_run, "attribution": !opts.no_attribution},
    });
    write_manifest(out, meta, &tree, &bare, &collisions)?;
    write_tree_txt(out, &tree)?;
    write_summary_md(out, &tree, &bare)?;
    write_other_paths(out, &strings)?;
    write_readme(out, opts.modem_label.as_deref())?;
    Ok(out.join("manifest.json"))
}

// ───────────────────────────────────────────────────────────────────────────

/// recursive file list (sorted), shared with the manifest walk.
fn walk_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)? {
            let p = e?.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn normalize_path(raw: &str) -> String {
    let mut p = raw.replace('\\', "/");
    loop {
        if let Some(r) = p.strip_prefix("../") {
            p = r.to_string();
        } else if let Some(r) = p.strip_prefix("./") {
            p = r.to_string();
        } else if let Some(r) = p.strip_prefix('/') {
            p = r.to_string();
        } else {
            break;
        }
    }
    p.split('/')
        .filter(|seg| !seg.is_empty() && *seg != "." && *seg != "..")
        .collect::<Vec<_>>()
        .join("/")
}

#[derive(Debug, Clone)]
struct Occurrence {
    offset: usize,
    vaddr: u64,
    raw: String,
    norm: String,
}

fn detect_occurrences(strings: &[(usize, &[u8])]) -> Vec<Occurrence> {
    strings
        .iter()
        .filter(|(_, b)| is_source_path(b))
        .map(|&(off, b)| {
            let raw = latin1(b);
            let norm = normalize_path(&raw);
            Occurrence {
                offset: off,
                vaddr: BASE + off as u64,
                raw,
                norm,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_strings_finds_runs() {
        let data = b"\x00\x00hello\x00ab\xffworldXY\x00";
        let out = extract_strings(data, 3);
        let strs: Vec<&[u8]> = out.iter().map(|(_, b)| *b).collect();
        assert!(strs.contains(&&b"hello"[..]));
        assert!(strs.contains(&&b"worldXY"[..]));
        assert!(!strs.contains(&&b"ab"[..])); // len 2 < 3
        assert_eq!(out[0].0, 2); // "hello" at offset 2
    }

    #[test]
    fn latin1_maps_bytes() {
        assert_eq!(latin1(b"abc"), "abc");
        assert_eq!(latin1(&[0xc0]).chars().next().unwrap() as u32, 0xc0);
    }

    #[test]
    fn is_source_path_accepts_and_rejects() {
        assert!(is_source_path(
            b"../../../third_party/chre/chpp/transport.c"
        ));
        assert!(is_source_path(b"PALCommon/Src/VHM_Control.c"));
        assert!(is_source_path(b"app.c"));
        assert!(is_source_path(b"foo/bar.CPP")); // ext case-insensitive
        assert!(!is_source_path(b"%d %s/sec rate")); // space
        assert!(!is_source_path(b"data/SLB.bin")); // non-source ext
        assert!(!is_source_path(b"noext/file"));
    }

    #[test]
    fn normalize_path_rules() {
        assert_eq!(normalize_path("../../../x/y.c"), "x/y.c");
        assert_eq!(normalize_path("./a/b.c"), "a/b.c");
        assert_eq!(normalize_path("\\a\\b.c"), "a/b.c"); // literal \a\b.c
        assert_eq!(normalize_path("/abs/c.c"), "abs/c.c");
        for raw in ["a/../../../b.c", "../../etc/x.c", "p/./q.c"] {
            let out = normalize_path(raw);
            assert!(!out.split('/').any(|s| s == ".."));
            assert!(!out.starts_with('/'));
        }
        assert_eq!(normalize_path("../app.c"), "app.c");
    }

    #[test]
    fn detect_occurrences_builds() {
        let data = b"\x00../src/a.c\x00noise\x00b/c.cpp\x00";
        let occ = detect_occurrences(&extract_strings(data, MIN_RUN));
        let norms: HashSet<&str> = occ.iter().map(|o| o.norm.as_str()).collect();
        assert_eq!(norms, HashSet::from(["src/a.c", "b/c.cpp"]));
        let a = occ.iter().find(|o| o.norm == "src/a.c").unwrap();
        assert_eq!(a.raw, "../src/a.c");
        assert_eq!(a.vaddr, BASE + a.offset as u64);
    }

    #[test]
    fn boilerplate_rules() {
        let dc: HashMap<String, usize> = [
            ("unique msg".to_string(), 1),
            ("everywhere".to_string(), 50),
        ]
        .into();
        assert!(is_boilerplate("DBT:", &dc, 100, SHARED_PCT, SHARED_ABS)); // stoplist
        assert!(is_boilerplate("()", &dc, 100, SHARED_PCT, SHARED_ABS)); // no alnum
        assert!(is_boilerplate("ab", &dc, 100, SHARED_PCT, SHARED_ABS)); // too short
        assert!(is_boilerplate("everywhere", &dc, 100, 0.05, SHARED_ABS)); // 50/100 > 5%
        assert!(!is_boilerplate(
            "unique msg",
            &dc,
            100,
            SHARED_PCT,
            SHARED_ABS
        ));
    }

    #[test]
    fn attribute_wires() {
        let data = b"a/one.c\x00specific to one\x00DBT:\x00a/two.c\x00specific to two\x00";
        let strings = extract_strings(data, MIN_RUN);
        let occ = detect_occurrences(&strings);
        // shared_pct=1.0 so the corpus-frequency rule can't fire on a 2-file fixture
        let (attributed, confidence) = attribute(&strings, &occ, GAP, 1.0, SHARED_ABS);
        assert!(attributed["a/one.c"].contains(&"specific to one".to_string()));
        assert!(!attributed["a/one.c"].contains(&"DBT:".to_string()));
        assert_eq!(confidence["a/one.c"], "high");
    }

    #[test]
    fn build_records_aggregates_and_splits() {
        let occ = vec![
            Occurrence {
                offset: 10,
                vaddr: BASE + 10,
                raw: "../a/x.c".into(),
                norm: "a/x.c".into(),
            },
            Occurrence {
                offset: 40,
                vaddr: BASE + 40,
                raw: "a/x.c".into(),
                norm: "a/x.c".into(),
            },
            Occurrence {
                offset: 80,
                vaddr: BASE + 80,
                raw: "lone.c".into(),
                norm: "lone.c".into(),
            },
        ];
        let attributed: HashMap<String, Vec<String>> =
            [("a/x.c".to_string(), vec!["hi".to_string()])].into();
        let confidence: HashMap<String, String> = [
            ("a/x.c".to_string(), "high".to_string()),
            ("lone.c".to_string(), "none".to_string()),
        ]
        .into();
        let recs = build_records(&occ, &attributed, &confidence);
        assert_eq!(recs["a/x.c"].count, 2);
        assert_eq!(recs["a/x.c"].module, "a");
        assert_eq!(recs["a/x.c"].occurrences[0], (BASE + 10, 10)); // sorted by offset
        assert_eq!(
            recs["a/x.c"].raws,
            vec!["../a/x.c".to_string(), "a/x.c".to_string()]
        ); // sorted unique
        assert_eq!(recs["lone.c"].module, "_bare");
        let (tree, bare) = split_tree_bare(recs);
        assert!(tree.contains_key("a/x.c"));
        assert!(bare.contains_key("lone.c"));
    }

    #[test]
    fn collect_followers_stops() {
        let data = b"x/y.c\x00msg one\x00msg two\x00\x00\x00\x00\x00farAway";
        let strings = extract_strings(data, MIN_RUN);
        let idx = strings.iter().position(|(_, b)| *b == b"x/y.c").unwrap();
        let src: HashSet<usize> = [strings[idx].0].into_iter().collect();
        assert_eq!(
            collect_followers(&strings, idx, &src, GAP, MAX_FOLLOW, MAX_SPAN),
            vec!["msg one".to_string(), "msg two".to_string()]
        );

        let data2 = b"a/b.c\x00follower\x00c/d.c\x00other";
        let s2 = extract_strings(data2, MIN_RUN);
        let i2 = s2.iter().position(|(_, b)| *b == b"a/b.c").unwrap();
        let src2: HashSet<usize> = s2
            .iter()
            .filter(|(_, b)| is_source_path(b))
            .map(|(o, _)| *o)
            .collect();
        assert_eq!(
            collect_followers(&s2, i2, &src2, GAP, MAX_FOLLOW, MAX_SPAN),
            vec!["follower".to_string()]
        );
    }

    #[test]
    fn finalize_rel_collisions() {
        let dir_set: HashSet<String> = ["a".into(), "a/b".into()].into();
        let mut used = HashMap::new();
        assert_eq!(finalize_rel("a/b", &dir_set, &mut used), "a/b.node"); // path is also a dir

        let mut used2 = HashMap::new();
        let first = finalize_rel("a/Foo.c", &HashSet::new(), &mut used2);
        let second = finalize_rel("a/foo.c", &HashSet::new(), &mut used2); // case-collides
        assert_ne!(first.to_lowercase(), second.to_lowercase());

        // mangled name must not collide with an existing real name
        let mut used3 = HashMap::new();
        let a = finalize_rel("d/foo~1.c", &HashSet::new(), &mut used3);
        let b = finalize_rel("d/foo.c", &HashSet::new(), &mut used3);
        let c = finalize_rel("d/Foo.c", &HashSet::new(), &mut used3);
        let set: HashSet<String> = [a.to_lowercase(), b.to_lowercase(), c.to_lowercase()].into();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn materialize_writes_tree() {
        let recs: HashMap<String, Record> = [
            (
                "a/b/x.c".to_string(),
                Record {
                    norm: "a/b/x.c".into(),
                    module: "a".into(),
                    raws: vec!["a/b/x.c".into()],
                    occurrences: vec![(BASE, 0)],
                    count: 1,
                    attributed: vec!["hello".into()],
                    confidence: "high".into(),
                },
            ),
            (
                "a/b".to_string(),
                Record {
                    norm: "a/b".into(),
                    module: "a".into(),
                    raws: vec!["a/b.c".into()],
                    occurrences: vec![(BASE + 9, 9)],
                    count: 1,
                    attributed: vec![],
                    confidence: "none".into(),
                },
            ),
        ]
        .into();
        let tmp = std::env::temp_dir().join("pme_st_materialize");
        let _ = std::fs::remove_dir_all(&tmp);
        let (written, modified) = materialize_tree(&recs, &tmp).unwrap();
        assert_eq!(written, 2);
        assert!(tmp.join("tree/a/b/x.c").is_file());
        assert!(tmp.join("tree/a/b.node").is_file()); // a/b collided with the dir
        assert!(modified.contains(&"a/b".to_string()));
    }

    #[test]
    fn manifest_shape() {
        let tree: HashMap<String, Record> = [(
            "a/b.c".to_string(),
            Record {
                norm: "a/b.c".into(),
                module: "a".into(),
                raws: vec!["a/b.c".into()],
                occurrences: vec![(BASE + 5, 5)],
                count: 1,
                attributed: vec!["msg".into()],
                confidence: "high".into(),
            },
        )]
        .into();
        let bare: HashMap<String, Record> = [(
            "lone.c".to_string(),
            Record {
                norm: "lone.c".into(),
                module: "_bare".into(),
                raws: vec!["lone.c".into()],
                occurrences: vec![(BASE, 0)],
                count: 1,
                attributed: vec![],
                confidence: "none".into(),
            },
        )]
        .into();
        let tmp = std::env::temp_dir().join("pme_st_manifest");
        std::fs::create_dir_all(&tmp).unwrap();
        write_manifest(
            &tmp,
            serde_json::json!({"sha256": "deadbeef"}),
            &tree,
            &bare,
            &["a/b".to_string()],
        )
        .unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(tmp.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(v["counts"]["tree_files"], 1);
        assert_eq!(v["counts"]["bare_filenames"], 1);
        assert_eq!(v["files"]["a/b.c"]["attributed_strings"][0], "msg");
        assert_eq!(v["files"]["a/b.c"]["occurrences"][0]["offset"], 5);
        assert!(v["bare_filenames"].get("lone.c").is_some());
        assert_eq!(v["collisions"][0], "a/b");
    }

    fn _recs() -> HashMap<String, Record> {
        [
            (
                "a/b/x.c".to_string(),
                Record {
                    norm: "a/b/x.c".into(),
                    module: "a".into(),
                    raws: vec!["a/b/x.c".into()],
                    occurrences: vec![(BASE, 0)],
                    count: 1,
                    attributed: vec![],
                    confidence: "none".into(),
                },
            ),
            (
                "a/y.cpp".to_string(),
                Record {
                    norm: "a/y.cpp".into(),
                    module: "a".into(),
                    raws: vec!["a/y.cpp".into()],
                    occurrences: vec![(BASE + 5, 5)],
                    count: 1,
                    attributed: vec![],
                    confidence: "none".into(),
                },
            ),
        ]
        .into()
    }

    #[test]
    fn reports_write() {
        let tmp = std::env::temp_dir().join("pme_st_reports");
        std::fs::create_dir_all(&tmp).unwrap();
        write_tree_txt(&tmp, &_recs()).unwrap();
        let tt = std::fs::read_to_string(tmp.join("tree.txt")).unwrap();
        assert!(tt.contains("x.c") && tt.contains("y.cpp"));
        assert!(tt.contains("(2)")); // root dir "a" has 2 leaves
        assert!(tt.contains("├── ")); // box-drawing
        write_summary_md(&tmp, &_recs(), &HashMap::new()).unwrap();
        assert!(
            std::fs::read_to_string(tmp.join("summary.md"))
                .unwrap()
                .contains("tree files")
        );
        let strings = extract_strings(b"\x00data/SLB.bin\x00a/b.c\x00plain text\x00", MIN_RUN);
        write_other_paths(&tmp, &strings).unwrap();
        let op = std::fs::read_to_string(tmp.join("other_paths.txt")).unwrap();
        assert!(op.contains("data/SLB.bin") && !op.contains("a/b.c"));
        write_readme(&tmp, None).unwrap();
        assert!(
            std::fs::read_to_string(tmp.join("README.md"))
                .unwrap()
                .contains("NOT original source")
        );
    }

    #[test]
    fn readme_uses_modem_label_when_present() {
        let tmp = std::env::temp_dir().join("pme_readme_label");
        let _ = std::fs::create_dir_all(&tmp);
        write_readme(&tmp, Some("S5300")).unwrap();
        let s = std::fs::read_to_string(tmp.join("README.md")).unwrap();
        assert!(s.contains("Samsung Shannon S5300 baseband image"), "{s}");
        assert!(!s.contains("S5400"), "{s}");
    }

    #[test]
    fn readme_generic_without_label() {
        let tmp = std::env::temp_dir().join("pme_readme_generic");
        let _ = std::fs::create_dir_all(&tmp);
        write_readme(&tmp, None).unwrap();
        let s = std::fs::read_to_string(tmp.join("README.md")).unwrap();
        assert!(s.contains("Samsung Shannon baseband image"), "{s}");
        assert!(!s.contains("S5400") && !s.contains("S5300"), "{s}");
    }

    #[test]
    fn render_leaf_format() {
        let rec = Record {
            norm: "third_party/chre/chpp/transport.c".into(),
            module: "third_party".into(),
            raws: vec!["../../../third_party/chre/chpp/transport.c".into()],
            occurrences: vec![(0x409afa60, 0x99fa60)],
            count: 1,
            attributed: vec!["Async send failure: %d".into()],
            confidence: "high".into(),
        };
        let t = render_leaf(&rec);
        assert!(t.contains("NOT original source"));
        assert!(t.contains("normalized : third_party/chre/chpp/transport.c"));
        assert!(t.contains("confidence: high"));
        assert!(t.contains("0x409afa60/0x99fa60"));
        assert!(t.contains("\"Async send failure: %d\""));
        assert!(t.ends_with('\n'));

        let rec2 = Record {
            norm: "a/b.c".into(),
            module: "a".into(),
            raws: vec!["a/b.c".into()],
            occurrences: vec![(BASE, 0)],
            count: 1,
            attributed: vec![],
            confidence: "none".into(),
        };
        assert!(!render_leaf(&rec2).contains("observable strings"));
    }

    #[test]
    fn materialize_rejects_escaping_norm() {
        // normalize_path strips `..` upstream, but materialize_tree must never write outside tree/.
        let recs: HashMap<String, Record> = [(
            "../evil.c".to_string(),
            Record {
                norm: "../evil.c".into(),
                module: "_bare".into(),
                raws: vec!["../evil.c".into()],
                occurrences: vec![(BASE, 0)],
                count: 1,
                attributed: vec![],
                confidence: "none".into(),
            },
        )]
        .into();
        let tmp = std::env::temp_dir().join("pme_st_escape");
        let _ = std::fs::remove_dir_all(&tmp);
        let (written, _) = materialize_tree(&recs, &tmp).unwrap();
        assert_eq!(written, 0); // escaping norm skipped
        assert!(!tmp.join("evil.c").exists());
        assert!(!std::env::temp_dir().join("evil.c").exists());
    }

    #[test]
    fn run_no_attribution_branch() {
        let data = b"\x00../src/a.c\x00some message here\x00b/c.cpp\x00";
        let tmp = std::env::temp_dir().join("pme_st_noattr");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let input = tmp.join("02_MAIN");
        std::fs::write(&input, data).unwrap();
        let out = tmp.join("out");
        let opts = Opts {
            no_attribution: true,
            ..Opts::default()
        };
        run(&input, &out, &opts).unwrap();
        let m: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(m["metadata"]["params"]["attribution"], false);
        assert_eq!(
            m["files"]["src/a.c"]["attributed_strings"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(m["files"]["src/a.c"]["attribution_confidence"], "none");
        let leaf = std::fs::read_to_string(out.join("tree/src/a.c")).unwrap();
        assert!(!leaf.contains("observable strings"));
    }
}
