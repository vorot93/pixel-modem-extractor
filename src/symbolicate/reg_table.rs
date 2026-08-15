//! Registration-table function-name recovery: scan the raw image for contiguous
//! `{name_ptr, fn_ptr}` tables (AT-command dispatch, ISR, protocol handler
//! tables) and turn each into an authoritative (`Recovered`) function name.
//! Pure; fail-closed. The function pointer must resolve to a *known* function
//! entry (ARM or Thumb) — the inventory is the gate, so a name is only minted
//! for a confirmed function. Unlike the string-reference tier, all-caps names
//! are accepted here (`PICH_HISR` is a real ISR name) because the table
//! structure earns that trust. See `2026-08-14-registration-naming-*` findings.

use super::name_guess::is_ident;
use std::collections::{HashMap, HashSet};

/// One validated `{name, fn}` table record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegEntry {
    pub name: String,
    /// Target function entry, Thumb bit stripped.
    pub fn_addr: u64,
    pub arch: &'static str, // "arm" | "thumb"
    /// Bytes per record (always 8 — the two supported layouts are both stride-8).
    pub stride: u8,
}

/// Result of scanning an image for registration tables.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RegScan {
    /// The full detected-table inventory, in image order (before 1:1
    /// resolution) — every `{name, fn}` record found. `names` is what naming
    /// consumes; `entries` records what detection alone found (so a table entry
    /// dropped by the 1:1 rule is still visible here, which the tests rely on).
    pub entries: Vec<RegEntry>,
    /// Fail-closed authoritative names: `fn_addr` (no Thumb bit) → name, only
    /// where both the name and the function map 1:1. This is what `build_map`
    /// applies as `Recovered`.
    pub names: HashMap<u64, String>,
}

/// Scan `image` for contiguous `{name_ptr, fn_ptr}` tables and recover
/// authoritative function names, fail-closed. `fn_entries` maps a function
/// entry address (no Thumb bit) to its arch and is the acceptance gate: a name
/// is minted only when the pointer resolves to a known function. `globals` and
/// `fn_names` are rejected as names (an aliased global / another function's
/// name) — but only as completely as those sets are populated: the caller
/// supplies them, and at the pre-globals `symbol_map` stage `globals` is empty
/// (see `build_map`), so global-alias rejection is best-effort there. Any
/// residual name collision is handled downstream by `finalize_names`. Names
/// that are not 1:1 (a name at >1 function, or a function under >1 distinct
/// name) are dropped from `names` but retained in `entries`.
pub fn scan(
    image: &[u8],
    load_addr: u64,
    fn_entries: &HashMap<u64, &'static str>,
    globals: &HashSet<String>,
    fn_names: &HashSet<String>,
) -> RegScan {
    let words = classify_words(image, load_addr, fn_entries);
    let entries = find_tables(&words, image, load_addr);
    let names = resolve_names(&entries, globals, fn_names);
    RegScan { entries, names }
}

/// A classified 4-aligned image word. Both pointer variants carry only the
/// word's *value* (not a materialized `String`), so classifying a multi-MB
/// image allocates nothing per word — the name string is read back from the
/// image only for the handful of words that end up inside a confirmed table.
#[derive(Clone, Copy)]
enum Word {
    /// vaddr of an identifier string.
    Name(u32),
    /// (function entry with Thumb bit stripped, is_thumb).
    Fn(u32, bool),
    Other,
}

/// Minimum records for a run to count as a table (kills coincidental pairs).
const MIN_RUN: usize = 3;

fn classify_words(
    image: &[u8],
    load_addr: u64,
    fn_entries: &HashMap<u64, &'static str>,
) -> Vec<Word> {
    let nwords = image.len() / 4;
    let mut words = Vec::with_capacity(nwords);
    for i in 0..nwords {
        let o = i * 4;
        let v = u32::from_le_bytes([image[o], image[o + 1], image[o + 2], image[o + 3]]);
        let w = if ident_range_at(image, load_addr, v as u64).is_some() {
            Word::Name(v)
        } else if let Some(&arch) = fn_entries.get(&((v & !1) as u64)) {
            Word::Fn(v & !1, arch == "thumb")
        } else {
            Word::Other
        };
        words.push(w);
    }
    words
}

/// Record layouts as (stride in words, name-word offset, fn-word offset). Both
/// stride-8 orders occur in the firmware and carry comparable validated yield;
/// wider strides were measured to contribute nothing and are omitted.
const LAYOUTS: &[(usize, usize, usize)] = &[
    (2, 0, 1), // {name, fn}
    (2, 1, 0), // {fn, name}
];

/// A maximal contiguous run of `{name, fn}` records under one layout.
struct Run {
    start: usize,
    stride_w: usize,
    name_off: usize,
    fn_off: usize,
    records: usize,
}

/// Find `{name, fn}` tables across all layouts, resolving overlaps
/// **longest-run-first**. This is what keeps a reversed `{fn, name}` table from
/// being misread by the forward layout shifted one word in: the true run is
/// always one record longer than its shifted misread, so it claims the span.
fn find_tables(words: &[Word], image: &[u8], load_addr: u64) -> Vec<RegEntry> {
    let nwords = words.len();
    let is_name = |w: &Word| matches!(w, Word::Name(_));
    let is_fn = |w: &Word| matches!(w, Word::Fn(..));

    let mut runs: Vec<Run> = Vec::new();
    for &(stride_w, name_off, fn_off) in LAYOUTS {
        let rec_at = |base: usize| {
            base + stride_w <= nwords
                && is_name(&words[base + name_off])
                && is_fn(&words[base + fn_off])
        };
        let mut i = 0;
        while i + stride_w <= nwords {
            if rec_at(i) {
                let mut records = 1;
                let mut j = i + stride_w;
                while rec_at(j) {
                    records += 1;
                    j += stride_w;
                }
                if records >= MIN_RUN {
                    runs.push(Run {
                        start: i,
                        stride_w,
                        name_off,
                        fn_off,
                        records,
                    });
                }
                i = j; // skip the scanned records (maximal within this layout)
            } else {
                i += 1;
            }
        }
    }

    runs.sort_by(|a, b| b.records.cmp(&a.records).then(a.start.cmp(&b.start)));
    let mut consumed = vec![false; nwords];
    let mut entries: Vec<RegEntry> = Vec::new();
    for r in &runs {
        let span = r.records * r.stride_w;
        if (r.start..r.start + span).any(|w| consumed[w]) {
            continue; // a longer run already claimed these words
        }
        consumed[r.start..r.start + span].fill(true);
        for k in 0..r.records {
            let base = r.start + k * r.stride_w;
            if let (Word::Name(nv), Word::Fn(fa, is_thumb)) =
                (words[base + r.name_off], words[base + r.fn_off])
                && let Some(name) = read_ident_at(image, load_addr, nv as u64)
            {
                entries.push(RegEntry {
                    name,
                    fn_addr: fa as u64,
                    arch: if is_thumb { "thumb" } else { "arm" },
                    stride: (r.stride_w * 4) as u8,
                });
            }
        }
    }
    entries.sort_by_key(|e| e.fn_addr);
    entries
}

/// Fail-closed 1:1 name map: drop names that alias a recovered global or another
/// function's name, then keep only strict 1:1 (name ↔ function) pairs.
fn resolve_names(
    entries: &[RegEntry],
    globals: &HashSet<String>,
    fn_names: &HashSet<String>,
) -> HashMap<u64, String> {
    let mut fn_to_names: HashMap<u64, HashSet<String>> = HashMap::new();
    let mut name_to_fns: HashMap<String, HashSet<u64>> = HashMap::new();
    for e in entries {
        if globals.contains(&e.name) || fn_names.contains(&e.name) {
            continue;
        }
        fn_to_names
            .entry(e.fn_addr)
            .or_default()
            .insert(e.name.clone());
        name_to_fns
            .entry(e.name.clone())
            .or_default()
            .insert(e.fn_addr);
    }
    let mut names = HashMap::new();
    for (fa, ns) in &fn_to_names {
        if ns.len() == 1 {
            let n = ns.iter().next().unwrap();
            if name_to_fns[n].len() == 1 {
                names.insert(*fa, n.clone());
            }
        }
    }
    names
}

/// Byte range `[start, end)` of a NUL-terminated printable-ASCII C identifier
/// stored at `vaddr`, or `None` (out of range / non-printable / unterminated /
/// not an `is_ident`). The allocation-free core of [`read_ident_at`], so a
/// whole-image classification pass can test every word without building a
/// `String` for each candidate.
fn ident_range_at(image: &[u8], load_addr: u64, vaddr: u64) -> Option<(usize, usize)> {
    let start = vaddr.checked_sub(load_addr)? as usize;
    let mut o = start;
    while o < image.len() && image[o] != 0 && o - start < MAX_NAME {
        if !(0x20..=0x7e).contains(&image[o]) {
            return None; // non-printable — not a string
        }
        o += 1;
    }
    if o >= image.len() || image[o] != 0 {
        return None; // ran off the end / not NUL-terminated in range
    }
    let s = std::str::from_utf8(&image[start..o]).ok()?;
    is_ident(s).then_some((start, o))
}

/// Read a NUL-terminated printable-ASCII C identifier stored at `vaddr`, or
/// `None` if the address is out of range, the bytes are not printable, the
/// string is not NUL-terminated within range, or it is not an `is_ident`.
pub fn read_ident_at(image: &[u8], load_addr: u64, vaddr: u64) -> Option<String> {
    let (start, end) = ident_range_at(image, load_addr, vaddr)?;
    // `ident_range_at` already validated printable ASCII (=> valid UTF-8).
    Some(String::from_utf8_lossy(&image[start..end]).into_owned())
}

/// Upper bound on a scanned name length (keeps the string search cheap and is
/// well above any real identifier; `is_ident` caps acceptance at 64).
const MAX_NAME: usize = 96;

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x4001_0000;

    /// Build an image with `s` (NUL-terminated) placed at file offset `off`.
    fn image_with_string(off: usize, s: &str) -> Vec<u8> {
        let mut img = vec![0u8; off + s.len() + 8];
        img[off..off + s.len()].copy_from_slice(s.as_bytes());
        img[off + s.len()] = 0; // NUL
        img
    }

    /// Minimal image builder: place strings and 32-bit LE pointer words at
    /// chosen file offsets, and hand back their virtual addresses.
    struct Img {
        bytes: Vec<u8>,
    }
    impl Img {
        fn new(size: usize) -> Self {
            Img {
                bytes: vec![0u8; size],
            }
        }
        fn va(&self, off: usize) -> u64 {
            BASE + off as u64
        }
        /// Write `s\0` at `off`, return its vaddr.
        fn put_str(&mut self, off: usize, s: &str) -> u64 {
            self.bytes[off..off + s.len()].copy_from_slice(s.as_bytes());
            self.bytes[off + s.len()] = 0;
            self.va(off)
        }
        /// Write a 32-bit LE word at `off`.
        fn put_u32(&mut self, off: usize, v: u32) {
            self.bytes[off..off + 4].copy_from_slice(&v.to_le_bytes());
        }
    }

    fn thumb_entries(addrs: &[u64]) -> HashMap<u64, &'static str> {
        addrs.iter().map(|a| (*a, "thumb")).collect()
    }

    #[test]
    fn read_ident_at_reads_nul_terminated_identifier() {
        let img = image_with_string(0x100, "AtiParsePlusCOPS");
        assert_eq!(
            read_ident_at(&img, BASE, BASE + 0x100),
            Some("AtiParsePlusCOPS".to_string())
        );
    }

    #[test]
    fn read_ident_at_rejects_out_of_range() {
        let img = image_with_string(0x100, "Foo_Bar");
        assert_eq!(read_ident_at(&img, BASE, BASE - 4), None); // below load base
        assert_eq!(read_ident_at(&img, BASE, BASE + 0x9999), None); // past image
    }

    #[test]
    fn read_ident_at_rejects_unterminated_string() {
        // identifier bytes run to the very end with no NUL
        let mut img = vec![0u8; 0x100];
        img.extend_from_slice(b"Unterminated");
        assert_eq!(read_ident_at(&img, BASE, BASE + 0x100), None);
    }

    #[test]
    fn read_ident_at_rejects_non_printable_and_non_ident() {
        let mut img = image_with_string(0x100, "Bad");
        img[0x101] = 0x07; // bell byte inside -> not a string
        assert_eq!(read_ident_at(&img, BASE, BASE + 0x100), None);
        let img2 = image_with_string(0x100, "has space"); // not an identifier
        assert_eq!(read_ident_at(&img2, BASE, BASE + 0x100), None);
    }

    /// A 3-record `{name_ptr, thumb_fn_ptr}` table (stride 8) whose fn pointers
    /// all resolve to known Thumb entries yields all three names, 1:1.
    #[test]
    fn scan_detects_simple_thumb_table() {
        let mut img = Img::new(0x400);
        // names
        let na = img.put_str(0x200, "Handler_A");
        let nb = img.put_str(0x220, "Handler_B");
        let nc = img.put_str(0x240, "Handler_C");
        // function entries (odd = Thumb bit set in the stored pointer)
        let (fa, fb, fc) = (0x4001_1000, 0x4001_1040, 0x4001_1080);
        // table at 0x40: {name, fn|1} x3
        img.put_u32(0x40, na as u32);
        img.put_u32(0x44, fa as u32 | 1);
        img.put_u32(0x48, nb as u32);
        img.put_u32(0x4c, fb as u32 | 1);
        img.put_u32(0x50, nc as u32);
        img.put_u32(0x54, fc as u32 | 1);

        let entries = thumb_entries(&[fa, fb, fc]);
        let scan = scan(&img.bytes, BASE, &entries, &HashSet::new(), &HashSet::new());

        assert_eq!(scan.names.get(&fa), Some(&"Handler_A".to_string()));
        assert_eq!(scan.names.get(&fb), Some(&"Handler_B".to_string()));
        assert_eq!(scan.names.get(&fc), Some(&"Handler_C".to_string()));
        assert_eq!(scan.entries.len(), 3);
        assert!(
            scan.entries
                .iter()
                .all(|e| e.arch == "thumb" && e.stride == 8)
        );
    }

    /// Build a stride-8 `{name, fn|1}` table of `(name, fn)` records at `off`.
    fn table_at(img: &mut Img, off: usize, recs: &[(u64, u64)]) {
        for (k, (na, fa)) in recs.iter().enumerate() {
            img.put_u32(off + k * 8, *na as u32);
            img.put_u32(off + k * 8 + 4, *fa as u32 | 1);
        }
    }

    #[test]
    fn scan_drops_name_used_for_multiple_functions() {
        let mut img = Img::new(0x400);
        let dup = img.put_str(0x200, "Shared"); // same name string
        let (f1, f2, f3) = (0x4001_1000, 0x4001_1040, 0x4001_1080);
        table_at(&mut img, 0x40, &[(dup, f1), (dup, f2), (dup, f3)]);
        let entries = thumb_entries(&[f1, f2, f3]);
        let scan = scan(&img.bytes, BASE, &entries, &HashSet::new(), &HashSet::new());
        // detected as a table, but the ambiguous name maps to no function
        assert_eq!(scan.entries.len(), 3);
        assert!(
            scan.names.is_empty(),
            "a name at >1 function must be dropped"
        );
    }

    #[test]
    fn scan_drops_function_under_multiple_names() {
        let mut img = Img::new(0x400);
        let na = img.put_str(0x200, "Name_A");
        let nb = img.put_str(0x220, "Name_B");
        let nc = img.put_str(0x240, "Name_C");
        let f = 0x4001_1000; // one function, three different names
        table_at(&mut img, 0x40, &[(na, f), (nb, f), (nc, f)]);
        let entries = thumb_entries(&[f]);
        let scan = scan(&img.bytes, BASE, &entries, &HashSet::new(), &HashSet::new());
        assert_eq!(
            scan.names.get(&f),
            None,
            "a function under >1 name must be dropped"
        );
    }

    #[test]
    fn scan_rejects_name_aliasing_a_global_or_function() {
        let mut img = Img::new(0x400);
        let ng = img.put_str(0x200, "TmuGlobal"); // a recovered global name
        let nf = img.put_str(0x220, "ExistingFn"); // another function's name
        let nok = img.put_str(0x240, "Legit_Handler");
        let (f1, f2, f3) = (0x4001_1000, 0x4001_1040, 0x4001_1080);
        table_at(&mut img, 0x40, &[(ng, f1), (nf, f2), (nok, f3)]);
        let entries = thumb_entries(&[f1, f2, f3]);
        let globals: HashSet<String> = ["TmuGlobal".into()].into_iter().collect();
        let fn_names: HashSet<String> = ["ExistingFn".into()].into_iter().collect();
        let scan = scan(&img.bytes, BASE, &entries, &globals, &fn_names);
        assert_eq!(scan.names.get(&f1), None, "global-aliased name rejected");
        assert_eq!(scan.names.get(&f2), None, "fn-aliased name rejected");
        assert_eq!(scan.names.get(&f3), Some(&"Legit_Handler".to_string()));
    }

    #[test]
    fn scan_accepts_all_caps_isr_name() {
        // divergence from the string-ref tier: the table structure earns trust
        // in an all-caps name like an ISR handler.
        let mut img = Img::new(0x400);
        let a = img.put_str(0x200, "PICH_HISR");
        let b = img.put_str(0x220, "CPI_HISR");
        let c = img.put_str(0x240, "SLEEP_FEE_HISR");
        let (f1, f2, f3) = (0x4001_1000, 0x4001_1040, 0x4001_1080);
        table_at(&mut img, 0x40, &[(a, f1), (b, f2), (c, f3)]);
        let entries = thumb_entries(&[f1, f2, f3]);
        let scan = scan(&img.bytes, BASE, &entries, &HashSet::new(), &HashSet::new());
        assert_eq!(scan.names.get(&f1), Some(&"PICH_HISR".to_string()));
    }

    #[test]
    fn scan_gate_rejects_run_whose_pointers_are_not_known_functions() {
        let mut img = Img::new(0x400);
        let a = img.put_str(0x200, "Name_A");
        let b = img.put_str(0x220, "Name_B");
        let c = img.put_str(0x240, "Name_C");
        let (f1, f2, f3) = (0x4001_1000, 0x4001_1040, 0x4001_1080);
        table_at(&mut img, 0x40, &[(a, f1), (b, f2), (c, f3)]);
        // empty entry set -> the "fn" words are not known functions
        let scan = scan(
            &img.bytes,
            BASE,
            &HashMap::new(),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert!(
            scan.entries.is_empty(),
            "no run without confirmed function pointers"
        );
        assert!(scan.names.is_empty());
    }

    #[test]
    fn scan_labels_arm_targets() {
        let mut img = Img::new(0x400);
        let a = img.put_str(0x200, "Arm_A");
        let b = img.put_str(0x220, "Arm_B");
        let c = img.put_str(0x240, "Arm_C");
        let (f1, f2, f3) = (0x4001_1000u64, 0x4001_1040, 0x4001_1080); // even = ARM
        for (k, (na, fa)) in [(a, f1), (b, f2), (c, f3)].iter().enumerate() {
            img.put_u32(0x40 + k * 8, *na as u32);
            img.put_u32(0x40 + k * 8 + 4, *fa as u32); // no Thumb bit
        }
        let entries: HashMap<u64, &'static str> =
            [f1, f2, f3].iter().map(|a| (*a, "arm")).collect();
        let scan = scan(&img.bytes, BASE, &entries, &HashSet::new(), &HashSet::new());
        assert_eq!(scan.names.get(&f1), Some(&"Arm_A".to_string()));
        assert!(scan.entries.iter().all(|e| e.arch == "arm"));
    }

    #[test]
    fn scan_rejects_too_short_run() {
        let mut img = Img::new(0x400);
        let a = img.put_str(0x200, "Name_A");
        let b = img.put_str(0x220, "Name_B");
        let (f1, f2) = (0x4001_1000, 0x4001_1040);
        table_at(&mut img, 0x40, &[(a, f1), (b, f2)]); // only 2 records
        let entries = thumb_entries(&[f1, f2]);
        let scan = scan(&img.bytes, BASE, &entries, &HashSet::new(), &HashSet::new());
        assert!(scan.entries.is_empty(), "a 2-record run is below MIN_RUN");
    }

    /// A 4-record reversed `{fn|1, name}` table must be detected AND paired
    /// correctly. The forward `{name,fn}` layout, read one word in, would misread
    /// it as a 3-record table pairing each name with the *next* function — the
    /// detector must prefer the longer, correct interpretation.
    #[test]
    fn scan_detects_reversed_layout_without_mispairing() {
        let mut img = Img::new(0x400);
        let a = img.put_str(0x200, "Rev_A");
        let b = img.put_str(0x220, "Rev_B");
        let c = img.put_str(0x240, "Rev_C");
        let d = img.put_str(0x260, "Rev_D");
        let (f1, f2, f3, f4) = (0x4001_1000, 0x4001_1040, 0x4001_1080, 0x4001_10c0);
        for (k, (na, fa)) in [(a, f1), (b, f2), (c, f3), (d, f4)].iter().enumerate() {
            img.put_u32(0x40 + k * 8, *fa as u32 | 1); // fn first
            img.put_u32(0x40 + k * 8 + 4, *na as u32); // name second
        }
        let entries = thumb_entries(&[f1, f2, f3, f4]);
        let scan = scan(&img.bytes, BASE, &entries, &HashSet::new(), &HashSet::new());
        assert_eq!(scan.entries.len(), 4, "all four reversed records detected");
        // correct pairing — NOT name_k with fn_{k+1}
        assert_eq!(scan.names.get(&f1), Some(&"Rev_A".to_string()));
        assert_eq!(scan.names.get(&f2), Some(&"Rev_B".to_string()));
        assert_eq!(scan.names.get(&f4), Some(&"Rev_D".to_string()));
    }
}
