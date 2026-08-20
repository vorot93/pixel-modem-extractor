//! Address-indexed view of a `disasm.lst`-format text file. Build once
//! per image (one linear pass over the file), then look up per-function
//! slices in O(log L + k) via binary search.

/// Address-indexed view of a full-image `disasm.lst` for O(log L + k)
/// per-function slicing. Lifted from `globals::DisasmIndex` (Phase 3.0.1
/// Task 12) and unified with `symbolicate`'s analogous need.
///
/// **Sortedness invariant.** `slice_for` binary-searches by address, so
/// the backing lines MUST be in non-decreasing address order. Ghidra's
/// `ExportDecomp.java` emits `disasm.lst` as a linear address-ordered
/// listing (verified on `02_MAIN`: 0 of 7,627,481 lines out of order); we
/// preserve file order at construction and trust it at lookup. A future
/// emitter that breaks sortedness would silently produce wrong slices —
/// if `disasm.lst` ever stops being sorted, add an explicit sort step
/// here (or a panic on construction).
///
/// Equivalent to a `BTreeMap<u64, &str>` view but without the per-node
/// overhead: a single sorted `Vec` we binary-search (`partition_point`).
pub struct DisasmIndex<'a> {
    src: &'a str,
    /// `(addr, line-without-terminator, start-byte, end-byte-including-terminator)`
    /// per address line, in file order.
    lines: Vec<(u64, &'a str, usize, usize)>,
}

impl<'a> DisasmIndex<'a> {
    /// Build the index: one linear pass to parse leading addresses,
    /// dropping non-address lines (comments, blanks, the symbolication
    /// sentinel). O(L) where L = line count.
    pub fn new(disasm: &'a str) -> Self {
        // `split_inclusive` keeps each line's terminator so byte ranges
        // into `disasm` can be recovered; the stored `line` strips the
        // terminator(s) exactly like `str::lines`, keeping `slice_for`'s
        // joined semantics unchanged.
        let mut lines = Vec::new();
        let mut offset = 0usize;
        for chunk in disasm.split_inclusive('\n') {
            let start = offset;
            offset += chunk.len();
            let line = match chunk.strip_suffix('\n') {
                Some(l) => l.strip_suffix('\r').unwrap_or(l),
                None => chunk.strip_suffix('\r').unwrap_or(chunk),
            };
            if let Some(addr) = line_addr(line) {
                lines.push((addr, line, start, offset));
            }
        }
        Self { src: disasm, lines }
    }

    /// Lines whose leading address is in `[entry, end)`, joined with `\n`
    /// terminators. O(log L) to find the start, then O(k) to copy the
    /// matching lines (k = matching line count).
    pub fn slice_for(&self, entry: u64, end: u64) -> String {
        let mut out = String::new();
        let start = self.lines.partition_point(|(a, _, _, _)| *a < entry);
        for (addr, line, _, _) in &self.lines[start..] {
            if *addr >= end {
                break;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// Zero-copy view of the same lines [`Self::slice_for`] would join:
    /// borrowed from the backing buffer whenever that is byte-identical
    /// (Unix `\n` separators and a terminator after the final matching
    /// line), and an owned copy otherwise (CRLF separators, or the final
    /// matching line lacking its trailing newline). The returned value is
    /// ALWAYS equal to `slice_for(entry, end)` — the fallback exists so a
    /// borrowed range can never drift from the joined form. This is the
    /// memory-envelope lever for `symbolicate`'s ARM loader: pathological
    /// wide-range function records must not each copy ~hundreds of MB of
    /// owned text.
    pub fn slice_cow(&self, entry: u64, end: u64) -> std::borrow::Cow<'a, str> {
        let start = self.lines.partition_point(|(a, _, _, _)| *a < entry);
        let mut first: Option<usize> = None;
        let mut last_end = 0usize;
        for (addr, _, s, e) in &self.lines[start..] {
            if *addr >= end {
                break;
            }
            if first.is_none() {
                first = Some(*s);
            }
            last_end = *e;
        }
        let Some(first) = first else {
            return std::borrow::Cow::Borrowed("");
        };
        let view = &self.src[first..last_end];
        // Byte-identical to the '\n'-joined form only when the borrowed
        // bytes carry exactly '\n' separators and end with one.
        if !view.contains('\r') && view.ends_with('\n') {
            std::borrow::Cow::Borrowed(view)
        } else {
            std::borrow::Cow::Owned(self.slice_for(entry, end))
        }
    }
}

/// Parse the leading address of a `disasm.lst` line. The address is the
/// text before the first `": "` (the bytes-column separator); tolerate
/// an optional address-space prefix (`ram:40010120:` → `40010120`).
/// Returns `None` for non-address lines (comments, the sentinel, blanks).
///
/// Unified from `symbolicate::line_addr` and `globals::disasm_line_addr`
/// (which were byte-equivalent modulo the `parse_hex` vs inline radix
/// choice — both parse the same `0x`-prefixed or bare hex token).
pub fn line_addr(line: &str) -> Option<u64> {
    let head = line.trim_start().split_once(": ")?.0;
    let tok = head.rsplit(':').next()?;
    u64::from_str_radix(tok.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_cow_matches_slice_for_on_unix_lines() {
        let disasm = "\
0x1000: 00  mov r0, #1
0x1004: 00  mov r1, #2
0x1008: 00  mov r2, #3
0x100c: 00  mov r3, #4
";
        let idx = DisasmIndex::new(disasm);
        // Borrowed (zero-copy) for every ordinary \n-terminated range.
        assert!(matches!(
            idx.slice_cow(0x1000, 0x1008),
            std::borrow::Cow::Borrowed(_)
        ));
        for (entry, end) in [
            (0x1000, 0x1008),
            (0x1008, 0x1010),
            (0x1000, 0x1010),
            (0x1004, 0x1008),
        ] {
            assert_eq!(
                idx.slice_cow(entry, end),
                idx.slice_for(entry, end),
                "{entry:#x}-{end:#x}"
            );
        }
        // No matching lines: both empty.
        assert_eq!(idx.slice_cow(0x2000, 0x2008), "");
        assert_eq!(idx.slice_cow(0x2000, 0x2008), idx.slice_for(0x2000, 0x2008));
    }

    #[test]
    fn slice_cow_falls_back_to_owned_and_still_matches_slice_for() {
        // CRLF separators and a missing final newline both make a borrowed
        // byte-range view differ from `slice_for`'s '\n'-joined output, so
        // the view must degrade to an owned copy — never drift.
        let disasm = "0x1000: 00  mov r0, #1\r\n0x1004: 00  mov r1, #2\r\n0x1008: 00  mov r2, #3";
        let idx = DisasmIndex::new(disasm);
        assert!(matches!(
            idx.slice_cow(0x1000, 0x100c),
            std::borrow::Cow::Owned(_)
        ));
        assert_eq!(idx.slice_cow(0x1000, 0x100c), idx.slice_for(0x1000, 0x100c));
        // Final line without a trailing newline (no CRs): owned fallback,
        // still identical.
        let no_nl = "0x1000: 00  mov r0, #1\n0x1004: 00  mov r1, #2";
        let idx2 = DisasmIndex::new(no_nl);
        assert!(matches!(
            idx2.slice_cow(0x1000, 0x1008),
            std::borrow::Cow::Owned(_)
        ));
        assert_eq!(
            idx2.slice_cow(0x1000, 0x1008),
            idx2.slice_for(0x1000, 0x1008)
        );
    }

    #[test]
    fn disasm_index_returns_correct_slice_for_function_range() {
        // Two adjacent functions covering [0x1000, 0x1008) and [0x1008, 0x1010).
        // Half-open: 0x1008 must NOT appear in fn1's slice.
        let disasm = "\
0x1000: 00  mov r0, #1
0x1004: 00  mov r1, #2
0x1008: 00  mov r2, #3
0x100c: 00  mov r3, #4
";
        let idx = DisasmIndex::new(disasm);
        assert_eq!(
            idx.slice_for(0x1000, 0x1008),
            "0x1000: 00  mov r0, #1\n0x1004: 00  mov r1, #2\n"
        );
        assert_eq!(
            idx.slice_for(0x1008, 0x1010),
            "0x1008: 00  mov r2, #3\n0x100c: 00  mov r3, #4\n"
        );
    }

    #[test]
    fn disasm_index_handles_empty_disasm() {
        let idx = DisasmIndex::new("");
        assert_eq!(idx.slice_for(0, 0x100), "");
        assert_eq!(idx.slice_for(0, 0), "");
    }

    #[test]
    fn disasm_index_handles_no_matching_range() {
        // [entry, end) outside any line's address → empty result.
        let disasm = "0x4000: 00  nop\n0x4004: 00  nop\n";
        let idx = DisasmIndex::new(disasm);
        assert_eq!(idx.slice_for(0, 0x100), "");
        assert_eq!(idx.slice_for(0x10000, 0x20000), "");
    }

    #[test]
    fn line_addr_parses_plain_space_qualified_and_prefixed() {
        // Bare hex
        assert_eq!(line_addr("40010120: 00  mov ..."), Some(0x40010120));
        // 0x-prefixed
        assert_eq!(line_addr("0x40010120: 00  mov ..."), Some(0x40010120));
        // 0X-prefixed (uppercase)
        assert_eq!(line_addr("0X40010120: 00  mov ..."), Some(0x40010120));
        // Address-space-prefixed
        assert_eq!(line_addr("ram:40010120: 00  mov ..."), Some(0x40010120));
        // Leading whitespace tolerated
        assert_eq!(line_addr("  40010120: 00  mov ..."), Some(0x40010120));
        // Non-address lines return None
        assert_eq!(line_addr("// FUNCTION 40010120"), None);
        assert_eq!(line_addr(""), None);
        assert_eq!(line_addr("nop"), None);
    }
}
