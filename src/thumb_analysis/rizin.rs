//! Rizin inventory, capture-shape, and outgoing-xref adaptation for the
//! coordinator's failure-only fallback.

use super::radare2::FunctionRecord;
use super::stream::{ValueScanner, read_rizin_pdfj_value, scan_rizin_inventory};
use super::{ProducerIdentity, ThumbProducer, discover};
use crate::error::{Error, Result};
use crate::execution_ranges::DecodeRange;
use serde::Deserializer;
use serde::de::{self, SeqAccess, Visitor};
use serde_json::Value;
use std::fmt;
use std::io::{Seek, SeekFrom};
use std::path::Path;

pub(crate) const RIZIN_SELECTED_XREF_CAP: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RizinXref {
    pub from: u32,
    pub to: u64,
}

fn json_u64(value: &Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }
    if let Some(number) = value.as_i64() {
        return (number >= 0).then_some(number as u64);
    }
    let value = value.as_str()?;
    value
        .strip_prefix("0x")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .or_else(|| value.parse::<u64>().ok())
}

pub(super) fn function_record(raw: &Value) -> FunctionRecord {
    FunctionRecord {
        entry: raw
            .get("offset")
            .or_else(|| raw.get("addr"))
            .and_then(json_u64),
        end: raw.get("maxbound").and_then(json_u64),
        real_size: raw.get("realsz").and_then(json_u64),
        bounding_size: raw.get("size").and_then(json_u64),
        name: raw.get("name").and_then(Value::as_str).map(str::to_owned),
    }
}

fn is_selected_xref(record: &Value) -> bool {
    let Some(kind) = record.get("type").and_then(Value::as_str) else {
        return false;
    };
    let kind = kind.to_ascii_lowercase();
    let included = ["data", "str", "string", "mem", "ptr", "read"]
        .iter()
        .any(|needle| kind.contains(needle));
    let excluded = ["code", "call", "jump", "exec"]
        .iter()
        .any(|needle| kind.contains(needle));
    included && !excluded
}

fn read_trailing_xrefs(
    capture: &Path,
    scanner: &mut ValueScanner<std::io::BufReader<std::fs::File>>,
    cap: usize,
) -> Result<Vec<RizinXref>> {
    let trailing = scanner.next_streamed_value()?.ok_or_else(|| {
        Error::Serialize("Rizin capture lacks a valid trailing axlj array".to_string())
    })?;
    if trailing.opener != b'[' {
        return Err(Error::Serialize(
            "Rizin capture axlj array is not the final body sequence".to_string(),
        ));
    }

    let mut reader = std::io::BufReader::new(std::fs::File::open(capture)?);
    reader.seek(SeekFrom::Start(trailing.start))?;
    let mut deserializer = serde_json::Deserializer::from_reader(&mut reader);
    let mut xrefs = deserializer
        .deserialize_seq(XrefSequence { cap })
        .map_err(|error| Error::Serialize(format!("parse trailing Rizin axlj: {error}")))?;
    drop(deserializer);

    if scanner.next_streamed_any_value()?.is_some() {
        return Err(Error::Serialize(
            "Rizin capture contains JSON after the trailing axlj array".to_string(),
        ));
    }
    xrefs.sort_unstable_by_key(|xref| (xref.from, xref.to));
    xrefs.dedup();
    Ok(xrefs)
}

struct XrefSequence {
    cap: usize,
}

impl<'de> Visitor<'de> for XrefSequence {
    type Value = Vec<RizinXref>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a trailing Rizin axlj array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut xrefs = Vec::new();
        while let Some(record) = sequence.next_element::<Value>()? {
            if !is_selected_xref(&record) {
                continue;
            }
            let from = record
                .get("from")
                .and_then(json_u64)
                .and_then(|from| u32::try_from(from).ok())
                .ok_or_else(|| {
                    de::Error::custom(
                        "selected Rizin xref lacks a valid canonical u32 source address",
                    )
                })?;
            let to = record
                .get("to")
                .or_else(|| record.get("addr"))
                .and_then(json_u64)
                .ok_or_else(|| {
                    de::Error::custom("selected Rizin xref lacks a valid target address")
                })?;
            if xrefs.len() >= self.cap {
                return Err(de::Error::custom(format!(
                    "selected Rizin xref cap of {} records exceeded",
                    self.cap
                )));
            }
            xrefs.push(RizinXref { from, to });
        }
        Ok(xrefs)
    }
}

#[cfg(test)]
pub(crate) fn read_rizin_xrefs(capture: &Path, cap: usize) -> Result<Vec<RizinXref>> {
    read_rizin_xrefs_inner(capture, cap, usize::MAX)
}

fn read_rizin_xrefs_inner(
    capture: &Path,
    cap: usize,
    generic_value_limit: usize,
) -> Result<Vec<RizinXref>> {
    let file = std::fs::File::open(capture)?;
    let mut scanner =
        ValueScanner::with_value_limit(std::io::BufReader::new(file), generic_value_limit);
    let inventory = scan_rizin_inventory(&mut scanner, function_record)?;
    for position in 0..inventory.len() {
        read_rizin_pdfj_value(&mut scanner, position)?;
    }
    read_trailing_xrefs(capture, &mut scanner, cap)
}

pub(super) fn read_rizin_xrefs_with_value_limit(
    capture: &Path,
    cap: usize,
    generic_value_limit: usize,
) -> Result<Vec<RizinXref>> {
    read_rizin_xrefs_inner(capture, cap, generic_value_limit)
}

pub(crate) fn refs_for_ranges(xrefs: &[RizinXref], ranges: &[DecodeRange]) -> Vec<String> {
    let mut targets = std::collections::BTreeSet::new();
    for range in ranges {
        let start = xrefs.partition_point(|xref| xref.from < range.start);
        let end = xrefs.partition_point(|xref| xref.from < range.end);
        targets.extend(xrefs[start..end].iter().map(|xref| xref.to));
    }
    targets
        .into_iter()
        .map(|target| format!("0x{target:x}"))
        .collect()
}

pub fn discover_rizin() -> Result<ProducerIdentity> {
    discover("rizin", ThumbProducer::Rizin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution_ranges::{DecodeIsa, DecodeRange};
    use std::path::PathBuf;

    fn capture(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capture.stdout");
        std::fs::write(&path, contents).unwrap();
        (dir, path)
    }

    fn large_axlj(count: usize) -> String {
        let records = (0..count)
            .map(|index| {
                format!(
                    "{{\"from\":{},\"to\":{},\"type\":\"DATA\"}}",
                    0x1000 + index,
                    0x8000 + index
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!("[{records}]")
    }

    #[test]
    fn axlj_filters_every_type_variant_and_sorts_deduplicates_pairs() {
        let (_dir, path) = capture(
            r#"[{"offset":4096,"xrefs_to":[{"from":1,"to":2,"type":"DATA"}],"codexrefs":[{"from":3,"to":4,"type":"DATA"}]}]
{"addr":4096,"ops":[],"xrefs_to":[{"from":5,"to":6,"type":"DATA"}],"incoming":[{"from":7,"to":8,"type":"DATA"}]}
[
  {"from":4101,"to":36869,"type":"DATA"},
  {"from":4096,"addr":36864,"type":"str"},
  {"from":4097,"to":36865,"type":"STRING"},
  {"from":4098,"to":36866,"type":"mem"},
  {"from":4099,"to":36867,"type":"PtR"},
  {"from":4100,"to":36868,"type":"read"},
  {"from":4096,"addr":36864,"type":"STR"},
  {"type":"CODE"},
  {"type":"CALL"},
  {"type":"jump"},
  {"type":"exec"},
  {"from":8192,"to":12288,"type":"data/code"},
  {"from":"malformed but unselected","type":"unknown"},
  {"from":1,"to":2,"type":7},
  null
]"#,
        );

        let xrefs = read_rizin_xrefs(&path, RIZIN_SELECTED_XREF_CAP).unwrap();

        assert_eq!(
            xrefs,
            vec![
                RizinXref {
                    from: 0x1000,
                    to: 0x9000,
                },
                RizinXref {
                    from: 0x1001,
                    to: 0x9001,
                },
                RizinXref {
                    from: 0x1002,
                    to: 0x9002,
                },
                RizinXref {
                    from: 0x1003,
                    to: 0x9003,
                },
                RizinXref {
                    from: 0x1004,
                    to: 0x9004,
                },
                RizinXref {
                    from: 0x1005,
                    to: 0x9005,
                },
            ]
        );
    }

    #[test]
    fn axlj_accepts_empty_trailing_array() {
        let (_dir, path) = capture("[{\"offset\":4096}]\n{\"ops\":[]}\n[]\n");

        assert_eq!(
            read_rizin_xrefs(&path, RIZIN_SELECTED_XREF_CAP).unwrap(),
            Vec::<RizinXref>::new()
        );
    }

    #[test]
    fn axlj_accepts_leading_and_interstitial_diagnostics() {
        let (_dir, path) = capture(
            r#"WARN: analysis started
[{"offset":4096}]
INFO: [true diagnostic] inventory complete
{"addr":4096,"ops":[]}
DEBUG: [false diagnostic] collecting outgoing references
[{"from":4096,"to":8192,"type":"DATA"}]"#,
        );

        assert_eq!(
            read_rizin_xrefs(&path, RIZIN_SELECTED_XREF_CAP).unwrap(),
            vec![RizinXref {
                from: 0x1000,
                to: 0x2000,
            }]
        );
    }

    #[test]
    fn axlj_distinguishes_same_line_scalars_from_diagnostic_fragments() {
        let diagnostics = [
            ("string suffix", " \"extra\" suffix"),
            ("unterminated string", " \"unterminated"),
            ("number suffix", " 42ms"),
            ("boolean suffix", " true-ish"),
            ("null suffix", " null pointer"),
            ("incomplete boolean", " tru"),
            ("incomplete number", " -"),
            ("embedded scalar", " diagnostic=true"),
            ("bracketed keyword diagnostic", " [true diagnostic]"),
            ("whitespace", " \t  "),
        ];
        for (case, suffix) in diagnostics {
            let contents = format!("[{{\"offset\":4096}}]\n{{\"ops\":[]}}\n[]{suffix}");
            let (_dir, path) = capture(&contents);
            assert!(
                read_rizin_xrefs(&path, RIZIN_SELECTED_XREF_CAP).is_ok(),
                "{case} must remain diagnostic noise"
            );
        }

        let scalars = [
            ("string", " \"extra\""),
            ("number", " 42"),
            ("true", " true"),
            ("false", " false"),
            ("null", " null"),
            ("scalar sequence", " true false"),
        ];
        let accepted = scalars
            .into_iter()
            .filter_map(|(case, suffix)| {
                let contents = format!("[{{\"offset\":4096}}]\n{{\"ops\":[]}}\n[]{suffix}");
                let (_dir, path) = capture(&contents);
                read_rizin_xrefs(&path, RIZIN_SELECTED_XREF_CAP)
                    .is_ok()
                    .then_some(case)
            })
            .collect::<Vec<_>>();
        assert!(
            accepted.is_empty(),
            "accepted same-line trailing scalars: {}",
            accepted.join(", ")
        );
    }

    #[test]
    fn axlj_distinguishes_newline_scalars_from_diagnostic_fragments() {
        let diagnostics = [
            ("string suffix", "\n\"extra\" suffix\n"),
            ("unterminated string", "\n\"unterminated\n"),
            ("number suffix", "\n-42 percent\n"),
            ("boolean suffix", "\nfalse-positive\n"),
            ("null suffix", "\nnullability unknown\n"),
            ("incomplete boolean", "\nfal\n"),
            ("embedded scalar", "\nDEBUG true\n"),
            (
                "whitespace and bracketed noise",
                "\n \t\r\nDEBUG: [true diagnostic]\nINFO: complete\n",
            ),
        ];
        for (case, suffix) in diagnostics {
            let contents = format!("[{{\"offset\":4096}}]\n{{\"ops\":[]}}\n[]{suffix}");
            let (_dir, path) = capture(&contents);
            assert!(
                read_rizin_xrefs(&path, RIZIN_SELECTED_XREF_CAP).is_ok(),
                "{case} must remain diagnostic noise"
            );
        }

        let scalars = [
            ("string", "\n\"extra\"\n"),
            ("number", "\n-42\n"),
            ("true", "\ntrue\n"),
            ("false", "\nfalse\n"),
            ("null", "\nnull\n"),
            ("scalar before later noise", "\ntrue\nDEBUG: complete\n"),
        ];
        let accepted = scalars
            .into_iter()
            .filter_map(|(case, suffix)| {
                let contents = format!("[{{\"offset\":4096}}]\n{{\"ops\":[]}}\n[]{suffix}");
                let (_dir, path) = capture(&contents);
                read_rizin_xrefs(&path, RIZIN_SELECTED_XREF_CAP)
                    .is_ok()
                    .then_some(case)
            })
            .collect::<Vec<_>>();
        assert!(
            accepted.is_empty(),
            "accepted newline trailing scalars: {}",
            accepted.join(", ")
        );
    }

    #[test]
    fn axlj_invalid_inventory_stops_before_large_array_generic_scan() {
        let large = large_axlj(32);
        let captures = [
            ("empty inventory", format!("[]\n{large}")),
            (
                "ops-disqualified inventory",
                format!("[{{\"ops\":[]}}]\n{{\"ops\":[]}}\n{large}"),
            ),
        ];

        for (case, contents) in captures {
            let (_dir, path) = capture(&contents);
            let error =
                read_rizin_xrefs_with_value_limit(&path, RIZIN_SELECTED_XREF_CAP, 64).unwrap_err();
            let message = error.to_string();
            assert!(message.contains("inventory"), "{case}: {message}");
            assert!(
                !message.contains("generic JSON value limit"),
                "{case} crossed into the large array: {message}"
            );
        }
    }

    #[test]
    fn axlj_large_sequence_streams_beyond_generic_value_limit_and_honors_cap() {
        let contents = format!(
            "WARN: start\n[{{\"offset\":4096}}]\nINFO: body\n{{\"ops\":[]}}\nDEBUG: xrefs\n{}",
            large_axlj(32)
        );
        let (_dir, path) = capture(&contents);

        let xrefs = read_rizin_xrefs_with_value_limit(&path, 32, 64).unwrap();
        assert_eq!(xrefs.len(), 32);
        assert_eq!(
            xrefs.first(),
            Some(&RizinXref {
                from: 0x1000,
                to: 0x8000,
            })
        );
        assert_eq!(
            xrefs.last(),
            Some(&RizinXref {
                from: 0x101f,
                to: 0x801f,
            })
        );

        let error = read_rizin_xrefs_with_value_limit(&path, 8, 64).unwrap_err();
        assert!(error.to_string().contains("cap"), "{error}");
    }

    #[test]
    fn axlj_shared_scanner_preserves_all_trailing_sequence_failures() {
        let cases = [
            ("missing", "[{\"offset\":4096}]\n{\"ops\":[]}"),
            (
                "malformed",
                "[{\"offset\":4096}]\n{\"ops\":[]}\n[{\"type\":\"DATA\"}",
            ),
            ("duplicate", "[{\"offset\":4096}]\n{\"ops\":[]}\n[]\n[]"),
            ("non-trailing", "[{\"offset\":4096}]\n[]\n{\"ops\":[]}"),
            (
                "additional object",
                "[{\"offset\":4096}]\n{\"ops\":[]}\n[]\n{\"extra\":true}",
            ),
        ];

        for (case, contents) in cases {
            let (_dir, path) = capture(contents);
            assert!(
                read_rizin_xrefs_with_value_limit(&path, RIZIN_SELECTED_XREF_CAP, 64,).is_err(),
                "{case} must fail"
            );
        }

        let (_dir, path) =
            capture("WARN: start\n[{\"offset\":4096}]\nINFO: body\n{\"ops\":[]}\nDEBUG: xrefs\n[]");
        assert!(
            read_rizin_xrefs_with_value_limit(&path, RIZIN_SELECTED_XREF_CAP, 64)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn axlj_rejects_missing_malformed_duplicate_non_trailing_and_additional_values() {
        let cases = [
            ("missing axlj", "[{\"offset\":4096}]\n{\"ops\":[]}"),
            (
                "malformed axlj",
                "[{\"offset\":4096}]\n{\"ops\":[]}\n[{\"type\":\"DATA\"}",
            ),
            (
                "duplicate axlj",
                "[{\"offset\":4096}]\n{\"ops\":[]}\n[]\n[]",
            ),
            ("non-trailing axlj", "[{\"offset\":4096}]\n[]\n{\"ops\":[]}"),
            (
                "additional trailing object",
                "[{\"offset\":4096}]\n{\"ops\":[]}\n[]\n{\"extra\":true}",
            ),
            (
                "additional pdfj",
                "[{\"offset\":4096}]\n{\"ops\":[]}\n{\"ops\":[]}\n[]",
            ),
        ];

        for (case, contents) in cases {
            let (_dir, path) = capture(contents);
            assert!(
                read_rizin_xrefs(&path, RIZIN_SELECTED_XREF_CAP).is_err(),
                "{case} must fail"
            );
        }
    }

    #[test]
    fn axlj_requires_inventory_records_and_one_pdfj_object_each() {
        let cases = [
            ("non-array inventory", "{\"offset\":4096}\n[]"),
            ("non-object inventory record", "[7]\n{}\n[]"),
            ("missing pdfj", "[{\"offset\":4096}]\n[]"),
            ("non-object pdfj", "[{\"offset\":4096}]\n7\n[]"),
            (
                "too few pdfj objects",
                "[{\"offset\":4096},{\"offset\":8192}]\n{}\n[]",
            ),
        ];

        for (case, contents) in cases {
            let (_dir, path) = capture(contents);
            assert!(
                read_rizin_xrefs(&path, RIZIN_SELECTED_XREF_CAP).is_err(),
                "{case} must fail"
            );
        }
    }

    #[test]
    fn axlj_selected_records_require_valid_source_and_target_domains() {
        let invalid_records = [
            ("missing from", r#"{"to":2,"type":"DATA"}"#),
            ("malformed from", r#"{"from":"bad","to":2,"type":"DATA"}"#),
            ("negative from", r#"{"from":-1,"to":2,"type":"DATA"}"#),
            ("fractional from", r#"{"from":1.5,"to":2,"type":"DATA"}"#),
            (
                "overflowed from",
                r#"{"from":4294967296,"to":2,"type":"DATA"}"#,
            ),
            ("missing target", r#"{"from":1,"type":"DATA"}"#),
            ("malformed target", r#"{"from":1,"to":"bad","type":"DATA"}"#),
            ("negative target", r#"{"from":1,"to":-1,"type":"DATA"}"#),
            ("fractional target", r#"{"from":1,"to":1.5,"type":"DATA"}"#),
            (
                "overflowed target",
                r#"{"from":1,"to":18446744073709551616,"type":"DATA"}"#,
            ),
        ];

        for (case, record) in invalid_records {
            let contents = format!("[{{\"offset\":4096}}]\n{{}}\n[{record}]");
            let (_dir, path) = capture(&contents);
            assert!(
                read_rizin_xrefs(&path, RIZIN_SELECTED_XREF_CAP).is_err(),
                "{case} must fail"
            );
        }

        let (_dir, path) = capture(
            r#"[{"offset":4096}]
{}
[
  {"from":"0xffffffff","to":"0xffffffffffffffff","type":"DATA"},
  {"from":0,"addr":18446744073709551615,"type":"read"}
]"#,
        );
        assert_eq!(
            read_rizin_xrefs(&path, RIZIN_SELECTED_XREF_CAP).unwrap(),
            vec![
                RizinXref {
                    from: 0,
                    to: u64::MAX,
                },
                RizinXref {
                    from: u32::MAX,
                    to: u64::MAX,
                },
            ]
        );
    }

    #[test]
    fn axlj_applies_selected_record_cap_before_deduplication() {
        let (_dir, path) = capture(
            r#"[{"offset":4096}]
{}
[
  {"from":4096,"to":8192,"type":"DATA"},
  {"from":4096,"to":8192,"type":"DATA"}
]"#,
        );

        let error = read_rizin_xrefs(&path, 1).unwrap_err();

        assert!(error.to_string().contains("cap"), "{error}");
    }

    #[test]
    fn refs_for_overlapping_ranges_union_sorted_targets_for_every_function() {
        let xrefs = vec![
            RizinXref {
                from: 0x0fff,
                to: 0xdead,
            },
            RizinXref {
                from: 0x1000,
                to: 0x9002,
            },
            RizinXref {
                from: 0x1001,
                to: 0xabcd,
            },
            RizinXref {
                from: 0x1002,
                to: 0x9001,
            },
            RizinXref {
                from: 0x1003,
                to: 0x9000,
            },
            RizinXref {
                from: 0x1004,
                to: 0x9003,
            },
            RizinXref {
                from: 0x1005,
                to: 0x9001,
            },
            RizinXref {
                from: 0x1006,
                to: u64::MAX,
            },
        ];
        let first = [DecodeRange {
            isa: DecodeIsa::Thumb,
            start: 0x1000,
            end: 0x1004,
        }];
        let second = [DecodeRange {
            isa: DecodeIsa::Thumb,
            start: 0x1002,
            end: 0x1006,
        }];
        let discontiguous = [first[0], second[0]];

        assert_eq!(
            refs_for_ranges(&xrefs, &first),
            vec!["0x9000", "0x9001", "0x9002", "0xabcd"]
        );
        assert_eq!(
            refs_for_ranges(&xrefs, &second),
            vec!["0x9000", "0x9001", "0x9003"]
        );
        assert_eq!(
            refs_for_ranges(&xrefs, &discontiguous),
            vec!["0x9000", "0x9001", "0x9002", "0x9003", "0xabcd"]
        );
        assert!(refs_for_ranges(&xrefs, &[]).is_empty());
    }
}
