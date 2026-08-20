//! Pure Rizin inventory, capture-shape, and outgoing-xref adaptation.
//!
//! Execution remains coordinator-owned, so these crate-internal seams are
//! intentionally available before they are reachable from the public runner.
#![allow(dead_code)]

use super::radare2::FunctionRecord;
use super::{ProducerIdentity, ThumbProducer, discover};
use crate::error::{Error, Result};
use crate::execution_ranges::DecodeRange;
use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::fmt;
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

struct ObjectOnly;

impl<'de> Deserialize<'de> for ObjectOnly {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ObjectOnlyVisitor)
    }
}

struct ObjectOnlyVisitor;

impl<'de> Visitor<'de> for ObjectOnlyVisitor {
    type Value = ObjectOnly;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(ObjectOnly)
    }
}

struct InventoryCount(usize);

impl<'de> Deserialize<'de> for InventoryCount {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(InventoryVisitor)
    }
}

struct InventoryVisitor;

impl<'de> Visitor<'de> for InventoryVisitor {
    type Value = InventoryCount;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Rizin function inventory array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut count = 0usize;
        while sequence.next_element::<ObjectOnly>()?.is_some() {
            count = count
                .checked_add(1)
                .ok_or_else(|| de::Error::custom("Rizin inventory count overflow"))?;
        }
        Ok(InventoryCount(count))
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

pub(crate) fn read_rizin_xrefs(capture: &Path, cap: usize) -> Result<Vec<RizinXref>> {
    let file = std::fs::File::open(capture)?;
    let mut deserializer = serde_json::Deserializer::from_reader(std::io::BufReader::new(file));
    let InventoryCount(inventory_count) = InventoryCount::deserialize(&mut deserializer)
        .map_err(|error| Error::Serialize(format!("parse Rizin capture inventory: {error}")))?;
    for _ in 0..inventory_count {
        ObjectOnly::deserialize(&mut deserializer)
            .map_err(|error| Error::Serialize(format!("parse Rizin capture pdfj body: {error}")))?;
    }
    let mut xrefs = deserializer
        .deserialize_seq(XrefSequence { cap })
        .and_then(|xrefs| deserializer.end().map(|()| xrefs))
        .map_err(|error| Error::Serialize(format!("parse trailing Rizin axlj: {error}")))?;
    xrefs.sort_unstable_by_key(|xref| (xref.from, xref.to));
    xrefs.dedup();
    Ok(xrefs)
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
            let contents = format!("[]\n[{record}]");
            let (_dir, path) = capture(&contents);
            assert!(
                read_rizin_xrefs(&path, RIZIN_SELECTED_XREF_CAP).is_err(),
                "{case} must fail"
            );
        }

        let (_dir, path) = capture(
            r#"[]
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
            r#"[]
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
