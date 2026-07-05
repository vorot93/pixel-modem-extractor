//! Decode the `pw_token_db` artifact: a Pigweed `pw_tokenizer` binary token
//! database (the `TOKENS` format). Maps 32-bit tokens -> format/identifier
//! strings. `parse`/`serialize` are an exact round-trip (the faithfulness oracle).
use crate::error::{Error, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"TOKENS\0\0";
const HEADER_LEN: usize = 16;
const ENTRY_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Date {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub token: u32,
    pub date_removed: Option<Date>,
    pub string: String,
}

#[derive(Debug)]
pub struct Database {
    pub reserved: u32,
    pub entries: Vec<Entry>,
}

pub fn parse(bytes: &[u8]) -> Result<Database> {
    if bytes.get(0..8) != Some(&MAGIC[..]) {
        return Err(Error::BadTokenDb("bad or missing TOKENS magic".into()));
    }
    if bytes.len() < HEADER_LEN {
        return Err(Error::BadTokenDb("truncated header".into()));
    }
    let count = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    let reserved = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let table_end = count
        .checked_mul(ENTRY_LEN)
        .and_then(|n| n.checked_add(HEADER_LEN))
        .ok_or_else(|| Error::BadTokenDb("entry count overflow".into()))?;
    if bytes.len() < table_end {
        return Err(Error::BadTokenDb(format!(
            "truncated entry table: need {table_end} bytes, have {}",
            bytes.len()
        )));
    }

    // Pass 1: tokens + removal dates (strings follow the whole entry table).
    let mut meta: Vec<(u32, Option<Date>)> = Vec::with_capacity(count);
    for chunk in bytes[HEADER_LEN..table_end].chunks_exact(ENTRY_LEN) {
        let token = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let date_removed = if chunk[4..8] == [0xFF, 0xFF, 0xFF, 0xFF] {
            None
        } else {
            Some(Date {
                day: chunk[4],
                month: chunk[5],
                year: u16::from_le_bytes([chunk[6], chunk[7]]),
            })
        };
        meta.push((token, date_removed));
    }

    // Pass 2: exactly `count` NUL-terminated strings, ending at EOF.
    let mut entries = Vec::with_capacity(count);
    let mut p = table_end;
    for (token, date_removed) in meta {
        let rel = bytes[p..].iter().position(|&c| c == 0).ok_or_else(|| {
            Error::BadTokenDb("string table underrun (missing NUL terminator)".into())
        })?;
        let string = std::str::from_utf8(&bytes[p..p + rel])
            .map_err(|e| Error::BadTokenDb(format!("invalid UTF-8 in string table: {e}")))?
            .to_string();
        entries.push(Entry {
            token,
            date_removed,
            string,
        });
        p += rel + 1;
    }
    if p != bytes.len() {
        return Err(Error::BadTokenDb(format!(
            "trailing bytes after string table: {} extra",
            bytes.len() - p
        )));
    }

    Ok(Database { reserved, entries })
}

pub fn serialize(db: &Database) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(db.entries.len() as u32).to_le_bytes());
    out.extend_from_slice(&db.reserved.to_le_bytes());
    for e in &db.entries {
        out.extend_from_slice(&e.token.to_le_bytes());
        match e.date_removed {
            None => out.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]),
            Some(d) => {
                out.push(d.day);
                out.push(d.month);
                out.extend_from_slice(&d.year.to_le_bytes());
            }
        }
    }
    for e in &db.entries {
        out.extend_from_slice(e.string.as_bytes());
        out.push(0);
    }
    out
}

fn csv_quote(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Canonical Pigweed CSV: one row per unique `(token, string)` pair, sorted by
/// `(token, string)`. Columns: `token,date_removed,string` (LF-terminated).
pub fn write_csv(db: &Database) -> String {
    use std::collections::BTreeMap;
    let mut uniq: BTreeMap<(u32, String), Option<Date>> = BTreeMap::new();
    for e in &db.entries {
        uniq.entry((e.token, e.string.clone()))
            .or_insert(e.date_removed);
    }
    let mut s = String::new();
    for ((token, string), date) in uniq {
        let date_str = match date {
            Some(d) => format!("{:04}-{:02}-{:02}", d.year, d.month, d.day),
            None => String::new(),
        };
        s.push_str(&format!("{token:08x},{date_str},{}\n", csv_quote(&string)));
    }
    s
}

#[derive(Debug, Serialize)]
pub struct Summary {
    format: &'static str,
    input: String,
    input_sha256: String,
    entry_count: usize,
    unique_entries: usize,
    exact_duplicates: usize,
    colliding_tokens: usize,
    entries_with_removal_date: usize,
    csv: String,
    csv_sha256: String,
}

pub fn build_summary(
    db: &Database,
    input_name: &str,
    input_bytes: &[u8],
    csv: &str,
    csv_name: &str,
) -> Summary {
    use std::collections::{HashMap, HashSet};
    let entry_count = db.entries.len();
    let unique: HashSet<(u32, &str)> = db
        .entries
        .iter()
        .map(|e| (e.token, e.string.as_str()))
        .collect();
    let unique_entries = unique.len();
    // a "colliding" token maps to >= 2 distinct strings (none in the corpus).
    let mut by_token: HashMap<u32, HashSet<&str>> = HashMap::new();
    for e in &db.entries {
        by_token
            .entry(e.token)
            .or_default()
            .insert(e.string.as_str());
    }
    let colliding_tokens = by_token.values().filter(|set| set.len() >= 2).count();
    let entries_with_removal_date = db
        .entries
        .iter()
        .filter(|e| e.date_removed.is_some())
        .count();
    Summary {
        format: "Pigweed pw_tokenizer token database (TOKENS)",
        input: input_name.to_string(),
        input_sha256: crate::manifest::sha256_bytes(input_bytes),
        entry_count,
        unique_entries,
        exact_duplicates: entry_count - unique_entries,
        colliding_tokens,
        entries_with_removal_date,
        csv: csv_name.to_string(),
        csv_sha256: crate::manifest::sha256_bytes(csv.as_bytes()),
    }
}

pub fn run(input: &Path, out: &Path) -> Result<PathBuf> {
    let bytes = std::fs::read(input)?;
    let db = parse(&bytes)?;
    std::fs::create_dir_all(out)?;

    let input_name = input
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("pw_token_db")
        .to_string();
    let csv = write_csv(&db);
    let csv_name = format!("{input_name}.csv");
    let csv_path = out.join(&csv_name);
    std::fs::write(&csv_path, &csv)?;

    let summary = build_summary(&db, &input_name, &bytes, &csv, &csv_name);
    let summary_path = out.join("summary.json");
    std::fs::write(
        &summary_path,
        serde_json::to_string_pretty(&summary).map_err(|e| Error::Serialize(e.to_string()))?,
    )?;

    println!(
        "decoded {input_name}: {} entries ({} unique, {} duplicate, {} colliding tokens), {} with removal dates",
        summary.entry_count,
        summary.unique_entries,
        summary.exact_duplicates,
        summary.colliding_tokens,
        summary.entries_with_removal_date
    );
    println!("csv     -> {}", csv_path.display());
    println!("summary -> {}", summary_path.display());
    Ok(summary_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 3 entries: (1,"AB",present), (2,"C,D",removed 2021-02-03), and an exact
    /// duplicate of entry 0. The comma in "C,D" exercises CSV quoting (Task 2).
    fn fixture() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"TOKENS\0\0");
        b.extend_from_slice(&3u32.to_le_bytes()); // count
        b.extend_from_slice(&0u32.to_le_bytes()); // reserved
        // entries (token + 4 date bytes)
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // present
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&[3u8, 2u8]); // day=3, month=2
        b.extend_from_slice(&2021u16.to_le_bytes()); // year=2021
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // duplicate of entry 0
        // string table (NUL-terminated, in entry order)
        b.extend_from_slice(b"AB\0");
        b.extend_from_slice(b"C,D\0");
        b.extend_from_slice(b"AB\0");
        b
    }

    #[test]
    fn write_csv_is_canonical() {
        // fixture: 3 entries -> 2 unique rows, sorted by token; the duplicate
        // collapses; "C,D" is quoted; dates render empty / ISO.
        let csv = write_csv(&parse(&fixture()).unwrap());
        assert_eq!(csv, "00000001,,AB\n00000002,2021-02-03,\"C,D\"\n");
    }

    #[test]
    fn parse_reads_entries_and_dates() {
        let db = parse(&fixture()).unwrap();
        assert_eq!(db.reserved, 0);
        assert_eq!(db.entries.len(), 3);
        assert_eq!(
            db.entries[0],
            Entry {
                token: 1,
                date_removed: None,
                string: "AB".into()
            }
        );
        assert_eq!(
            db.entries[1],
            Entry {
                token: 2,
                date_removed: Some(Date {
                    year: 2021,
                    month: 2,
                    day: 3
                }),
                string: "C,D".into()
            }
        );
        assert_eq!(
            db.entries[2],
            Entry {
                token: 1,
                date_removed: None,
                string: "AB".into()
            }
        );
    }

    #[test]
    fn round_trip_is_byte_exact() {
        let bytes = fixture();
        assert_eq!(serialize(&parse(&bytes).unwrap()), bytes);
    }

    #[test]
    fn summary_counts_are_correct() {
        let bytes = fixture();
        let db = parse(&bytes).unwrap();
        let csv = write_csv(&db);
        let s = build_summary(&db, "pw_token_db", &bytes, &csv, "pw_token_db.csv");
        assert_eq!(s.entry_count, 3);
        assert_eq!(s.unique_entries, 2);
        assert_eq!(s.exact_duplicates, 1);
        assert_eq!(s.colliding_tokens, 0);
        assert_eq!(s.entries_with_removal_date, 1);
        assert_eq!(s.input_sha256.len(), 64);
        assert_eq!(s.csv_sha256, crate::manifest::sha256_bytes(csv.as_bytes()));
    }

    #[test]
    fn csv_quote_escapes_and_wraps() {
        // a `"` is doubled and the field is wrapped; a newline forces quoting
        assert_eq!(csv_quote("a\"b\nc"), "\"a\"\"b\nc\"");
        // a carriage return also forces quoting
        assert_eq!(csv_quote("x\ry"), "\"x\ry\"");
        // no special chars: returned unquoted
        assert_eq!(csv_quote("plain"), "plain");
    }

    #[test]
    fn parse_rejects_malformed() {
        // bad magic
        let mut bad_magic = fixture();
        bad_magic[0] = b'X';
        assert!(matches!(parse(&bad_magic), Err(Error::BadTokenDb(_))));
        // bind the Vec first so the slices below borrow `full`, not a dropped temporary
        let full = fixture();
        // truncated entry table (header claims 3 entries; only 20 bytes given)
        assert!(matches!(parse(&full[..20]), Err(Error::BadTokenDb(_))));
        // string-table underrun (drop the final NUL terminator)
        assert!(matches!(
            parse(&full[..full.len() - 1]),
            Err(Error::BadTokenDb(_))
        ));
        // trailing bytes after the string table
        let mut trailing = fixture();
        trailing.push(0x99);
        assert!(matches!(parse(&trailing), Err(Error::BadTokenDb(_))));
    }
}
