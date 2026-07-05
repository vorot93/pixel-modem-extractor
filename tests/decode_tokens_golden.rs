use std::{collections::HashSet, path::PathBuf};

// Set PME_GOLDEN_DIR to the extracted golden tree (the `modem_extracted` root).
const FW: &str = "PIXELMODEM_rootfs/images/g5400i-260317-260429-B-15308590";

#[test]
fn decode_tokens_matches_golden() {
    let Some(root) = std::env::var_os("PME_GOLDEN_DIR").map(PathBuf::from) else {
        eprintln!("skip: set PME_GOLDEN_DIR");
        return;
    };
    let db_path = root.join(FW).join("pw_token_db");
    if !db_path.exists() {
        eprintln!("skip: golden pw_token_db absent");
        return;
    }
    let bytes = std::fs::read(&db_path).unwrap();
    let db = pixel_modem_extractor::tokens::parse(&bytes).unwrap();

    // known facts (spec §1.1)
    assert_eq!(db.entries.len(), 164, "entry_count");
    let unique: HashSet<(u32, &str)> = db
        .entries
        .iter()
        .map(|e| (e.token, e.string.as_str()))
        .collect();
    assert_eq!(unique.len(), 151, "unique (token,string) pairs");
    assert!(
        db.entries.iter().all(|e| e.date_removed.is_none()),
        "all present"
    );

    // authoritative oracle: binary round-trip is byte-exact
    assert_eq!(
        pixel_modem_extractor::tokens::serialize(&db),
        bytes,
        "round-trip differs"
    );

    // run() emits a canonical CSV: 151 sorted rows incl. the spot-checked pair
    let out = std::env::temp_dir().join("pme_decode_tokens");
    let _ = std::fs::remove_dir_all(&out);
    pixel_modem_extractor::tokens::run(&db_path, &out).unwrap();
    let csv = std::fs::read_to_string(out.join("pw_token_db.csv")).unwrap();
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 151, "csv row count");
    assert!(
        lines.contains(&"00000cc9,,Latency"),
        "spot-checked pair present"
    );
    let mut prev = 0u32;
    for line in &lines {
        let tok = u32::from_str_radix(line.split(',').next().unwrap(), 16).unwrap();
        assert!(tok >= prev, "csv not sorted by token");
        prev = tok;
    }
}
