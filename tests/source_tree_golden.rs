use pixel_modem_extractor::manifest::sha256_bytes as sha;
use std::path::{Path, PathBuf};

// Set PME_GOLDEN_DIR to the extracted golden tree (the `modem_extracted` root).
// Unset (or inputs absent) → the test skips.
const FW: &str = "PIXELMODEM_rootfs/images/g5400i-260317-260429-B-15308590";

fn walk(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}

#[test]
fn source_tree_matches_golden() {
    let Some(root) = std::env::var_os("PME_GOLDEN_DIR").map(PathBuf::from) else {
        eprintln!("skip: set PME_GOLDEN_DIR to the extracted golden tree");
        return;
    };
    let gold_02main = root.join(FW).join("modem.bin.split").join("02_MAIN");
    let gold_st = root.join(FW).join("02_MAIN.source_tree");
    if !gold_02main.exists() || !gold_st.exists() {
        eprintln!("skip: golden inputs absent");
        return;
    }
    let out = std::env::temp_dir().join(format!("pme_st_golden_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let opts = pixel_modem_extractor::source_tree::Opts::default();
    pixel_modem_extractor::source_tree::run(&gold_02main, &out, &opts).unwrap();

    // 1. every golden tree/ leaf byte-matches ours
    let gold_tree = gold_st.join("tree");
    let mut checked = 0usize;
    for gp in walk(&gold_tree) {
        let rel = gp.strip_prefix(&gold_tree).unwrap();
        let op = out.join("tree").join(rel);
        assert!(op.exists(), "missing our leaf {}", rel.display());
        assert_eq!(
            sha(&std::fs::read(&op).unwrap()),
            sha(&std::fs::read(&gp).unwrap()),
            "leaf differs: {}",
            rel.display()
        );
        checked += 1;
    }
    assert!(checked >= 6000, "only checked {checked} leaves");
    // same leaf count both ways
    assert_eq!(walk(&out.join("tree")).len(), walk(&gold_tree).len());

    // 2. text reports byte-match (README intentionally excluded)
    for f in ["tree.txt", "summary.md", "other_paths.txt"] {
        assert_eq!(
            sha(&std::fs::read(out.join(f)).unwrap()),
            sha(&std::fs::read(gold_st.join(f)).unwrap()),
            "{f} differs"
        );
    }

    // 3. manifest structural match
    let ours: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
    let gold: serde_json::Value =
        serde_json::from_slice(&std::fs::read(gold_st.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(ours["counts"]["tree_files"], gold["counts"]["tree_files"]);
    let key = "third_party/chre/chpp/transport.c";
    assert!(
        ours["files"][key]["attributed_strings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "Async send failure: %d")
    );
}
