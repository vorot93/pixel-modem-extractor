use pixel_modem_extractor::manifest::sha256_bytes as sha;
use std::path::PathBuf;

// Golden inputs live outside the repo. Point the test at them with env vars:
//   PME_RADIO_IMG  — the radio FBPK `.img`
//   PME_GOLDEN_DIR — the extracted golden tree (the `modem_extracted` root)
// Either unset (or the inputs absent) → the test skips.
const FW: &str = "PIXELMODEM_rootfs/images/g5400i-260317-260429-B-15308590";

#[test]
fn extract_matches_golden() {
    let (Some(img), Some(root)) = (
        std::env::var_os("PME_RADIO_IMG").map(PathBuf::from),
        std::env::var_os("PME_GOLDEN_DIR").map(PathBuf::from),
    ) else {
        eprintln!("skip: set PME_RADIO_IMG and PME_GOLDEN_DIR");
        return;
    };
    let gold_split = root.join(FW).join("modem.bin.split");
    let gold_ext4 = root.join("g5400i-260317-260429-B-15308590.ext4");
    if !img.exists() || !gold_split.exists() {
        eprintln!("skip: golden inputs absent");
        return;
    }
    let out = std::env::temp_dir().join("pme_golden");
    let _ = std::fs::remove_dir_all(&out);
    pixel_modem_extractor::pipeline::extract(&img, &out, true).unwrap();

    // 5 images byte-match exactly
    for n in ["00_BOOT", "01_PSP", "02_MAIN", "03_APM", "04_VSS"] {
        let ours = std::fs::read(out.join("modem.bin.split").join(n)).unwrap();
        let gold = std::fs::read(gold_split.join(n)).unwrap();
        assert_eq!(
            sha(&ours),
            sha(&gold),
            "{n} differs (len ours={} gold={})",
            ours.len(),
            gold.len()
        );
    }
    // DBGCORE: ours (5520, TOC-authoritative) == first 5520 bytes of the over-sliced golden
    let ours = std::fs::read(out.join("modem.bin.split").join("05_DBGCORE")).unwrap();
    let gold = std::fs::read(gold_split.join("05_DBGCORE")).unwrap();
    assert_eq!(ours.len(), 5520);
    assert_eq!(
        sha(&ours),
        sha(&gold[..5520]),
        "05_DBGCORE first-5520 differs"
    );

    // ext4 byte-matches the golden ext4
    if gold_ext4.exists() {
        assert_eq!(
            sha(&std::fs::read(out.join("modem.ext4")).unwrap()),
            sha(&std::fs::read(&gold_ext4).unwrap()),
            "modem.ext4 differs"
        );
    }
}
