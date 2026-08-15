//! Select recovered scalar global shapes and emit a strict apply-map for
//! `ApplyGlobalTypes.java`. Fail-closed: only `inferred` scalars of width
//! 1/2/4/8 are applied; everything else is counted as ineligible and dropped.
//! Reads `global_shapes.json` through a minimal local view because the
//! `global_shapes::artifact` wire types are `Serialize`-only.
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::path::Path;

/// One global that will be typed as `undefined<width>` at `address`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeCandidate {
    pub address: String,
    pub width: u8,
}

/// Selection outcome: apply-worthy candidates plus the count of shapes that
/// carried no applicable scalar type (array/unknown/non-inferred/bad-width).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub candidates: Vec<TypeCandidate>,
    pub ineligible: usize,
}

// Minimal read view of global_shapes.json (see module note).
#[derive(Deserialize)]
struct ShapesFile {
    globals: Vec<ShapeGlobal>,
}

#[derive(Deserialize)]
struct ShapeGlobal {
    address: String,
    status: String,
    #[serde(default)]
    summary: Option<ShapeSummary>,
}

#[derive(Deserialize)]
struct ShapeSummary {
    provisional_shape: ShapeKind,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ShapeKind {
    ScalarCandidate {
        width: u8,
    },
    ArrayCandidate {
        #[allow(dead_code)]
        element_width: u8,
        #[allow(dead_code)]
        minimum_elements: u32,
    },
    Unknown,
}

const VALID_WIDTHS: [u8; 4] = [1, 2, 4, 8];

pub fn select_from_shapes_json(bytes: &[u8]) -> Result<Selection> {
    let file: ShapesFile =
        serde_json::from_slice(bytes).map_err(|e| Error::Serialize(e.to_string()))?;
    let mut candidates = Vec::new();
    let mut ineligible = 0usize;
    for g in file.globals {
        match (g.status.as_str(), g.summary.map(|s| s.provisional_shape)) {
            ("inferred", Some(ShapeKind::ScalarCandidate { width }))
                if VALID_WIDTHS.contains(&width) =>
            {
                candidates.push(TypeCandidate {
                    address: g.address,
                    width,
                });
            }
            _ => ineligible += 1,
        }
    }
    Ok(Selection {
        candidates,
        ineligible,
    })
}

// Strict write format, mirrored by ApplyGlobalTypes.java's FORMAT check.
#[derive(Serialize)]
struct TypeMapFile<'a> {
    format: &'a str,
    image: &'a str,
    types: Vec<TypeEntry<'a>>,
}

#[derive(Serialize)]
struct TypeEntry<'a> {
    address: &'a str,
    width: u8,
}

const FORMAT: &str = "pixel-modem-extractor-global-types-v1";

pub fn write_type_map(path: &Path, image: &str, sel: &Selection) -> Result<Option<NonZeroUsize>> {
    let Some(count) = NonZeroUsize::new(sel.candidates.len()) else {
        return Ok(None);
    };
    let file = TypeMapFile {
        format: FORMAT,
        image,
        types: sel
            .candidates
            .iter()
            .map(|c| TypeEntry {
                address: &c.address,
                width: c.width,
            })
            .collect(),
    };
    let bytes = serde_json::to_vec_pretty(&file).map_err(|e| Error::Serialize(e.to_string()))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(Some(count))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHAPES: &str = r#"{
      "globals": [
        {"address":"0x40010000","status":"inferred",
         "summary":{"provisional_shape":{"kind":"scalar_candidate","width":4}}},
        {"address":"0x40010010","status":"inferred",
         "summary":{"provisional_shape":{"kind":"scalar_candidate","width":1}}},
        {"address":"0x40010020","status":"inferred",
         "summary":{"provisional_shape":{"kind":"array_candidate","element_width":1,"minimum_elements":4}}},
        {"address":"0x40010030","status":"inferred",
         "summary":{"provisional_shape":{"kind":"unknown"}}},
        {"address":"0x40010040","status":"inferred",
         "summary":{"provisional_shape":{"kind":"scalar_candidate","width":3}}},
        {"address":"0x40010050","status":"no_evidence","summary":null},
        {"address":"0x40010060","status":"conflicting","summary":null}
      ]
    }"#;

    #[test]
    fn selects_only_inferred_scalars_of_valid_width() {
        let sel = select_from_shapes_json(SHAPES.as_bytes()).unwrap();
        let got: Vec<(&str, u8)> = sel
            .candidates
            .iter()
            .map(|c| (c.address.as_str(), c.width))
            .collect();
        assert_eq!(got, vec![("0x40010000", 4), ("0x40010010", 1)]);
        // array + unknown + width-3 + no_evidence + conflicting = 5 ineligible
        assert_eq!(sel.ineligible, 5);
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(select_from_shapes_json(b"{ not json").is_err());
    }

    #[test]
    fn write_type_map_skips_empty_selection() {
        let dir = tempdir_unique("gt_empty");
        let path = dir.join("global_types.json");
        let empty = Selection {
            candidates: vec![],
            ineligible: 3,
        };
        assert!(write_type_map(&path, "02_MAIN", &empty).unwrap().is_none());
        assert!(!path.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_type_map_emits_strict_format() {
        let dir = tempdir_unique("gt_write");
        let path = dir.join("global_types.json");
        let sel = select_from_shapes_json(SHAPES.as_bytes()).unwrap();
        let count = write_type_map(&path, "02_MAIN", &sel).unwrap().unwrap();
        assert_eq!(count.get(), 2);
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(v["format"], "pixel-modem-extractor-global-types-v1");
        assert_eq!(v["image"], "02_MAIN");
        assert_eq!(v["types"][0]["address"], "0x40010000");
        assert_eq!(v["types"][0]["width"], 4);
        std::fs::remove_dir_all(&dir).ok();
    }

    fn tempdir_unique(tag: &str) -> std::path::PathBuf {
        // Deterministic per-test dir under the cargo target tmp area.
        let dir = std::env::temp_dir().join(format!("pme_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
