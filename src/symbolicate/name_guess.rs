//! String-reference function-name classifier: turn a function's uniquely-
//! referenced identifier string into a fail-closed `guess_` name candidate.
//! Pure; see the design spec. Never yields authoritative (`Recovered`) names.

use std::collections::{HashMap, HashSet};

/// What a surviving candidate identifier most likely names. Descriptive
/// provenance only — both variants are named; it does not gate acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// A function-shaped identifier (verb / CamelCase / Module_Action).
    FnName,
    /// The ASN.1 / 3GPP-IE type the function handles (imprecise but useful).
    TypeLabel,
}

impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Class::FnName => "fn_name",
            Class::TypeLabel => "type_label",
        }
    }
}

/// `true` if `id` carries no ASCII lowercase — an all-caps message/enum
/// constant (`NS_USIM_UPDATE_REQ`), rejected as a function name.
pub fn is_all_caps(id: &str) -> bool {
    !id.chars().any(|c| c.is_ascii_lowercase())
}

/// Classify an accepted identifier for provenance: ASN.1/3GPP-IE type names
/// (an `Asn_` prefix or a `_r<digits>` release tag) vs function-shaped names.
pub fn classify(id: &str) -> Class {
    if id.starts_with("Asn_") || has_release_tag(id) {
        Class::TypeLabel
    } else {
        Class::FnName
    }
}

/// A `_r<digits>` segment (a 3GPP release tag such as `_r15`).
fn has_release_tag(id: &str) -> bool {
    let b = id.as_bytes();
    (0..b.len().saturating_sub(2))
        .any(|i| b[i] == b'_' && b[i + 1] == b'r' && b[i + 2].is_ascii_digit())
}

/// A bare C identifier (3–64 chars), i.e. a plausible `__func__` / symbol name.
pub fn is_ident(s: &str) -> bool {
    let n = s.len();
    (3..=64).contains(&n)
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The single *distinct* `is_ident` string among `data_refs` (dedup by content
/// first, so a legitimately-repeated `__func__` ref is not treated as
/// ambiguous). `None` for zero or more than one distinct identifier — fail-closed.
pub fn unique_ident(data_refs: &[u64], strings: &HashMap<u64, String>) -> Option<String> {
    let mut seen: HashSet<&str> = HashSet::new();
    let idents: Vec<&String> = data_refs
        .iter()
        .filter_map(|r| strings.get(r))
        .filter(|s| is_ident(s))
        .filter(|s| seen.insert(s.as_str()))
        .collect();
    match idents.as_slice() {
        [only] => Some((*only).clone()),
        _ => None,
    }
}

/// Turn a function's candidate identifier into a fail-closed `guess_` name
/// candidate, or reject. `ident_count[id]` is the image-wide count of functions
/// whose `unique_ident` is `id`; `globals` are recovered global names; `fn_names`
/// are known function names elsewhere in the image. Rejects: not referenced by
/// exactly one function, an all-caps message constant, a global name, or another
/// function's name. Survivors carry a descriptive `Class`.
pub fn string_ref_guess(
    cand: Option<&str>,
    ident_count: &HashMap<String, usize>,
    globals: &HashSet<String>,
    fn_names: &HashSet<String>,
) -> Option<(String, Class)> {
    let id = cand?;
    if ident_count.get(id).copied().unwrap_or(0) != 1 {
        return None;
    }
    if is_all_caps(id) || globals.contains(id) || fn_names.contains(id) {
        return None;
    }
    Some((id.to_string(), classify(id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_type_labels_and_fn_names() {
        assert_eq!(classify("Asn_MeasurementCommand_r4"), Class::TypeLabel);
        assert_eq!(
            classify("LteRrc_MeasResultList3EUTRA_r15"),
            Class::TypeLabel
        );
        assert_eq!(classify("RF_SM_Set_ET_Voltage"), Class::FnName);
        assert_eq!(classify("OS_Delete_Semaphore"), Class::FnName);
    }

    #[test]
    fn all_caps_detects_message_constants() {
        assert!(is_all_caps("NS_USIM_UPDATE_REQ"));
        assert!(is_all_caps("AP2CP_PARTIAL_RESET"));
        assert!(!is_all_caps("RF_SM_Set_ET_Voltage"));
        assert!(!is_all_caps("AnrHandler"));
    }

    #[test]
    fn class_str_is_stable() {
        assert_eq!(Class::FnName.as_str(), "fn_name");
        assert_eq!(Class::TypeLabel.as_str(), "type_label");
    }

    #[test]
    fn unique_ident_returns_single_distinct_identifier() {
        let mut s = HashMap::new();
        s.insert(0x200u64, "LteRrc_Reestab".to_string());
        assert_eq!(
            unique_ident(&[0x200], &s),
            Some("LteRrc_Reestab".to_string())
        );
    }

    #[test]
    fn unique_ident_dedups_repeated_identifier() {
        // same __func__ referenced twice (two asserts) is not ambiguous
        let mut s = HashMap::new();
        s.insert(0x200u64, "Foo_Bar".to_string());
        s.insert(0x208u64, "Foo_Bar".to_string());
        assert_eq!(
            unique_ident(&[0x200, 0x208], &s),
            Some("Foo_Bar".to_string())
        );
    }

    #[test]
    fn unique_ident_is_none_when_ambiguous_or_absent() {
        let mut s = HashMap::new();
        s.insert(0x200u64, "Foo_Bar".to_string());
        s.insert(0x300u64, "Other_Ident".to_string());
        assert_eq!(unique_ident(&[0x200, 0x300], &s), None); // two distinct
        assert_eq!(unique_ident(&[], &s), None); // none
    }

    #[test]
    fn is_ident_rejects_paths_and_short_strings() {
        assert!(is_ident("LteRrc_Reestab"));
        assert!(!is_ident("ab")); // too short
        assert!(!is_ident("has space"));
        assert!(!is_ident("dir/file.c")); // path
    }

    fn ctx() -> (HashMap<String, usize>, HashSet<String>, HashSet<String>) {
        let mut count = HashMap::new();
        for id in [
            "RF_SM_Set_ET_Voltage",
            "Asn_Foo_r4",
            "TmuGlobal",
            "AliasedName",
            "NS_REQ",
        ] {
            count.insert(id.to_string(), 1);
        }
        count.insert("Shared_Api".to_string(), 2); // referenced by two functions
        let globals: HashSet<String> = ["TmuGlobal".to_string()].into_iter().collect();
        let fn_names: HashSet<String> = ["AliasedName".to_string()].into_iter().collect();
        (count, globals, fn_names)
    }

    #[test]
    fn accepts_fn_name_and_type_label() {
        let (count, g, f) = ctx();
        assert_eq!(
            string_ref_guess(Some("RF_SM_Set_ET_Voltage"), &count, &g, &f),
            Some(("RF_SM_Set_ET_Voltage".to_string(), Class::FnName))
        );
        assert_eq!(
            string_ref_guess(Some("Asn_Foo_r4"), &count, &g, &f),
            Some(("Asn_Foo_r4".to_string(), Class::TypeLabel))
        );
    }

    #[test]
    fn rejects_wrong_classes() {
        let (count, g, f) = ctx();
        assert_eq!(string_ref_guess(None, &count, &g, &f), None); // no candidate
        assert_eq!(string_ref_guess(Some("NS_REQ"), &count, &g, &f), None); // all-caps const
        assert_eq!(string_ref_guess(Some("TmuGlobal"), &count, &g, &f), None); // recovered global — rejected only via globals.contains
        assert_eq!(string_ref_guess(Some("AliasedName"), &count, &g, &f), None); // another fn's name
        assert_eq!(string_ref_guess(Some("Shared_Api"), &count, &g, &f), None); // not 1:1 image-wide
        assert_eq!(
            string_ref_guess(Some("Never_Referenced"), &count, &g, &f),
            None
        ); // never referenced -> count 0 -> != 1
    }
}
