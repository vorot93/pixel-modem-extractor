//! String-reference function-name classifier: turn a function's uniquely-
//! referenced identifier string into a fail-closed `guess_` name candidate.
//! Pure; see the design spec. Never yields authoritative (`Recovered`) names.

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
}
