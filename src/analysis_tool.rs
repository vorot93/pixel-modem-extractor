use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisTool {
    Ghidra,
    Radare2,
    Rizin,
}

#[cfg(test)]
mod tests {
    use super::AnalysisTool;

    #[test]
    fn analysis_tool_serializes_exact_lowercase_ids() {
        for (tool, expected) in [
            (AnalysisTool::Ghidra, "\"ghidra\""),
            (AnalysisTool::Radare2, "\"radare2\""),
            (AnalysisTool::Rizin, "\"rizin\""),
        ] {
            assert_eq!(serde_json::to_string(&tool).unwrap(), expected);
        }
    }
}
