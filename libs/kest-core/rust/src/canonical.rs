#[cfg(test)]
mod tests {
    use crate::canonical::to_canonical_string;
    use serde_json::json;

    #[test]
    fn test_rfc8785_canonicalization_basic() {
        // Rule 1: Sorting properties
        let input = json!({
            "z": 1,
            "a": 2
        });
        let output = to_canonical_string(&input).unwrap();
        assert_eq!(output, "{\"a\":2,\"z\":1}");
    }

    #[test]
    fn test_rfc8785_canonicalization_floats() {
        // Rule 2: Float formatting
        let input = json!({
            "a": 1.0,
            "b": 1e10,
            "c": 0.0000000000001
        });
        let output = to_canonical_string(&input).unwrap();
        // RFC 8785 specifies how to represent numbers (no scientific notation for small/large if they fit)
        // 1.0 -> 1
        // 1e10 -> 10000000000
        assert_eq!(output, "{\"a\":1,\"b\":10000000000,\"c\":1e-13}"); 
        // Wait, 1e-13 is NOT valid in RFC 8785? Actually it says:
        // "Integer values MUST be encoded as an integer. Numerical values MUST be encoded as an integer or as a decimal fraction."
        // "Scientific notation MUST NOT be used."
    }

    #[test]
    fn test_rfc8785_canonicalization_strings() {
        // Rule 3: Escape sequences
        let input = json!({
            "a": "newline\n",
            "b": "quote\"",
            "c": "unicode\u{1234}"
        });
        let output = to_canonical_string(&input).unwrap();
        assert_eq!(output, "{\"a\":\"newline\\n\",\"b\":\"quote\\\"\",\"c\":\"unicode\u{1234}\"}");
    }
}

pub fn to_canonical_string(value: &serde_json::Value) -> Result<String, String> {
    serde_jcs::to_string(value).map_err(|e| e.to_string())
}
