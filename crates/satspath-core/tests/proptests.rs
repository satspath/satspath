use proptest::prelude::*;
use satspath_core::canonicalize_identifier;

proptest! {
    #[test]
    fn test_canonicalize_identifier_does_not_panic(s in "\\PC*") {
        // Just verify that canonicalize_identifier doesn't crash on any string
        let _ = canonicalize_identifier(&s);
    }

    #[test]
    fn test_canonicalize_json_does_not_panic_on_arbitrary_strings(s in "\\PC*") {
        // If it parses as JSON, it shouldn't panic the canonicalizer
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&s) {
            let _ = canonical_json::to_string(&val);
        }
    }
}

// More property tests for event transitions, canonical JSON, etc., will go here.
