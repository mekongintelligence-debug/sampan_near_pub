//! Property tests (fuzz-style): parsers never panic on arbitrary input, canonical text
//! round-trips, and any non-canonical re-serialisation is rejected.
use proptest::prelude::*;
use sampan_formats::{
    canonicalize, parse_canonical, parse_mandate, parse_order, parse_receipt_core,
    verify_signed_mandate, ErrorCode,
};
use serde_json::Value;

fn value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        "[a-z0-9._-]{0,12}".prop_map(Value::String),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(4, 32, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map("[a-z_]{1,8}", inner, 0..4)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #![proptest_config({
        let cases: u32 = std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(2000);
        // Scalars print the same pretty or compact, so pretty_printing_is_rejected skips
        // many cases; allow as many skips as cases so long fuzz runs do not abort.
        ProptestConfig { cases, max_global_rejects: cases, ..ProptestConfig::default() }
    })]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_mandate(&bytes);
        let _ = verify_signed_mandate(&bytes);
        let _ = parse_order(&bytes);
        let _ = parse_receipt_core(&bytes);
    }

    #[test]
    fn json_shaped_text_never_panics(s in "[\\[\\]{}\":,a-z0-9 \\\\u-]{0,200}") {
        let _ = parse_mandate(s.as_bytes());
        let _ = verify_signed_mandate(s.as_bytes());
    }

    #[test]
    fn canonical_round_trip(v in value()) {
        let text = canonicalize(&v).unwrap();
        let (_, back) = parse_canonical(text.as_bytes(), 1 << 20).unwrap();
        prop_assert_eq!(back, text);
    }

    #[test]
    fn pretty_printing_is_rejected(v in value()) {
        let canonical = canonicalize(&v).unwrap();
        let pretty = serde_json::to_string_pretty(&v).unwrap();
        prop_assume!(pretty != canonical);
        prop_assert_eq!(parse_canonical(pretty.as_bytes(), 1 << 20).err(), Some(ErrorCode::NotCanonical));
    }

    #[test]
    fn numbers_always_rejected(n in any::<i64>()) {
        let doc = format!("{{\"a\":{n}}}");
        prop_assert_eq!(parse_canonical(doc.as_bytes(), 4096).err(), Some(ErrorCode::Schema));
    }
}
