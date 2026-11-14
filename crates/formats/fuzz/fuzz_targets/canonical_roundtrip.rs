//! Whatever parse_canonical accepts must re-serialise to exactly the same bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((value, text)) = sampan_formats::parse_canonical(data, 4096) {
        assert_eq!(text.as_bytes(), data);
        assert_eq!(sampan_formats::canonicalize(&value).unwrap(), text);
    }
});
