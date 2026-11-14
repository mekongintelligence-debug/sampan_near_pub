//! Any bytes: no parser may panic; every result is Ok or a defined ErrorCode.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sampan_formats::parse_mandate(data);
    let _ = sampan_formats::verify_signed_mandate(data);
    let _ = sampan_formats::parse_order(data);
    let _ = sampan_formats::parse_receipt_core(data);
});
