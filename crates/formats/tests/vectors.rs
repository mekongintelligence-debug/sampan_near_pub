//! Runs every shared vector in fixtures/vectors/ against the Rust implementation, using
//! NEAR's host functions (sha256, keccak256, ed25519_verify, ecrecover) in the mocked VM.
use base64::Engine;
use sampan_formats::{
    parse_mandate, parse_order, parse_receipt_core, verify_signed_mandate, ErrorCode,
};
use std::path::PathBuf;

fn run(kind: &str, input: &[u8]) -> Result<String, ErrorCode> {
    match kind {
        "mandate" => parse_mandate(input).map(|(_, h)| h),
        "signed_mandate" => verify_signed_mandate(input).map(|v| v.mandate_hash),
        "order" => parse_order(input).map(|(_, h)| h),
        "receipt_core" => parse_receipt_core(input).map(|(_, h)| h),
        other => panic!("unknown vector kind {other}"),
    }
}

#[test]
fn all_shared_vectors() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/vectors");
    let mut count = 0;
    let mut failures = Vec::new();
    for kind in std::fs::read_dir(&dir).unwrap() {
        let kind = kind.unwrap();
        if !kind.file_type().unwrap().is_dir() {
            continue;
        }
        for f in std::fs::read_dir(kind.path()).unwrap() {
            let path = f.unwrap().path();
            let v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let input = base64::engine::general_purpose::STANDARD
                .decode(v["input_b64"].as_str().unwrap())
                .unwrap();
            let got = run(v["kind"].as_str().unwrap(), &input);
            let want = &v["expect"];
            let ok = match (&got, want["ok"].as_bool().unwrap()) {
                (Ok(h), true) => h == want["hash"].as_str().unwrap(),
                (Err(e), false) => e.as_str() == want["error"].as_str().unwrap(),
                _ => false,
            };
            if !ok {
                failures.push(format!("{}: got {:?}, want {}", path.display(), got, want));
            }
            count += 1;
        }
    }
    // Floor = the current vector count, so deleting vectors fails (audit M2-04).
    assert!(count >= 137, "only {count} vectors");
    // Every file is in MANIFEST.sha256 with its exact hash, and nothing else is listed.
    let manifest = std::fs::read_to_string(dir.join("MANIFEST.sha256")).unwrap();
    let mut listed = 0;
    for line in manifest.lines() {
        let (hash, rel) = line.split_once(' ').unwrap();
        let bytes =
            std::fs::read(dir.join(rel)).unwrap_or_else(|_| panic!("listed file missing: {rel}"));
        let got: String = near_sdk::env::sha256_array(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(got, hash, "manifest hash mismatch for {rel}");
        listed += 1;
    }
    assert_eq!(
        listed, count,
        "manifest lists {listed} files, {count} vector files exist"
    );
    assert!(
        failures.is_empty(),
        "{} of {count} vectors failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
