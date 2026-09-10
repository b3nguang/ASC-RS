use std::{env, path::Path};

use asc_rs::{
    apk::load_dexes,
    dex::{Dex, Query, ReferenceKind},
    minidex::extract_minimal_dex,
};
use dex_decompiler::parse_dex;
use sha1::{Digest, Sha1};

/// Run with ASC_TEST_APK set to an APK fixture. Keeping the path outside the
/// repository avoids redistributing third-party applications.
#[test]
fn external_demo_apk_class_and_string_reference() {
    let Some(path) = env::var_os("ASC_TEST_APK") else {
        eprintln!("ASC_TEST_APK is not set; external APK test skipped");
        return;
    };
    let entries = load_dexes(Path::new(&path), 4).expect("load test APK");
    let mut found_class = false;
    let mut found_reference = false;
    let mut class_entry = None;
    for entry in entries {
        let dex = Dex::parse(&entry.data).expect("parse test DEX");
        if dex.defines_class("Lcom/zj/wuaipojie/ui/MainActivity;") {
            found_class = true;
            class_entry = Some(entry.data.clone());
        }
        let query = Query::String("请先注册id".to_owned());
        let targets = dex.matching_indices(&query);
        let refs = dex
            .scan_references(ReferenceKind::String, &targets)
            .expect("scan string references");
        found_reference |= !refs.is_empty();
    }
    assert!(found_class, "demo MainActivity was not found");
    assert!(
        found_reference,
        "demo registration string had no references"
    );

    let original = class_entry.expect("DEX containing MainActivity");
    let minimal = extract_minimal_dex(&original, "Lcom/zj/wuaipojie/ui/MainActivity;")
        .expect("extract minimal DEX");
    assert!(minimal.bytes.len() < original.len() / 1000);
    assert_eq!(&minimal.bytes[..8], b"dex\n035\0");
    assert_eq!(
        u32::from_le_bytes(minimal.bytes[32..36].try_into().unwrap()) as usize,
        minimal.bytes.len()
    );
    assert_eq!(
        &minimal.bytes[12..32],
        Sha1::digest(&minimal.bytes[32..]).as_slice()
    );
    assert_eq!(
        u32::from_le_bytes(minimal.bytes[8..12].try_into().unwrap()),
        adler2::adler32_slice(&minimal.bytes[12..])
    );

    let parsed = parse_dex(&minimal.bytes).expect("parse rebuilt DEX");
    let class = parsed
        .class_defs()
        .next()
        .expect("one class definition")
        .expect("valid class definition");
    let data = parsed
        .get_class_data(&class)
        .expect("read rebuilt class data")
        .expect("class data exists");
    assert_eq!(data.direct_methods.len() + data.virtual_methods.len(), 7);
}
