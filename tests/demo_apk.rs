use std::{env, path::Path, sync::Arc};

use asc_rs::{
    apk::ApkSession,
    dex::{Dex, Query, ReferenceKind, class_descriptors},
    minidex::{extract_minimal_dex, validate_minimal_dex},
    service::AscSession,
};
use dex_decompiler::{DecompilationMode, Decompiler, DecompilerOptions, parse_dex};
use sha1::{Digest, Sha1};

/// Run with ASC_TEST_APK set to an APK fixture. Keeping the path outside the
/// repository avoids redistributing third-party applications.
#[test]
fn external_demo_apk_class_and_string_reference() {
    let Some(path) = env::var_os("ASC_TEST_APK") else {
        eprintln!("ASC_TEST_APK is not set; external APK test skipped");
        return;
    };
    let apk = ApkSession::open(Path::new(&path), 4).expect("open test APK");
    assert_eq!(apk.cached_dex_count(), 0);
    let indexed = apk
        .find_class("Lcom/zj/wuaipojie/ui/MainActivity;")
        .expect("index class tables")
        .expect("find MainActivity");
    assert_eq!(apk.cached_dex_count(), 1);
    let indexed_again = apk
        .find_class("Lcom/zj/wuaipojie/ui/MainActivity;")
        .expect("reuse class index")
        .expect("find MainActivity again");
    assert!(Arc::ptr_eq(&indexed.data, &indexed_again.data));

    let entries = apk.load_all_dexes().expect("load test DEX entries");
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
        let sites = dex
            .scan_reference_sites(ReferenceKind::String, &targets)
            .expect("scan string reference sites");
        if !sites.is_empty() {
            assert!(sites.iter().all(|site| site.code_unit_offset > 0));
            assert!(
                dex.format_method(sites[0].caller_index)
                    .contains("alertFirst()V")
            );
        }
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
    validate_minimal_dex(&minimal.bytes).expect("validate canonical rebuilt DEX");
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

    let descriptors = class_descriptors(&original).expect("list class descriptors");
    let sample_step = (descriptors.len() / 100).max(1);
    for descriptor in descriptors.iter().step_by(sample_step).take(100) {
        let rebuilt = extract_minimal_dex(&original, descriptor)
            .unwrap_or_else(|error| panic!("extract {descriptor}: {error:#}"));
        validate_minimal_dex(&rebuilt.bytes)
            .unwrap_or_else(|error| panic!("validate {descriptor}: {error:#}"));
        let parsed =
            parse_dex(&rebuilt.bytes).unwrap_or_else(|error| panic!("parse {descriptor}: {error}"));
        let class = parsed
            .class_defs()
            .next()
            .expect("one rebuilt class")
            .unwrap_or_else(|error| panic!("read {descriptor}: {error}"));
        let options = DecompilerOptions {
            mode: DecompilationMode::Simple,
            resource_map: Some(Default::default()),
            ..Default::default()
        };
        Decompiler::with_options(&parsed, options)
            .decompile_class(&class)
            .unwrap_or_else(|error| panic!("decompile {descriptor}: {error}"));
    }

    let asc = AscSession::open(Path::new(&path), 4).expect("open service session");
    let search = asc
        .find_references(&Query::String("请先注册id".to_owned()))
        .expect("search through service API");
    assert!(
        search.references.iter().any(|reference| {
            reference.caller_method.contains("alertFirst()V")
                && reference.target_symbol == "请先注册id"
                && reference.code_unit_offset > 0
        }),
        "structured service result should retain signature, target, and offset"
    );
    let decompiled = asc
        .decompile_class(
            "com.zj.wuaipojie.ui.MainActivity",
            DecompilationMode::Simple,
        )
        .expect("decompile through service API");
    assert!(decompiled.source.contains("请先注册id"));
}
