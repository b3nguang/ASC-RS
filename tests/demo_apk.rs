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
        let dex = Dex::parse_shared(entry.data.clone()).expect("parse test DEX");
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
    assert_eq!(asc.apk().cached_parsed_dex_count(), 0);
    let service_query = Query::String("请先注册id".to_owned());
    let search = asc
        .find_references(&service_query)
        .expect("search through service API");
    assert_eq!(asc.apk().cached_parsed_dex_count(), 1);
    assert!(
        search.references.iter().any(|reference| {
            reference.caller_method.contains("alertFirst()V")
                && reference.target_symbol == "请先注册id"
                && reference.code_unit_offset > 0
        }),
        "structured service result should retain signature, target, and offset"
    );
    let warm_search = asc
        .find_references(&service_query)
        .expect("reuse parsed DEX and reference index");
    assert_eq!(warm_search.references.len(), search.references.len());
    assert_eq!(asc.apk().cached_parsed_dex_count(), 1);

    let patterns = vec![
        "请先注册id".to_owned(),
        "alert".to_owned(),
        "not-a-real-demo-string".to_owned(),
        "请先注册id".to_owned(),
    ];
    let batch = asc
        .find_string_references_batch(&patterns)
        .expect("batch search through service API");
    assert_eq!(batch.groups.len(), patterns.len());
    let mut individual_total_ms = 0.0;
    for group in &batch.groups {
        let individual = asc
            .find_references(&Query::String(group.pattern.clone()))
            .expect("compare individual string search");
        assert_eq!(group.references, individual.references);
        individual_total_ms += individual.timings.total_ms;
    }
    eprintln!(
        "four string queries batch={:.3} ms individual-total={individual_total_ms:.3} ms",
        batch.timings.total_ms
    );
    let many_patterns = (0..64)
        .map(|index| format!("not-a-real-demo-string-{index}"))
        .collect::<Vec<_>>();
    let small_miss_batch = asc
        .find_string_references_batch(&many_patterns[..4])
        .expect("small no-match batch search");
    let small_miss_individual_ms = many_patterns[..4]
        .iter()
        .map(|pattern| {
            asc.find_references(&Query::String(pattern.clone()))
                .expect("compare small no-match batch")
                .timings
                .total_ms
        })
        .sum::<f64>();
    eprintln!(
        "four no-match queries batch={:.3} ms individual-total={small_miss_individual_ms:.3} ms",
        small_miss_batch.timings.total_ms
    );
    let many_batch = asc
        .find_string_references_batch(&many_patterns)
        .expect("large batch search through service API");
    assert!(
        many_batch
            .groups
            .iter()
            .all(|group| group.references.is_empty())
    );
    let many_individual_ms = many_patterns
        .iter()
        .map(|pattern| {
            asc.find_references(&Query::String(pattern.clone()))
                .expect("compare large batch to individual searches")
                .timings
                .total_ms
        })
        .sum::<f64>();
    eprintln!(
        "64 string queries batch={:.3} ms individual-total={many_individual_ms:.3} ms",
        many_batch.timings.total_ms
    );
    eprintln!(
        "reference search cold={:.3} ms warm={:.3} ms",
        search.timings.total_ms, warm_search.timings.total_ms
    );
    let decompiled = asc
        .decompile_class(
            "com.zj.wuaipojie.ui.MainActivity",
            DecompilationMode::Simple,
        )
        .expect("decompile through service API");
    assert!(decompiled.source.contains("请先注册id"));
}
