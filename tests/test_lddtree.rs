use lddtree::DependencyAnalyzer;

#[test]
fn test_lddtree() {
    let analyzer = DependencyAnalyzer::default();
    let deps = analyzer.analyze("tests/test.elf").unwrap();
    assert_eq!(
        deps.interpreter.as_deref(),
        Some("/lib/ld-linux-aarch64.so.1")
    );
    assert_eq!(
        deps.needed,
        &[
            "libz.so.1",
            "libpthread.so.0",
            "libm.so.6",
            "libdl.so.2",
            "libc.so.6",
        ]
    );
    assert_eq!(deps.libraries.len(), 6);
}
