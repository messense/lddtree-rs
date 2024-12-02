use lddtree::DependencyAnalyzer;

#[test]
fn test_elf() {
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

#[test]
fn test_macho() {
    let analyzer = DependencyAnalyzer::default();
    let deps = analyzer.analyze("tests/test.macho").unwrap();
    assert!(deps.interpreter.is_none());
    assert_eq!(
        deps.needed,
        &[
            "/usr/lib/libz.1.dylib",
            "/usr/lib/libiconv.2.dylib",
            "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
            "/usr/lib/libSystem.B.dylib"
        ]
    );
    assert_eq!(deps.libraries.len(), 4);
}

#[test]
fn test_pe() {
    let analyzer = DependencyAnalyzer::default();
    let deps = analyzer.analyze("tests/test.pe").unwrap();
    assert!(deps.interpreter.is_none());
    assert_eq!(
        deps.needed,
        &[
            "KERNEL32.dll",
            "VCRUNTIME140.dll",
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "api-ms-win-crt-stdio-l1-1-0.dll"
        ]
    );
    assert_eq!(deps.libraries.len(), 4);
}
