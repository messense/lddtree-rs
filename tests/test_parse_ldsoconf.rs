use lddtree::ld_so_conf::parse_ld_so_conf;

#[test]
fn test_parse_ldsoconf() {
    let paths = parse_ld_so_conf("tests/ld.so.conf", "/").unwrap();
    assert_eq!(
        paths,
        vec![
            "/usr/lib/x86_64-linux-gnu/libfakeroot",
            "/usr/local/lib",
            "/usr/local/lib/x86_64-linux-gnu",
            "/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            "/lib32",
            "/usr/lib32",
        ]
    );
}
