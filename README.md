# lddtree-rs

[![CI](https://github.com/messense/lddtree-rs/workflows/CI/badge.svg)](https://github.com/messense/lddtree-rs/actions?query=workflow%3ACI)
[![Crates.io](https://img.shields.io/crates/v/lddtree.svg)](https://crates.io/crates/lddtree)
[![docs.rs](https://docs.rs/lddtree/badge.svg)](https://docs.rs/lddtree/)

Read the dynamic library dependency tree. Supports **ELF** (Linux), **Mach-O** (macOS), and **PE** (Windows) binaries.

This does not work like `ldd` in that we do not execute/load code (only read files on disk).
The binary format is detected automatically from the file header.

This is roughly a Rust port of [lddtree.py](https://github.com/pypa/auditwheel/blob/main/src/auditwheel/lddtree.py)
from [auditwheel](https://github.com/pypa/auditwheel), extended with Mach-O and PE support.
It's used in [maturin](https://github.com/PyO3/maturin) for automatic wheel repair on Linux, macOS, and Windows.

## Features

- **ELF**: rpath/runpath resolution, `LD_LIBRARY_PATH`, `ld.so.conf` parsing, sysroot support
- **Mach-O**: `@rpath`, `@loader_path`, `@executable_path` resolution, `DYLD_LIBRARY_PATH`/`DYLD_FALLBACK_LIBRARY_PATH`, fat/universal binary support
- **PE**: case-insensitive DLL lookup, API set DLL skipping (`api-ms-win-*`, `ext-ms-win-*`), Windows system directory search order, sysroot/Wine prefix support

## Installation

Add it to your `Cargo.toml`:

```toml
[dependencies]
lddtree = "0.4"
```

## Usage

```rust,no_run
use lddtree::DependencyAnalyzer;

// Analyze with default settings (root = "/")
let deps = DependencyAnalyzer::default()
    .analyze("/usr/bin/python3")
    .unwrap();

println!("Interpreter: {:?}", deps.interpreter);
println!("Direct dependencies: {:?}", deps.needed);
for (name, lib) in &deps.libraries {
    println!("  {} => {} (found: {})", name, lib.path.display(), lib.found());
}
```

```rust,no_run
use lddtree::DependencyAnalyzer;
use std::path::PathBuf;

// Analyze with a custom sysroot and additional library paths
let deps = DependencyAnalyzer::new("/path/to/sysroot".into())
    .library_paths(vec![PathBuf::from("/extra/lib")])
    .analyze("path/to/binary")
    .unwrap();
```

## Command line utility

There is also a simple CLI utility which can be installed via:

```bash
cargo install lddtree
```

Usage: `lddtree <pathname> [root]`

- `pathname` is the path to a shared library or executable (ELF, Mach-O, or PE).
- `root` is an optional path to a sysroot directory.

## License

This work is released under the MIT license. A copy of the license is provided
in the [LICENSE](./LICENSE) file.
