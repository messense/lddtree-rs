# lddtree-rs

[![CI](https://github.com/messense/lddtree-rs/workflows/CI/badge.svg)](https://github.com/messense/lddtree-rs/actions?query=workflow%3ACI)
[![Crates.io](https://img.shields.io/crates/v/lddtree.svg)](https://crates.io/crates/lddtree)
[![docs.rs](https://docs.rs/lddtree/badge.svg)](https://docs.rs/lddtree/)

Read the ELF dependency tree, this does not work like `ldd` in that we do not execute/load code (only read
files on disk).

This is roughly a Rust port of the [lddtree.py](https://github.com/pypa/auditwheel/blob/main/src/auditwheel/lddtree.py)
from the [auditwheel](https://github.com/pypa/auditwheel) project.
It's intended to be used in [maturin](https://github.com/PyO3/maturin) for
[implementing automatic repair of manylinux and musllinux wheels](https://github.com/PyO3/maturin/pull/742).

## Installation

Add it to your ``Cargo.toml``:

```toml
[dependencies]
lddtree = "0.3"
```

## Command line utility

There is also a simple cli utility which can be installed via

```bash
cargo install lddtree
```

Usage: `lddtree <pathname> [root]`

* `pathname` is the path to a linux shared library.
* `root` is an optional path to a sysroot directory.

## License

This work is released under the MIT license. A copy of the license is provided
in the [LICENSE](./LICENSE) file.
