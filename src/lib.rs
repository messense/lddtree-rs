use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use goblin::elf::Elf;

mod ld_so_conf;

pub use ld_so_conf::parse_ldsoconf;

#[derive(Debug, Clone)]
pub struct Library {
    pub path: PathBuf,
    pub needed: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DependencyTree {
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub libraries: HashMap<String, Library>,
}

#[derive(Debug, Clone)]
pub struct DependencyAnalyzer {}

impl DependencyAnalyzer {
    pub fn new() -> DependencyAnalyzer {
        DependencyAnalyzer {}
    }

    pub fn analyze(&self, path: impl AsRef<Path>) -> DependencyTree {
        let buffer = fs::read(path.as_ref()).unwrap();
        let elf = Elf::parse(&buffer).unwrap();
        let mut needed = Vec::new();
        let mut libraries = HashMap::new();

        for lib in &elf.libraries {
            needed.push(lib.to_string());
            libraries.insert(
                lib.to_string(),
                // FIXME: get real path and needed libraries
                Library {
                    path: PathBuf::from(lib),
                    needed: Vec::new(),
                },
            );
        }

        DependencyTree {
            interpreter: elf.interpreter.map(|interp| interp.to_string()),
            needed,
            libraries,
        }
    }
}
