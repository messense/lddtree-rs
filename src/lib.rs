use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

use fs_err as fs;
use goblin::elf::{
    dynamic::{DT_RPATH, DT_RUNPATH},
    Elf,
};
use goblin::strtab::Strtab;

mod errors;
pub mod ld_so_conf;

pub use errors::Error;
use ld_so_conf::parse_ldsoconf;

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
pub struct DependencyAnalyzer {
    env_ld_paths: Vec<String>,
    conf_ld_paths: Vec<String>,
}

impl DependencyAnalyzer {
    pub fn new() -> DependencyAnalyzer {
        DependencyAnalyzer {
            env_ld_paths: Vec::new(),
            conf_ld_paths: Vec::new(),
        }
    }

    pub fn analyze(&mut self, path: impl AsRef<Path>) -> Result<DependencyTree, Error> {
        let path = path.as_ref();
        self.load_ld_paths(path)?;

        let buffer = fs::read(path)?;
        let elf = Elf::parse(&buffer)?;

        let mut rpaths = Vec::new();
        let mut runpaths = Vec::new();
        if let Some(dynamic) = elf.dynamic {
            let dyn_info = &dynamic.info;
            let dynstrtab = Strtab::parse(&buffer, dyn_info.strtab, dyn_info.strsz, 0x0)?;
            for dyn_ in &dynamic.dyns {
                if dyn_.d_tag == DT_RUNPATH {
                    if let Some(runpath) = dynstrtab.get_at(dyn_.d_val as usize) {
                        runpaths = parse_ld_paths(runpath, path)?;
                    }
                } else if dyn_.d_tag == DT_RPATH {
                    if let Some(rpath) = dynstrtab.get_at(dyn_.d_val as usize) {
                        rpaths = parse_ld_paths(rpath, path)?;
                    }
                }
            }
        }
        if !runpaths.is_empty() {
            // If both RPATH and RUNPATH are set, only the latter is used.
            rpaths = Vec::new();
        }

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

        let dep_tree = DependencyTree {
            interpreter: elf.interpreter.map(|interp| interp.to_string()),
            needed,
            libraries,
        };
        Ok(dep_tree)
    }

    fn load_ld_paths(&mut self, elf_path: &Path) -> Result<(), Error> {
        if let Ok(env_ld_path) = env::var("LD_LIBRARY_PATH") {
            self.env_ld_paths = parse_ld_paths(&env_ld_path, elf_path)?;
        }
        // Load all the paths from a ldso config file
        match find_musl_libc() {
            // musl libc
            Ok(Some(_musl_libc)) => {
                // from https://git.musl-libc.org/cgit/musl/tree/ldso/dynlink.c?id=3f701faace7addc75d16dea8a6cd769fa5b3f260#n1063
                for entry in glob::glob("/etc/ld-musl-*.path").expect("invalid glob pattern") {
                    if let Ok(entry) = entry {
                        let content = fs::read_to_string(&entry)?;
                        for line in content.lines() {
                            let line_stripped = line.trim();
                            if !line_stripped.is_empty() {
                                self.conf_ld_paths.push(line_stripped.to_string());
                            }
                        }
                        break;
                    }
                }
                // default ld paths
                if self.conf_ld_paths.is_empty() {
                    self.conf_ld_paths.push("/lib".to_string());
                    self.conf_ld_paths.push("/usr/local/lib".to_string());
                    self.conf_ld_paths.push("/usr/lib".to_string());
                }
            }
            // glibc
            _ => {
                // Load up /etc/ld.so.conf
                if let Ok(paths) = parse_ldsoconf("/etc/ld.so.conf") {
                    self.conf_ld_paths = paths;
                }
                // the trusted directories are not necessarily in ld.so.conf
                for path in &["/lib", "/lib64/", "/usr/lib", "/usr/lib64"] {
                    self.conf_ld_paths.push(path.to_string());
                }
            }
        }
        self.conf_ld_paths.dedup();
        Ok(())
    }
}

/// Parse the colon-delimited list of paths and apply ldso rules
fn parse_ld_paths(ld_path: &str, elf_path: &Path) -> Result<Vec<String>, Error> {
    let mut paths = Vec::new();
    for path in ld_path.split(':') {
        if path.is_empty() {
            // The ldso treats empty paths as the current directory
            paths.push(env::current_dir()?.to_str().unwrap().to_string());
        } else if path.contains("$ORIGIN") {
            if let Some(elf_dir) = elf_path.canonicalize()?.parent() {
                paths.push(path.replace("$ORIGIN", elf_dir.to_str().unwrap()));
            }
        } else {
            paths.push(path.to_string());
        }
    }
    Ok(paths)
}

/// Find musl libc path from executable's ELF header
fn find_musl_libc() -> Result<Option<PathBuf>, Error> {
    let buffer = fs::read("/bin/ls")?;
    let elf = Elf::parse(&buffer)?;
    Ok(elf.interpreter.map(PathBuf::from))
}
