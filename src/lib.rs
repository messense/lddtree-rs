//! Read the ELF dependency tree.
//!
//! This does not work like `ldd` in that we do not execute/load code (only read
//! files on disk).
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

use fs_err as fs;
use goblin::mach::Mach;
use goblin::Object;

mod elf;
mod errors;
pub mod ld_so_conf;
mod macho;
mod pe;

pub use errors::Error;
use ld_so_conf::parse_ld_so_conf;

/// A library dependency
#[derive(Debug, Clone)]
pub struct Library {
    /// Library name
    pub name: String,
    /// The path to the library.
    pub path: PathBuf,
    /// The normalized real path to the library.
    pub realpath: Option<PathBuf>,
    /// The dependencies of this library.
    pub needed: Vec<String>,
    /// Runtime library search paths.
    pub rpath: Vec<String>,
}

impl Library {
    /// Is this library found in filesystem.
    pub fn found(&self) -> bool {
        self.realpath.is_some()
    }
}

/// Library dependency tree
#[derive(Debug, Clone)]
pub struct DependencyTree {
    /// The binary’s program interpreter (e.g., dynamic linker).
    pub interpreter: Option<String>,
    /// A list of this binary’s dynamic libraries it depends on directly.
    pub needed: Vec<String>,
    /// All of this binary’s dynamic libraries it uses in detail.
    pub libraries: HashMap<String, Library>,
    /// Runtime library search paths.
    pub rpath: Vec<String>,
}

trait InspectDylib {
    /// Runtime library search paths.
    fn rpaths(&self) -> &[&str];
    /// A list of this binary’s dynamic libraries it depends on directly.
    fn libraries(&self) -> Vec<&str>;
    /// The binary’s program interpreter (e.g., dynamic linker).
    fn interpreter(&self) -> Option<&str>;
    /// See if two dynamic libraries are compatible.
    fn compatible(&self, other: &Object) -> bool;
}

/// Library dependency analyzer
#[derive(Debug, Clone)]
pub struct DependencyAnalyzer {
    env_ld_paths: Vec<String>,
    conf_ld_paths: Vec<String>,
    additional_ld_paths: Vec<PathBuf>,
    rpaths: Vec<String>,
    root: PathBuf,
}

impl Default for DependencyAnalyzer {
    fn default() -> Self {
        Self::new(PathBuf::from("/"))
    }
}

impl DependencyAnalyzer {
    /// Create a new dependency analyzer.
    pub fn new(root: PathBuf) -> DependencyAnalyzer {
        DependencyAnalyzer {
            env_ld_paths: Vec::new(),
            conf_ld_paths: Vec::new(),
            additional_ld_paths: Vec::new(),
            rpaths: Vec::new(),
            root,
        }
    }

    /// Add additional library path
    ///
    /// Additional library paths are treated as absolute paths,
    /// not relative to `root`
    pub fn add_library_path(mut self, path: PathBuf) -> Self {
        self.additional_ld_paths.push(path);
        self
    }

    /// Set additional library paths
    ///
    /// Additional library paths are treated as absolute paths,
    /// not relative to `root`
    pub fn library_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.additional_ld_paths = paths;
        self
    }

    fn read_rpath(&self, lib: &impl InspectDylib, path: &Path) -> Result<Vec<String>, Error> {
        let mut rpaths = Vec::new();
        for rpath in lib.rpaths() {
            if let Ok(ld_paths) = self.parse_ld_paths(rpath, path) {
                rpaths = ld_paths;
            }
        }
        Ok(rpaths)
    }

    /// Analyze the given binary.
    pub fn analyze(mut self, path: impl AsRef<Path>) -> Result<DependencyTree, Error> {
        let path = path.as_ref();
        self.load_ld_paths(path)?;

        let bytes = fs::read(path)?;
        let dep_tree = match Object::parse(&bytes)? {
            Object::Elf(elf) => self.analyze_dylib(path, elf)?,
            Object::Mach(mach) => match mach {
                Mach::Fat(_) => return Err(Error::UnsupportedBinary),
                Mach::Binary(macho) => self.analyze_dylib(path, macho)?,
            },
            Object::PE(pe) => self.analyze_dylib(path, pe)?,
            _ => return Err(Error::UnsupportedBinary),
        };
        Ok(dep_tree)
    }

    fn analyze_dylib(
        &mut self,
        path: &Path,
        dylib: impl InspectDylib,
    ) -> Result<DependencyTree, Error> {
        let rpaths = self.read_rpath(&dylib, path)?;

        let needed: Vec<String> = dylib.libraries().iter().map(ToString::to_string).collect();
        let mut libraries = HashMap::new();

        let mut stack = needed.clone();
        while let Some(lib_name) = stack.pop() {
            if libraries.contains_key(&lib_name) {
                continue;
            }
            let library = self.find_library(&dylib, &lib_name)?;
            libraries.insert(lib_name, library.clone());
            stack.extend(library.needed);
        }

        let interpreter = dylib.interpreter().map(|interp| interp.to_string());
        if let Some(ref interp) = interpreter {
            if !libraries.contains_key(interp) {
                let interp_path = self.root.join(interp.strip_prefix('/').unwrap_or(interp));
                let interp_name = interp_path
                    .file_name()
                    .expect("missing filename")
                    .to_str()
                    .expect("Filename isn't valid Unicode");
                libraries.insert(
                    interp.to_string(),
                    Library {
                        name: interp_name.to_string(),
                        path: interp_path,
                        realpath: fs::canonicalize(PathBuf::from(interp)).ok(),
                        needed: Vec::new(),
                        rpath: Vec::new(),
                    },
                );
            }
        }
        let dep_tree = DependencyTree {
            interpreter,
            needed,
            libraries,
            rpath: rpaths,
        };
        Ok(dep_tree)
    }

    /// Parse the colon-delimited list of paths and apply ldso rules
    fn parse_ld_paths(&self, ld_path: &str, dylib_path: &Path) -> Result<Vec<String>, Error> {
        let mut paths = Vec::new();
        for path in ld_path.split(':') {
            let normpath = if path.is_empty() {
                // The ldso treats empty paths as the current directory
                env::current_dir()
            } else if path.contains("$ORIGIN") || path.contains("${ORIGIN}") {
                let dylib_path = fs::canonicalize(dylib_path)?;
                let dylib_dir = dylib_path.parent().expect("no parent");
                let replacement = dylib_dir.to_str().unwrap();
                let path = path
                    .replace("${ORIGIN}", replacement)
                    .replace("$ORIGIN", replacement);
                fs::canonicalize(PathBuf::from(path))
            } else {
                fs::canonicalize(self.root.join(path.strip_prefix('/').unwrap_or(path)))
            };
            if let Ok(normpath) = normpath {
                paths.push(normpath.display().to_string());
            }
        }
        Ok(paths)
    }

    fn load_ld_paths(&mut self, dylib_path: &Path) -> Result<(), Error> {
        #[cfg(unix)]
        if let Ok(env_ld_path) = env::var("LD_LIBRARY_PATH") {
            if self.root == Path::new("/") {
                self.env_ld_paths = self.parse_ld_paths(&env_ld_path, dylib_path)?;
            }
        }
        // Load all the paths from a ldso config file
        match find_musl_libc() {
            // musl libc
            Ok(Some(_musl_libc)) => {
                // from https://git.musl-libc.org/cgit/musl/tree/ldso/dynlink.c?id=3f701faace7addc75d16dea8a6cd769fa5b3f260#n1063
                let root_str = self.root.display().to_string();
                let root_str = root_str.strip_suffix("/").unwrap_or(&root_str);
                let pattern = format!("{}/etc/ld-musl-*.path", root_str);
                for entry in glob::glob(&pattern).expect("invalid glob pattern") {
                    if let Ok(entry) = entry {
                        let content = fs::read_to_string(&entry)?;
                        for line in content.lines() {
                            let line_stripped = line.trim();
                            if !line_stripped.is_empty() {
                                self.conf_ld_paths
                                    .push(root_str.to_string() + line_stripped);
                            }
                        }
                        break;
                    }
                }
                // default ld paths
                if self.conf_ld_paths.is_empty() {
                    self.conf_ld_paths.push(root_str.to_string() + "/lib");
                    self.conf_ld_paths
                        .push(root_str.to_string() + "/usr/local/lib");
                    self.conf_ld_paths.push(root_str.to_string() + "/usr/lib");
                }
            }
            // glibc
            _ => {
                // Load up /etc/ld.so.conf
                if let Ok(paths) = parse_ld_so_conf("/etc/ld.so.conf", &self.root) {
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

    /// Try to locate a `lib_name` that is compatible to `dylib`
    fn find_library(&self, dylib: &impl InspectDylib, lib_name: &str) -> Result<Library, Error> {
        for lib_path in self
            .rpaths
            .iter()
            .chain(self.env_ld_paths.iter())
            .chain(self.conf_ld_paths.iter())
            .map(|ld_path| {
                self.root
                    .join(ld_path.strip_prefix('/').unwrap_or(ld_path))
                    .join(lib_name)
            })
            .chain(
                self.additional_ld_paths
                    .iter()
                    .map(|ld_path| ld_path.join(lib_name)),
            )
        {
            // FIXME: readlink to get real path
            if lib_path.exists() {
                let bytes = fs::read(&lib_path)?;
                if let Ok(obj) = Object::parse(&bytes) {
                    if let Some((rpath, needed)) = match obj {
                        Object::Elf(ref elf) => {
                            if dylib.compatible(&obj) {
                                Some((
                                    self.read_rpath(elf, &lib_path)?,
                                    elf.libraries().iter().map(ToString::to_string).collect(),
                                ))
                            } else {
                                None
                            }
                        }
                        Object::Mach(ref mach) => match mach {
                            Mach::Fat(_) => None,
                            Mach::Binary(ref macho) => {
                                if dylib.compatible(&obj) {
                                    Some((
                                        self.read_rpath(macho, &lib_path)?,
                                        macho.libraries().iter().map(ToString::to_string).collect(),
                                    ))
                                } else {
                                    None
                                }
                            }
                        },
                        Object::PE(ref pe) => {
                            if dylib.compatible(&obj) {
                                Some((
                                    self.read_rpath(pe, &lib_path)?,
                                    pe.libraries().iter().map(ToString::to_string).collect(),
                                ))
                            } else {
                                None
                            }
                        }
                        _ => None,
                    } {
                        return Ok(Library {
                            name: lib_name.to_string(),
                            path: lib_path.to_path_buf(),
                            realpath: fs::canonicalize(lib_path).ok(),
                            needed,
                            rpath,
                        });
                    }
                }
            }
        }
        Ok(Library {
            name: lib_name.to_string(),
            path: PathBuf::from(lib_name),
            realpath: None,
            needed: Vec::new(),
            rpath: Vec::new(),
        })
    }
}

/// Find musl libc path
fn find_musl_libc() -> Result<Option<PathBuf>, Error> {
    match glob::glob("/lib/libc.musl-*.so.1")
        .expect("invalid glob pattern")
        .next()
    {
        Some(Ok(path)) => Ok(Some(path)),
        _ => Ok(None),
    }
}
