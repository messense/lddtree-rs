//! Read the dynamic library dependency tree.
//!
//! Supports ELF (Linux), Mach-O (macOS), and PE (Windows) binary formats.
//!
//! This does not work like `ldd` in that we do not execute/load code (only read
//! files on disk).
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

use fs_err as fs;
use goblin::mach::Mach;
use goblin::Object;
use memmap2::Mmap;

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
    /// The binary's program interpreter (e.g., dynamic linker).
    pub interpreter: Option<String>,
    /// A list of this binary's dynamic libraries it depends on directly.
    pub needed: Vec<String>,
    /// All of this binary's dynamic libraries it uses in detail.
    pub libraries: HashMap<String, Library>,
    /// Runtime library search paths.
    pub rpath: Vec<String>,
}

/// The binary format being analyzed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryFormat {
    Elf,
    MachO,
    PE,
}

trait InspectDylib {
    /// Runtime library search paths.
    fn rpaths(&self) -> &[&str];
    /// A list of this binary's dynamic libraries it depends on directly.
    fn libraries(&self) -> Vec<&str>;
    /// The binary's program interpreter (e.g., dynamic linker).
    fn interpreter(&self) -> Option<&str>;
    /// See if two dynamic libraries are compatible.
    fn compatible(&self, other: &Object) -> bool;
    /// The binary format of this dylib.
    fn format(&self) -> BinaryFormat;
}

/// Library dependency analyzer
#[derive(Debug, Clone)]
pub struct DependencyAnalyzer {
    env_ld_paths: Vec<String>,
    conf_ld_paths: Vec<String>,
    additional_ld_paths: Vec<PathBuf>,
    rpaths: Vec<String>,
    root: PathBuf,
    /// Path to the main executable being analyzed (used for @executable_path on macOS)
    executable_path: Option<PathBuf>,
    /// The detected binary format
    format: Option<BinaryFormat>,
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
            executable_path: None,
            format: None,
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
            if lib.format() == BinaryFormat::Elf {
                if let Ok(ld_paths) = self.parse_ld_paths(rpath, path) {
                    rpaths = ld_paths;
                }
            } else {
                // For MachO, rpaths may contain @executable_path or @loader_path
                // that need resolution, but we store them as-is for now and resolve
                // them during find_library
                let resolved = self.resolve_macho_path(rpath, path);
                if let Some(resolved) = resolved {
                    rpaths.push(resolved.display().to_string());
                } else {
                    rpaths.push(rpath.to_string());
                }
            }
        }
        Ok(rpaths)
    }

    /// Analyze the given binary.
    pub fn analyze(mut self, path: impl AsRef<Path>) -> Result<DependencyTree, Error> {
        let path = path.as_ref();
        self.executable_path = Some(path.to_path_buf());

        let file = fs::File::open(path)?;
        // SAFETY: The file is memory-mapped read-only and we only perform read operations
        // on the mapped bytes. We do not prevent other processes from modifying the file
        // concurrently; such external modification is accepted as a risk for this tool.
        let bytes = unsafe { Mmap::map(&file)? };
        let dep_tree = match Object::parse(&bytes)? {
            Object::Elf(elf) => {
                self.format = Some(BinaryFormat::Elf);
                self.load_elf_paths(path)?;
                self.analyze_dylib(path, elf)?
            }
            Object::Mach(mach) => {
                self.format = Some(BinaryFormat::MachO);
                self.load_macho_paths(path)?;
                match mach {
                    Mach::Fat(fat) => {
                        // For fat/universal binaries, find the best matching architecture.
                        // Prefer the native architecture, otherwise use the first one.
                        let arches: Vec<_> = fat.into_iter().collect();
                        let mut selected = None;
                        for (i, arch) in arches.iter().enumerate() {
                            if let Ok(goblin::mach::SingleArch::MachO(ref macho)) = arch {
                                if selected.is_none() {
                                    selected = Some(i);
                                }
                                // Prefer native arch
                                #[cfg(target_arch = "x86_64")]
                                if macho.header.cputype == goblin::mach::cputype::CPU_TYPE_X86_64 {
                                    selected = Some(i);
                                    break;
                                }
                                #[cfg(target_arch = "aarch64")]
                                if macho.header.cputype == goblin::mach::cputype::CPU_TYPE_ARM64 {
                                    selected = Some(i);
                                    break;
                                }
                            }
                        }
                        match selected {
                            Some(idx) => match arches.into_iter().nth(idx) {
                                Some(Ok(goblin::mach::SingleArch::MachO(macho))) => {
                                    self.analyze_dylib(path, macho)?
                                }
                                _ => return Err(Error::UnsupportedBinary),
                            },
                            None => return Err(Error::UnsupportedBinary),
                        }
                    }
                    Mach::Binary(macho) => self.analyze_dylib(path, macho)?,
                }
            }
            Object::PE(pe) => {
                self.format = Some(BinaryFormat::PE);
                self.load_pe_paths(path)?;
                self.analyze_dylib(path, pe)?
            }
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
            let library = self.find_library(&dylib, &lib_name, path)?;
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
                let interp_realpath = fs::canonicalize(PathBuf::from(&interp_path)).ok();
                libraries.insert(
                    interp.to_string(),
                    Library {
                        name: interp_name.to_string(),
                        path: interp_path,
                        realpath: interp_realpath,
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

    // ---- ELF-specific path loading ----

    /// Parse the colon-delimited list of paths and apply ldso rules (ELF-specific)
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

    fn load_elf_paths(&mut self, dylib_path: &Path) -> Result<(), Error> {
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
                if let Some(entry) = glob::glob(&pattern)
                    .expect("invalid glob pattern")
                    .flatten()
                    .next()
                {
                    let content = fs::read_to_string(&entry)?;
                    for line in content.lines() {
                        let line_stripped = line.trim();
                        if !line_stripped.is_empty() {
                            self.conf_ld_paths
                                .push(root_str.to_string() + line_stripped);
                        }
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

    // ---- MachO-specific path loading ----

    /// Load macOS-specific library search paths.
    ///
    /// macOS dyld search order:
    /// 1. DYLD_LIBRARY_PATH (environment)
    /// 2. rpaths (for @rpath/ prefixed names)
    /// 3. The library's install name path
    /// 4. DYLD_FALLBACK_LIBRARY_PATH (defaults to ~/lib:/usr/local/lib:/lib:/usr/lib)
    ///
    /// See: http://clarkkromenaker.com/post/library-dynamic-loading-mac/
    /// See: https://matthew-brett.github.io/docosx/mac_runtime_link.html
    fn load_macho_paths(&mut self, _dylib_path: &Path) -> Result<(), Error> {
        // DYLD_LIBRARY_PATH: searched before everything else
        if let Ok(dyld_lib_path) = env::var("DYLD_LIBRARY_PATH") {
            for path in dyld_lib_path.split(':') {
                if !path.is_empty() {
                    self.env_ld_paths.push(path.to_string());
                }
            }
        }
        // DYLD_FALLBACK_LIBRARY_PATH: searched after rpaths and install name
        // If not set, defaults to ~/lib:/usr/local/lib:/lib:/usr/lib
        match env::var("DYLD_FALLBACK_LIBRARY_PATH") {
            Ok(fallback_path) => {
                for path in fallback_path.split(':') {
                    if !path.is_empty() {
                        self.conf_ld_paths.push(path.to_string());
                    }
                }
            }
            Err(_) => {
                // Default fallback paths
                if let Ok(home) = env::var("HOME") {
                    self.conf_ld_paths.push(format!("{}/lib", home));
                }
                let root_str = self.root.display().to_string();
                let root_str = root_str.strip_suffix('/').unwrap_or(&root_str);
                self.conf_ld_paths
                    .push(format!("{}/usr/local/lib", root_str));
                self.conf_ld_paths.push(format!("{}/lib", root_str));
                self.conf_ld_paths.push(format!("{}/usr/lib", root_str));
            }
        }
        self.conf_ld_paths.dedup();
        Ok(())
    }

    /// Resolve a macOS path variable (@executable_path, @loader_path, @rpath).
    ///
    /// - `@executable_path/` → replaced with the directory of the main executable
    /// - `@loader_path/` → replaced with the directory of the binary that contains the load command
    /// - `@rpath/` → returns None (must be resolved by iterating rpaths)
    fn resolve_macho_path(&self, path: &str, loader_path: &Path) -> Option<PathBuf> {
        if let Some(rest) = path.strip_prefix("@executable_path/") {
            let exe_dir = self
                .executable_path
                .as_ref()
                .and_then(|p| p.parent())
                .unwrap_or(Path::new("."));
            Some(exe_dir.join(rest))
        } else if let Some(rest) = path.strip_prefix("@loader_path/") {
            let loader_dir = loader_path.parent().unwrap_or(Path::new("."));
            Some(loader_dir.join(rest))
        } else if path.starts_with("@rpath/") {
            // @rpath must be resolved by iterating rpaths - return None
            None
        } else {
            // Absolute or relative path
            Some(PathBuf::from(path))
        }
    }

    // ---- PE-specific path loading ----

    /// Load Windows PE-specific library search paths.
    ///
    /// Windows DLL search order (Standard Search Order):
    /// 1. The directory from which the application loaded
    /// 2. The system directory (e.g., C:\Windows\System32)
    /// 3. The 16-bit system directory (e.g., C:\Windows\System)
    /// 4. The Windows directory (e.g., C:\Windows)
    /// 5. The current directory
    /// 6. Directories listed in the PATH environment variable
    ///
    /// See: https://stefanoborini.com/windows-dll-search-path/
    /// See: https://stmxcsr.com/dll-search-order.html
    fn load_pe_paths(&mut self, dylib_path: &Path) -> Result<(), Error> {
        let root_str = self.root.display().to_string();
        let root_str = root_str.strip_suffix('/').unwrap_or(&root_str);
        let root_str = root_str.strip_suffix('\\').unwrap_or(root_str);

        // 1. Application directory
        if let Some(app_dir) = dylib_path.parent() {
            self.env_ld_paths.push(app_dir.display().to_string());
        }

        // 2-4. System directories (relative to root)
        // Try common Windows system directory layouts
        for sys_dir in &[
            "Windows/System32",
            "Windows/System",
            "Windows",
            "windows/system32",
            "windows/system",
            "windows",
            // Wine-style paths
            "drive_c/windows/system32",
            "drive_c/windows",
        ] {
            let full_path = format!("{}/{}", root_str, sys_dir);
            if Path::new(&full_path).is_dir() {
                self.conf_ld_paths.push(full_path);
            }
        }

        // 5-6. Current directory and PATH environment variable
        // Only use these when analyzing against the real filesystem root,
        // since they contain absolute paths that don't make sense with a
        // custom sysroot. This mirrors how ELF only uses LD_LIBRARY_PATH
        // when root is "/".
        #[cfg(windows)]
        {
            let is_system_root = self.root == Path::new("/")
                || self.root == Path::new("\\")
                || self
                    .root
                    .to_str()
                    .is_some_and(|s| s.len() <= 3 && s.contains(':'));
            if is_system_root {
                if let Ok(cwd) = env::current_dir() {
                    self.conf_ld_paths.push(cwd.display().to_string());
                }
                if let Ok(path_env) = env::var("PATH") {
                    for path in path_env.split(';') {
                        if !path.is_empty() {
                            self.conf_ld_paths.push(path.to_string());
                        }
                    }
                }
            }
        }

        self.conf_ld_paths.dedup();
        Ok(())
    }

    // ---- Library finding ----

    /// Try to locate a `lib_name` that is compatible to `dylib`.
    ///
    /// Dispatches to format-specific find logic based on the binary format.
    fn find_library(
        &self,
        dylib: &impl InspectDylib,
        lib_name: &str,
        loader_path: &Path,
    ) -> Result<Library, Error> {
        match dylib.format() {
            BinaryFormat::MachO => self.find_macho_library(dylib, lib_name, loader_path),
            BinaryFormat::PE => self.find_pe_library(dylib, lib_name),
            BinaryFormat::Elf => self.find_elf_library(dylib, lib_name),
        }
    }

    /// Try to locate an ELF library.
    ///
    /// Search order: rpaths, LD_LIBRARY_PATH, ld.so.conf paths, additional paths.
    fn find_elf_library(
        &self,
        dylib: &impl InspectDylib,
        lib_name: &str,
    ) -> Result<Library, Error> {
        let candidates: Vec<PathBuf> = self
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
            .collect();
        self.try_library_candidates(dylib, lib_name, &candidates)
    }

    /// Try to locate a Mach-O library.
    ///
    /// Handles @rpath/, @loader_path/, @executable_path/ prefixes.
    /// Search order:
    /// 1. DYLD_LIBRARY_PATH
    /// 2. @rpath expansion (if lib_name starts with @rpath/)
    /// 3. @executable_path / @loader_path resolution
    /// 4. Direct path (absolute install name)
    /// 5. DYLD_FALLBACK_LIBRARY_PATH
    /// 6. Additional user-provided paths
    fn find_macho_library(
        &self,
        dylib: &impl InspectDylib,
        lib_name: &str,
        loader_path: &Path,
    ) -> Result<Library, Error> {
        let mut candidates: Vec<PathBuf> = Vec::new();

        // Extract the filename for searching in DYLD_LIBRARY_PATH etc.
        let file_name = Path::new(lib_name)
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or(lib_name);

        // 1. DYLD_LIBRARY_PATH (searched first, using just the leaf filename)
        for path in &self.env_ld_paths {
            candidates.push(PathBuf::from(path).join(file_name));
        }

        // 2-3. Handle path variable prefixes
        if let Some(rest) = lib_name.strip_prefix("@rpath/") {
            // Search each rpath for the library
            for rpath in &self.rpaths {
                candidates.push(PathBuf::from(rpath).join(rest));
            }
        } else if let Some(resolved) = self.resolve_macho_path(lib_name, loader_path) {
            // @executable_path, @loader_path, or absolute path
            candidates.push(resolved);
        }

        // 4. DYLD_FALLBACK_LIBRARY_PATH (using just the leaf filename)
        for path in &self.conf_ld_paths {
            candidates.push(PathBuf::from(path).join(file_name));
        }

        // 5. Additional user-provided paths
        for path in &self.additional_ld_paths {
            candidates.push(path.join(file_name));
        }

        self.try_library_candidates(dylib, lib_name, &candidates)
    }

    /// Try to locate a PE library (DLL).
    ///
    /// Search order:
    /// 1. Application directory (from env_ld_paths)
    /// 2. System directories (from conf_ld_paths)
    /// 3. PATH directories (from conf_ld_paths)
    /// 4. Additional user-provided paths
    fn find_pe_library(&self, dylib: &impl InspectDylib, lib_name: &str) -> Result<Library, Error> {
        let candidates: Vec<PathBuf> = self
            .env_ld_paths
            .iter()
            .chain(self.conf_ld_paths.iter())
            .map(|ld_path| PathBuf::from(ld_path).join(lib_name))
            .chain(
                self.additional_ld_paths
                    .iter()
                    .map(|ld_path| ld_path.join(lib_name)),
            )
            .collect();
        self.try_library_candidates(dylib, lib_name, &candidates)
    }

    /// Try a list of candidate paths and return the first compatible library found.
    fn try_library_candidates(
        &self,
        dylib: &impl InspectDylib,
        lib_name: &str,
        candidates: &[PathBuf],
    ) -> Result<Library, Error> {
        for lib_path in candidates {
            if !lib_path.exists() {
                continue;
            }
            let file = match fs::File::open(lib_path) {
                Ok(f) => f,
                Err(_) => continue,
            };
            // SAFETY: The file is memory-mapped read-only and we only perform read operations
            // on the mapped bytes.
            let bytes = match unsafe { Mmap::map(&file) } {
                Ok(m) => m,
                Err(_) => continue,
            };
            if let Ok(obj) = Object::parse(&bytes) {
                if let Some((rpath, needed)) = match obj {
                    Object::Elf(ref elf) => {
                        if dylib.compatible(&obj) {
                            Some((
                                self.read_rpath(elf, lib_path)?,
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
                                    self.read_rpath(macho, lib_path)?,
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
                                self.read_rpath(pe, lib_path)?,
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
