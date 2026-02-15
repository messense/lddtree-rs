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
    root: PathBuf,
    /// Path to the main executable being analyzed (used for @executable_path on macOS)
    executable_path: Option<PathBuf>,
}

impl Default for DependencyAnalyzer {
    fn default() -> Self {
        Self::new(PathBuf::from("/"))
    }
}

/// Extracted library info: (rpaths, needed library names).
type LibInfo = (Vec<String>, Vec<String>);

impl DependencyAnalyzer {
    /// Create a new dependency analyzer.
    pub fn new(root: PathBuf) -> DependencyAnalyzer {
        DependencyAnalyzer {
            env_ld_paths: Vec::new(),
            conf_ld_paths: Vec::new(),
            additional_ld_paths: Vec::new(),
            root,
            executable_path: None,
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

    /// Read and resolve rpaths from a parsed binary.
    ///
    /// For ELF: rpaths go through `parse_ld_paths` which handles `$ORIGIN` expansion.
    /// For MachO: rpaths may contain `@executable_path` or `@loader_path` which are
    ///   resolved relative to the given `path` (the binary that contains the rpaths).
    ///   `@rpath` entries within rpaths don't make sense and are kept as-is.
    fn read_rpath(&self, lib: &impl InspectDylib, path: &Path) -> Result<Vec<String>, Error> {
        let mut rpaths = Vec::new();
        for rpath in lib.rpaths() {
            if lib.format() == BinaryFormat::Elf {
                if let Ok(ld_paths) = self.parse_ld_paths(rpath, path) {
                    rpaths = ld_paths;
                }
            } else {
                // For MachO, rpaths may contain @executable_path or @loader_path.
                // These are resolved here so that when we later use these rpaths
                // for @rpath/ library name resolution, they are already absolute.
                // Example: rpath = "@loader_path/../Frameworks" with loader at
                // /app/Contents/MacOS/binary → resolves to /app/Contents/Frameworks
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
                self.load_elf_paths(path)?;
                self.analyze_dylib(path, elf)?
            }
            Object::Mach(mach) => {
                self.load_macho_paths(path)?;
                match mach {
                    Mach::Fat(fat) => {
                        // Fat/universal binaries contain multiple architecture slices
                        // (e.g., x86_64 + arm64). We select the best matching architecture:
                        // prefer the native arch of the host, otherwise take the first one.
                        let arches: Vec<_> = fat.into_iter().collect();
                        let mut selected = None;
                        for (i, arch) in arches.iter().enumerate() {
                            if let Ok(goblin::mach::SingleArch::MachO(ref macho)) = arch {
                                if selected.is_none() {
                                    selected = Some(i);
                                }
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

        // Dependency resolution stack. Each entry carries:
        //  - lib_name: the library to resolve (e.g., "libfoo.dylib" or "@rpath/libbar.dylib")
        //  - loader_path: path of the binary that imports this library, used to resolve
        //    @loader_path on macOS. For direct deps this is the main binary; for transitive
        //    deps it's the intermediate library that depends on this one.
        //  - lib_rpaths: rpaths from the importing binary, used to resolve @rpath/ prefixes.
        //    Each library has its own rpaths (from LC_RPATH load commands on macOS, or
        //    DT_RPATH/DT_RUNPATH on ELF). When resolving a library's own dependencies,
        //    we use *that library's* rpaths, not the top-level binary's rpaths.
        let mut stack: Vec<(String, PathBuf, Vec<String>)> = needed
            .iter()
            .map(|n| (n.clone(), path.to_path_buf(), rpaths.clone()))
            .collect();

        while let Some((lib_name, loader_path, current_rpaths)) = stack.pop() {
            if libraries.contains_key(&lib_name) {
                continue;
            }

            // API set DLLs (api-ms-win-*, ext-ms-win-*) are virtual DLLs that Windows
            // resolves at runtime through an API set schema mapping. They never exist as
            // real files on disk. We record them as not-found and skip dependency
            // resolution to avoid pointless (and expensive) filesystem searches.
            // See: https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets
            if dylib.format() == BinaryFormat::PE && is_api_set_dll(&lib_name) {
                libraries.insert(lib_name.clone(), not_found_library(&lib_name));
                continue;
            }

            let library = self.find_library(&dylib, &lib_name, &loader_path, &current_rpaths)?;

            // For transitive dependency resolution, use the *found library's* path as the
            // loader_path and its rpaths for @rpath/ resolution. This ensures that:
            // - @loader_path in a transitive dep resolves relative to the intermediate
            //   library, not the top-level binary
            // - @rpath uses the intermediate library's LC_RPATH entries, not the top-level's
            let dep_loader = library.realpath.as_ref().unwrap_or(&library.path).clone();
            let dep_rpaths = library.rpath.clone();
            let dep_needed: Vec<String> = library.needed.clone();

            libraries.insert(lib_name, library);

            for needed_name in dep_needed {
                if !libraries.contains_key(&needed_name) {
                    stack.push((needed_name, dep_loader.clone(), dep_rpaths.clone()));
                }
            }
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

    /// Parse the colon-delimited list of paths and apply ldso rules (ELF-specific).
    ///
    /// Handles `$ORIGIN` / `${ORIGIN}` expansion (replaced with the directory of the
    /// binary that contains the rpath) and root-relative path resolution.
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

    fn load_elf_paths(&mut self, _dylib_path: &Path) -> Result<(), Error> {
        #[cfg(unix)]
        if let Ok(env_ld_path) = env::var("LD_LIBRARY_PATH") {
            if self.root == Path::new("/") {
                self.env_ld_paths = self.parse_ld_paths(&env_ld_path, _dylib_path)?;
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
    /// macOS dyld search order (simplified):
    /// 1. `DYLD_LIBRARY_PATH` — searched first using leaf filename only
    /// 2. rpaths — for `@rpath/` prefixed install names, each LC_RPATH entry is tried
    /// 3. The library's install name path — absolute or `@executable_path`/`@loader_path`
    /// 4. `DYLD_FALLBACK_LIBRARY_PATH` — defaults to `~/lib:/usr/local/lib:/lib:/usr/lib`
    ///
    /// References:
    /// - <http://clarkkromenaker.com/post/library-dynamic-loading-mac/>
    /// - <https://matthew-brett.github.io/docosx/mac_runtime_link.html>
    fn load_macho_paths(&mut self, _dylib_path: &Path) -> Result<(), Error> {
        // DYLD_LIBRARY_PATH: searched before everything else, using leaf filename only.
        // This is intentionally not gated on root == "/" because it's commonly used
        // for testing and development overrides.
        if let Ok(dyld_lib_path) = env::var("DYLD_LIBRARY_PATH") {
            for path in dyld_lib_path.split(':') {
                if !path.is_empty() {
                    self.env_ld_paths.push(path.to_string());
                }
            }
        }
        // DYLD_FALLBACK_LIBRARY_PATH: searched after rpaths and install name.
        // If not set, macOS dyld uses a default set of fallback directories.
        match env::var("DYLD_FALLBACK_LIBRARY_PATH") {
            Ok(fallback_path) => {
                for path in fallback_path.split(':') {
                    if !path.is_empty() {
                        self.conf_ld_paths.push(path.to_string());
                    }
                }
            }
            Err(_) => {
                // Default fallback paths per dyld behavior
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

    /// Resolve a macOS install name path variable.
    ///
    /// macOS uses three special prefixes in library install names and rpaths:
    /// - `@executable_path/` — the directory of the main executable (set once at analyze time)
    /// - `@loader_path/` — the directory of the Mach-O binary that contains the load command.
    ///   This changes for each binary in the dependency chain: when A loads B which loads C,
    ///   `@loader_path` for C's resolution is B's directory, not A's.
    /// - `@rpath/` — a search variable; the remainder is appended to each LC_RPATH entry.
    ///   Returns None because the caller must iterate over rpaths to resolve it.
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
            // @rpath must be resolved by iterating rpaths — return None to signal this
            None
        } else {
            // Absolute or relative path — use as-is
            Some(PathBuf::from(path))
        }
    }

    // ---- PE-specific path loading ----

    /// Load Windows PE-specific library search paths.
    ///
    /// Windows DLL search order (Standard Search Order for Desktop Applications):
    /// 1. The directory from which the application loaded
    /// 2. The system directory (e.g., `C:\Windows\System32`)
    /// 3. The 16-bit system directory (e.g., `C:\Windows\System`)
    /// 4. The Windows directory (e.g., `C:\Windows`)
    /// 5. The current directory
    /// 6. Directories listed in the `PATH` environment variable
    ///
    /// References:
    /// - <https://stefanoborini.com/windows-dll-search-path/>
    /// - <https://stmxcsr.com/dll-search-order.html>
    fn load_pe_paths(&mut self, dylib_path: &Path) -> Result<(), Error> {
        let root_str = self.root.display().to_string();
        let root_str = root_str.strip_suffix('/').unwrap_or(&root_str);
        let root_str = root_str.strip_suffix('\\').unwrap_or(root_str);

        // 1. Application directory
        if let Some(app_dir) = dylib_path.parent() {
            self.env_ld_paths.push(app_dir.display().to_string());
        }

        // 2-4. System directories (relative to root)
        // On 64-bit Windows, System32 contains 64-bit DLLs and SysWOW64 contains
        // 32-bit DLLs. When a 32-bit process accesses System32, Windows transparently
        // redirects to SysWOW64 (the "WoW64 File System Redirector"). Since we don't
        // emulate this redirector, we include both directories and rely on the
        // compatible() check to select the correct architecture.
        //
        // References:
        // - https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector
        // - delvewheel's _translate_directory() handles System32 ↔ SysWOW64 ↔ Sysnative
        for sys_dir in &[
            "Windows/System32",
            "Windows/SysWOW64",
            "Windows/System",
            "Windows",
            "windows/system32",
            "windows/syswow64",
            "windows/system",
            "windows",
            // Wine-style paths
            "drive_c/windows/system32",
            "drive_c/windows/syswow64",
            "drive_c/windows",
        ] {
            let full_path = format!("{}/{}", root_str, sys_dir);
            if Path::new(&full_path).is_dir() {
                self.conf_ld_paths.push(full_path);
            }
        }

        // 5-6. Current directory and PATH environment variable.
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
    /// `loader_path` and `rpaths` provide per-dependency context for MachO/ELF
    /// resolution (see `analyze_dylib` for how they are threaded through the
    /// dependency graph).
    fn find_library(
        &self,
        dylib: &impl InspectDylib,
        lib_name: &str,
        loader_path: &Path,
        rpaths: &[String],
    ) -> Result<Library, Error> {
        match dylib.format() {
            BinaryFormat::MachO => self.find_macho_library(dylib, lib_name, loader_path, rpaths),
            BinaryFormat::PE => self.find_pe_library(dylib, lib_name),
            BinaryFormat::Elf => self.find_elf_library(dylib, lib_name, rpaths),
        }
    }

    /// Try to locate an ELF library.
    ///
    /// Search order: rpaths, `LD_LIBRARY_PATH`, `ld.so.conf` paths, additional paths.
    fn find_elf_library(
        &self,
        dylib: &impl InspectDylib,
        lib_name: &str,
        rpaths: &[String],
    ) -> Result<Library, Error> {
        let candidates: Vec<PathBuf> = rpaths
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
    /// Handles `@rpath/`, `@loader_path/`, `@executable_path/` prefixes.
    ///
    /// Search order:
    /// 1. `DYLD_LIBRARY_PATH` (leaf filename only)
    /// 2. `@rpath` expansion — each rpath from the *depending library* is tried
    /// 3. `@executable_path` / `@loader_path` resolution, or direct absolute path
    /// 4. `DYLD_FALLBACK_LIBRARY_PATH` (leaf filename only)
    /// 5. Additional user-provided paths
    ///
    /// The `rpaths` parameter contains the rpaths from the library that depends on
    /// `lib_name`, NOT the top-level binary. This is critical for transitive deps:
    /// if A (rpaths=[/a/lib]) depends on B (rpaths=[/b/lib]) which depends on
    /// `@rpath/libC.dylib`, we search /b/lib (B's rpaths), not /a/lib (A's rpaths).
    fn find_macho_library(
        &self,
        dylib: &impl InspectDylib,
        lib_name: &str,
        loader_path: &Path,
        rpaths: &[String],
    ) -> Result<Library, Error> {
        let mut candidates: Vec<PathBuf> = Vec::new();

        // Extract the leaf filename for searching flat directories.
        // Install names like "/usr/lib/libSystem.B.dylib" → "libSystem.B.dylib"
        let file_name = Path::new(lib_name)
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or(lib_name);

        // 1. DYLD_LIBRARY_PATH — searched first, using just the leaf filename
        for path in &self.env_ld_paths {
            candidates.push(PathBuf::from(path).join(file_name));
        }

        // 2-3. Handle @-prefixed install names
        if let Some(rest) = lib_name.strip_prefix("@rpath/") {
            // @rpath/foo.dylib → try each rpath directory with the suffix.
            // rpaths come from the *depending* library, already resolved by read_rpath
            // (so @loader_path/@executable_path within rpaths are already expanded).
            for rpath in rpaths {
                candidates.push(PathBuf::from(rpath).join(rest));
            }
            // Fallback: also try the @rpath suffix (not just the leaf filename) against
            // DYLD_FALLBACK_LIBRARY_PATH. This matches delocate's behavior of appending
            // /usr/local/lib and /usr/lib as fallback search directories for @rpath
            // resolution. For @rpath/subdir/libfoo.dylib this correctly tries
            // /usr/local/lib/subdir/libfoo.dylib rather than just /usr/local/lib/libfoo.dylib.
            for path in &self.conf_ld_paths {
                candidates.push(PathBuf::from(path).join(rest));
            }
            for path in &self.additional_ld_paths {
                candidates.push(path.join(rest));
            }
        } else if let Some(resolved) = self.resolve_macho_path(lib_name, loader_path) {
            // @executable_path/..., @loader_path/..., or absolute path
            candidates.push(resolved);

            // 4. DYLD_FALLBACK_LIBRARY_PATH — for non-@rpath install names, search
            // using the leaf filename (the path-less library name portion).
            for path in &self.conf_ld_paths {
                candidates.push(PathBuf::from(path).join(file_name));
            }

            // 5. Additional user-provided paths
            for path in &self.additional_ld_paths {
                candidates.push(path.join(file_name));
            }
        }

        self.try_library_candidates(dylib, lib_name, &candidates)
    }

    /// Try to locate a PE library (DLL).
    ///
    /// Uses case-insensitive filename matching because Windows filesystems are
    /// case-insensitive but this tool may run on a case-sensitive filesystem
    /// (e.g., Linux analyzing a Windows sysroot). Without this, a PE importing
    /// "KERNEL32.dll" would fail to match a file named "kernel32.dll".
    ///
    /// Search order:
    /// 1. Application directory (from `env_ld_paths`)
    /// 2. System directories (from `conf_ld_paths`)
    /// 3. `PATH` directories (from `conf_ld_paths`)
    /// 4. Additional user-provided paths
    fn find_pe_library(&self, dylib: &impl InspectDylib, lib_name: &str) -> Result<Library, Error> {
        for dir_str in self.env_ld_paths.iter().chain(self.conf_ld_paths.iter()) {
            let dir = Path::new(dir_str);
            if let Some(lib_path) = find_file_case_insensitive(dir, lib_name) {
                if let Some(lib) = self.try_single_candidate(dylib, lib_name, &lib_path)? {
                    return Ok(lib);
                }
            }
        }
        for dir in &self.additional_ld_paths {
            if let Some(lib_path) = find_file_case_insensitive(dir, lib_name) {
                if let Some(lib) = self.try_single_candidate(dylib, lib_name, &lib_path)? {
                    return Ok(lib);
                }
            }
        }
        Ok(not_found_library(lib_name))
    }

    /// Try a list of candidate paths and return the first compatible library found.
    ///
    /// Used by ELF and MachO library finding, which generate candidate paths directly.
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
            if let Some(lib) = self.try_single_candidate(dylib, lib_name, lib_path)? {
                return Ok(lib);
            }
        }
        Ok(not_found_library(lib_name))
    }

    /// Check if a parsed binary is compatible with the main binary and extract
    /// its rpaths and needed libraries.
    fn check_compatible(
        &self,
        dylib: &impl InspectDylib,
        lib: &impl InspectDylib,
        obj: &Object,
        lib_path: &Path,
    ) -> Result<Option<LibInfo>, Error> {
        if dylib.compatible(obj) {
            Ok(Some((
                self.read_rpath(lib, lib_path)?,
                lib.libraries().iter().map(ToString::to_string).collect(),
            )))
        } else {
            Ok(None)
        }
    }

    /// Try to parse a single candidate file and check compatibility.
    ///
    /// Opens the file, memory-maps it, parses the binary format, checks that it is
    /// compatible with the main binary, and extracts rpaths and needed libraries.
    ///
    /// For fat/universal Mach-O binaries, iterates through architecture slices to find
    /// one that is compatible with the main binary. This is important because dependent
    /// libraries on macOS are often distributed as universal binaries containing
    /// multiple architectures (e.g., x86_64 + arm64), and we need to pick the right
    /// slice to extract the correct rpaths and dependency list.
    fn try_single_candidate(
        &self,
        dylib: &impl InspectDylib,
        lib_name: &str,
        lib_path: &Path,
    ) -> Result<Option<Library>, Error> {
        let file = match fs::File::open(lib_path) {
            Ok(f) => f,
            Err(_) => return Ok(None),
        };
        // SAFETY: The file is memory-mapped read-only and we only perform read operations
        // on the mapped bytes.
        let bytes = match unsafe { Mmap::map(&file) } {
            Ok(m) => m,
            Err(_) => return Ok(None),
        };
        let obj = match Object::parse(&bytes) {
            Ok(o) => o,
            Err(_) => return Ok(None),
        };

        let info = match obj {
            Object::Elf(ref elf) => self.check_compatible(dylib, elf, &obj, lib_path)?,
            Object::Mach(ref mach) => match mach {
                Mach::Fat(ref fat) => {
                    // Fat/universal Mach-O: iterate through architecture slices to find
                    // one that is compatible with the main binary. We construct a
                    // temporary Object for each slice to reuse the compatible() trait
                    // method, which checks cputype, bitness, and endianness.
                    //
                    // MultiArch re-parses from the underlying byte buffer on each
                    // iteration, so the fat binary can be iterated multiple times.
                    let mut found = None;
                    for arch in fat.into_iter() {
                        if let Ok(goblin::mach::SingleArch::MachO(inner)) = arch {
                            // Wrap in Object to reuse compatible(), then unwrap to
                            // extract rpaths/libraries from the matched architecture.
                            let inner_obj = Object::Mach(Mach::Binary(inner));
                            if dylib.compatible(&inner_obj) {
                                let Object::Mach(Mach::Binary(ref macho)) = inner_obj else {
                                    unreachable!()
                                };
                                found = Some((
                                    self.read_rpath(macho, lib_path)?,
                                    macho.libraries().iter().map(ToString::to_string).collect(),
                                ));
                                break;
                            }
                        }
                    }
                    found
                }
                Mach::Binary(ref macho) => self.check_compatible(dylib, macho, &obj, lib_path)?,
            },
            Object::PE(ref pe) => self.check_compatible(dylib, pe, &obj, lib_path)?,
            _ => None,
        };

        if let Some((rpath, needed)) = info {
            Ok(Some(Library {
                name: lib_name.to_string(),
                path: lib_path.to_path_buf(),
                realpath: fs::canonicalize(lib_path).ok(),
                needed,
                rpath,
            }))
        } else {
            Ok(None)
        }
    }
}

/// Create a not-found library entry.
///
/// Used when a library cannot be located on disk (or is a virtual library like
/// Windows API sets). The library is recorded with `realpath: None` so callers
/// can detect it via `Library::found()`.
fn not_found_library(lib_name: &str) -> Library {
    Library {
        name: lib_name.to_string(),
        path: PathBuf::from(lib_name),
        realpath: None,
        needed: Vec::new(),
        rpath: Vec::new(),
    }
}

/// Check if a DLL name is a Windows API set.
///
/// API sets (e.g., `api-ms-win-crt-runtime-l1-1-0.dll`) and extension API sets
/// (e.g., `ext-ms-win-ntuser-draw-l1-1-0.dll`) are virtual DLL names that Windows
/// resolves to real host DLLs at runtime via an API set schema. They never exist
/// as files on disk. Trying to locate them is pointless and expensive.
///
/// References:
/// - <https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets>
/// - delvewheel uses `re.compile('api-.*')` to skip these
fn is_api_set_dll(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.starts_with("api-") || lower.starts_with("ext-ms-")
}

/// Find a file in a directory using case-insensitive name matching.
///
/// Windows filesystems (NTFS, FAT32) are case-insensitive: `KERNEL32.dll`,
/// `kernel32.dll`, and `Kernel32.DLL` all refer to the same file. However, when
/// analyzing a Windows sysroot on a case-sensitive filesystem (e.g., Linux ext4),
/// an exact-case lookup for `KERNEL32.dll` will fail if the file is stored as
/// `kernel32.dll`. This function handles that mismatch by falling back to a
/// directory scan with case-insensitive comparison when the exact match fails.
fn find_file_case_insensitive(dir: &Path, name: &str) -> Option<PathBuf> {
    // Fast path: try exact match first (also handles case-insensitive filesystems
    // like macOS HFS+ and Windows NTFS natively)
    let exact = dir.join(name);
    if exact.exists() {
        return Some(exact);
    }
    // Slow path: scan directory entries for case-insensitive match.
    // This is O(n) in the number of directory entries, but only runs when the
    // exact match fails (i.e., on case-sensitive filesystems with case mismatches).
    let name_lower = name.to_lowercase();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return None,
    };
    for entry in entries.flatten() {
        if let Some(file_name) = entry.file_name().to_str() {
            if file_name.to_lowercase() == name_lower {
                return Some(entry.path());
            }
        }
    }
    None
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_api_set_dll() {
        assert!(is_api_set_dll("api-ms-win-crt-runtime-l1-1-0.dll"));
        assert!(is_api_set_dll("api-ms-win-core-synch-l1-2-0.dll"));
        assert!(is_api_set_dll("API-MS-WIN-CRT-STDIO-L1-1-0.DLL"));
        assert!(is_api_set_dll("ext-ms-win-ntuser-draw-l1-1-0.dll"));
        assert!(!is_api_set_dll("KERNEL32.dll"));
        assert!(!is_api_set_dll("vcruntime140.dll"));
        assert!(!is_api_set_dll("libSystem.B.dylib"));
    }
}
