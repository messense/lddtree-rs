use std::error::Error;
use std::fmt;
use std::io;
use std::path::Path;

use fs_err as fs;

#[derive(Debug)]
pub enum LdSoConfError {
    /// I/O error
    Io(io::Error),
    /// Glob iteration error
    Glob(glob::GlobError),
    /// Invalid include directive
    InvalidIncludeDirective(String),
}

impl fmt::Display for LdSoConfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LdSoConfError::Io(e) => e.fmt(f),
            LdSoConfError::Glob(e) => e.fmt(f),
            LdSoConfError::InvalidIncludeDirective(line) => {
                write!(f, "invalid include directive: {}", line)
            }
        }
    }
}

impl Error for LdSoConfError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            LdSoConfError::Io(e) => e.source(),
            LdSoConfError::Glob(e) => e.source(),
            LdSoConfError::InvalidIncludeDirective(_) => None,
        }
    }
}

impl From<io::Error> for LdSoConfError {
    fn from(e: io::Error) -> Self {
        LdSoConfError::Io(e)
    }
}

impl From<glob::GlobError> for LdSoConfError {
    fn from(e: glob::GlobError) -> Self {
        LdSoConfError::Glob(e)
    }
}

/// Parse the `ld.so.conf` file on Linux
pub fn parse_ld_so_conf(
    path: impl AsRef<Path>,
    root: impl AsRef<Path>,
) -> Result<Vec<String>, LdSoConfError> {
    let path = path.as_ref();
    let root = root.as_ref();
    let conf = fs::read_to_string(path)?;
    let mut paths = Vec::new();
    for line in conf.lines() {
        if line.starts_with("#") {
            continue;
        }
        if line.starts_with("include ") {
            let include_path = &line[8..];
            let include_path = if !include_path.starts_with('/') {
                let parent = path.parent().unwrap();
                parent.join(include_path).display().to_string()
            } else {
                root.join(include_path.strip_prefix('/').unwrap_or(include_path))
                    .display()
                    .to_string()
            };
            for path in glob::glob(&include_path).map_err(|err| {
                LdSoConfError::InvalidIncludeDirective(format!("{} in '{}'", err, line))
            })? {
                let path = path?;
                paths.extend(parse_ld_so_conf(&path, root)?);
            }
        } else {
            paths.push(
                root.join(line.strip_prefix('/').unwrap_or(line))
                    .display()
                    .to_string(),
            );
        }
    }
    Ok(paths)
}
