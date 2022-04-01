use std::error;
use std::fmt;
use std::io;

use crate::ld_so_conf::LdSoConfError;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Goblin(goblin::error::Error),
    LdSoConf(LdSoConfError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => e.fmt(f),
            Error::Goblin(e) => e.fmt(f),
            Error::LdSoConf(e) => e.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Io(e) => e.source(),
            Error::Goblin(e) => e.source(),
            Error::LdSoConf(e) => e.source(),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<goblin::error::Error> for Error {
    fn from(e: goblin::error::Error) -> Self {
        Error::Goblin(e)
    }
}

impl From<LdSoConfError> for Error {
    fn from(e: LdSoConfError) -> Self {
        Error::LdSoConf(e)
    }
}
