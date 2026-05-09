use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    NotDataFile,
    NotKeyFile,
    NotLogFile,
    DifferentVersion { found: u16 },
    InvalidKeySize,
    InvalidBlockSize,
    InvalidLoadFactor,
    InvalidCapacity,
    InvalidBucketCount,
    InvalidBucketSize,
    InvalidLogIndex,
    InvalidLogSpill,
    HashMismatch,
    UidMismatch,
    AppnumMismatch,
    KeySizeMismatch,
    SaltMismatch,
    PepperMismatch,
    BlockSizeMismatch,
    KeyExists,
    KeyNotFound,
    ValueTooLarge,
    KeyLengthMismatch { expected: usize, actual: usize },
    Corrupt(&'static str),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(error) => write!(f, "{error}"),
            Error::NotDataFile => write!(f, "not a NuDB data file"),
            Error::NotKeyFile => write!(f, "not a NuDB key file"),
            Error::NotLogFile => write!(f, "not a NuDB log file"),
            Error::DifferentVersion { found } => write!(f, "unsupported NuDB version {found}"),
            Error::InvalidKeySize => write!(f, "invalid key size"),
            Error::InvalidBlockSize => write!(f, "invalid block size"),
            Error::InvalidLoadFactor => write!(f, "invalid load factor"),
            Error::InvalidCapacity => write!(f, "invalid bucket capacity"),
            Error::InvalidBucketCount => write!(f, "invalid bucket count"),
            Error::InvalidBucketSize => write!(f, "invalid bucket size"),
            Error::InvalidLogIndex => write!(f, "invalid log bucket index"),
            Error::InvalidLogSpill => write!(f, "invalid logged spill offset"),
            Error::HashMismatch => write!(f, "hash function fingerprint mismatch"),
            Error::UidMismatch => write!(f, "data/key uid mismatch"),
            Error::AppnumMismatch => write!(f, "data/key appnum mismatch"),
            Error::KeySizeMismatch => write!(f, "data/key key size mismatch"),
            Error::SaltMismatch => write!(f, "key/log salt mismatch"),
            Error::PepperMismatch => write!(f, "key/log pepper mismatch"),
            Error::BlockSizeMismatch => write!(f, "key/log block size mismatch"),
            Error::KeyExists => write!(f, "key already exists"),
            Error::KeyNotFound => write!(f, "key not found"),
            Error::ValueTooLarge => write!(f, "value is too large for NuDB"),
            Error::KeyLengthMismatch { expected, actual } => {
                write!(f, "key length mismatch: expected {expected}, got {actual}")
            }
            Error::Corrupt(message) => write!(f, "corrupt NuDB file: {message}"),
        }
    }
}

impl std::error::Error for Error {}
