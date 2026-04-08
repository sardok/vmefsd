use std::error::Error as StdError;
use std::io::{Error as IoError, ErrorKind};
use aes_gcm::Error as AesError;
use serde_cbor::Error as SerdeCborError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("ABI error: {0}")]
    AbiError(String),
    #[error("Serde cbor error")]
    CborError(#[from] SerdeCborError),
    #[error("Crypto error: {0}")]
    CryptoError(String),
    #[error("IO error")]
    IoError(#[from] IoError),
    #[error("Std error")]
    StdError(#[from] Box<dyn StdError>),
}

impl From<AesError> for Error {
    fn from(value: AesError) -> Self {
        Self::CryptoError(value.to_string())
    }
}

pub fn error_kind_to_libc(kind: ErrorKind) -> libc::c_int {
    match kind {
        ErrorKind::NotFound => libc::ENOENT,
        ErrorKind::PermissionDenied => libc::EACCES,
        ErrorKind::ConnectionRefused => libc::ECONNREFUSED,
        ErrorKind::ConnectionReset => libc::ECONNRESET,
        ErrorKind::ConnectionAborted => libc::ECONNABORTED,
        ErrorKind::NotConnected => libc::ENOTCONN,
        ErrorKind::AddrInUse => libc::EADDRINUSE,
        ErrorKind::AddrNotAvailable => libc::EADDRNOTAVAIL,
        ErrorKind::BrokenPipe => libc::EPIPE,
        ErrorKind::AlreadyExists => libc::EEXIST,
        ErrorKind::WouldBlock => libc::EWOULDBLOCK,
        ErrorKind::InvalidInput => libc::EINVAL,
        ErrorKind::TimedOut => libc::ETIMEDOUT,
        ErrorKind::Interrupted => libc::EINTR,
        _ => libc::EIO, // Fallback for general Input/Output error
    }
}
