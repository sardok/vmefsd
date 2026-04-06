use std::io::Error as IoError;
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
    #[error("Vsock error")]
    VsockError(#[from] IoError),
}

impl From<AesError> for Error {
    fn from(value: AesError) -> Self {
        Self::CryptoError(value.to_string())
    }
}
