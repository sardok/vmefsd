use std::io::Error as IoError;
use aes_gcm::Error as AesError;
use serde_cbor::Error as SerdeCborError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Vsock error")]
    VsockError(#[from] IoError),
    #[error("Crypto error: {0}")]
    CryptoError(String),
    #[error("Serde cbor error")]
    CborError(#[from] SerdeCborError),
}

impl From<AesError> for Error {
    fn from(value: AesError) -> Self {
        Self::CryptoError(value.to_string())
    }
}
