use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use fortanix_vme_abi::fs::FsEntry;
use serde::{Deserialize, Serialize};

use crate::meta::MetaFile;
use crate::error::Error;

const STATIC_KEY: &[u8; 32] = b"static_encryption_key_32_bytes!!";
const STATIC_NONCE: &[u8; 12] = b"static_nonce";
const BASE64_CONFIG: general_purpose::GeneralPurpose = general_purpose::URL_SAFE_NO_PAD;


pub fn encrypt(data: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(STATIC_KEY.into());
    let nonce = Nonce::from_slice(STATIC_NONCE);
    let encrypted = cipher
        .encrypt(nonce, data)
        .map_err(|e| Error::CryptoError(e.to_string()))?;
    Ok(encrypted)
}

pub fn decrypt(data: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(STATIC_KEY.into());
    let nonce = Nonce::from_slice(STATIC_NONCE);
    let decrypted = cipher
        .decrypt(nonce, data)
        .map_err(|e| Error::CryptoError(e.to_string()))?;
    Ok(decrypted)
}

pub fn encrypt_name(name: &str) -> Result<String, Error> {
    let encrypted = encrypt(name.as_bytes())?;
    Ok(BASE64_CONFIG.encode(encrypted))
}

// This type is identical to MetaFile
// except the fact that all plaintext information
// is encrypted.
#[derive(Deserialize, Serialize, Debug)]
pub struct EncryptedMetaFile {
    pub name: String,
    pub metadata: Vec<u8>,
}

impl TryFrom<MetaFile> for EncryptedMetaFile {
    type Error = Error;

    fn try_from(meta: MetaFile) -> Result<Self, Self::Error> {
        let cipher = Aes256Gcm::new(STATIC_KEY.into());
        let nonce = Nonce::from_slice(STATIC_NONCE);

        // Encrypt and base64 encode name
        let encrypted_name = cipher
            .encrypt(nonce, meta.name.as_bytes())?;
        let name_base64 = BASE64_CONFIG.encode(encrypted_name);

        // Serialize and encrypt MetaFile structure
        let serialized_meta = serde_cbor::to_vec(&meta)?;
        let encrypted_metadata = cipher
            .encrypt(nonce, serialized_meta.as_slice())?;

        Ok(EncryptedMetaFile {
            name: name_base64,
            metadata: encrypted_metadata,
        })
    }
}

impl TryFrom<FsEntry> for MetaFile {
    type Error = Error;

    fn try_from(value: FsEntry) -> Result<Self, Self::Error> {
        let cipher = Aes256Gcm::new(STATIC_KEY.into());
        let nonce = Nonce::from_slice(STATIC_NONCE);

        // Decrypt metadata field
        let decrypted = cipher
            .decrypt(nonce, value.metadata.as_slice())?;

        // Deserialize to MetaFile
        let metafile: MetaFile = serde_cbor::from_slice(&decrypted)?;
        Ok(metafile)
    }
}
