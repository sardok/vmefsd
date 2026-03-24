use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

use crate::meta::MetaFile;
use crate::error::Error;

const STATIC_KEY: &[u8; 32] = b"static_encryption_key_32_bytes!!";
const STATIC_NONCE: &[u8; 12] = b"static_nonce";

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
        let name_base64 = general_purpose::STANDARD_NO_PAD.encode(encrypted_name);

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

impl TryFrom<EncryptedMetaFile> for MetaFile {
    type Error = Error;

    fn try_from(enc: EncryptedMetaFile) -> Result<Self, Self::Error> {
        let cipher = Aes256Gcm::new(STATIC_KEY.into());
        let nonce = Nonce::from_slice(STATIC_NONCE);

        // Decrypt metadata field
        let decrypted_metadata = cipher
            .decrypt(nonce, enc.metadata.as_slice())?;

        // Deserialize to MetaFile
        let meta: MetaFile = serde_cbor::from_slice(&decrypted_metadata)?;

        Ok(meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::Metadata;

    #[test]
    fn test_meta_conversion_roundtrip() {
        let original_meta = MetaFile {
            name: "test_file.txt".to_string(),
            metadata: Metadata {
                size: 1234,
                mode: 0o644,
                uid: 1000,
                gid: 1000,
            },
        };

        // Convert MetaFile to EncryptedMetaFile
        let encrypted: EncryptedMetaFile = original_meta
            .clone()
            .try_into()
            .expect("Failed to convert MetaFile to EncryptedMetaFile");

        // Ensure encryption did something (name is not the same)
        assert_ne!(encrypted.name, original_meta.name);

        // Convert EncryptedMetaFile back to MetaFile
        let decrypted: MetaFile = encrypted
            .try_into()
            .expect("Failed to convert EncryptedMetaFile to MetaFile");

        // Verify roundtrip result matches original
        assert_eq!(original_meta, decrypted);
    }
}
