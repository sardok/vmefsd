use std::io::{self, Write};

use fortanix_vme_abi::SERVER_PORT;
use fortanix_vme_abi::fs::{FsOpResponse, FsOpRequest};
use vsock::{VsockStream, VsockAddr};

use crate::Result;
use crate::crypto::EncryptedMetaFile;

pub struct VmeClient {
    stream: VsockStream,
}

impl VmeClient {
    pub fn new(cid: u32) -> io::Result<Self> {
        let addr = VsockAddr::new(cid, SERVER_PORT);
        let stream = VsockStream::connect(&addr)?;
        Ok(Self { stream })
    }

    pub fn create(&mut self, parent: u64, encrypted_meta_file: EncryptedMetaFile) -> Result<FsOpResponse> {
        let EncryptedMetaFile {
            name,
            metadata,
        } = encrypted_meta_file;
        let op_req = FsOpRequest::Create {
            parent,
            name,
            metadata,
        };

        self.send_recv(&op_req)
    }

    fn send_recv(&mut self, payload: &FsOpRequest) -> Result<FsOpResponse>
    {
        let payload = serde_cbor::to_vec(payload)?;
        self.stream.write_all(&payload)?;
        let resp = serde_cbor::from_reader(&mut self.stream)?;
        Ok(resp)
    }
}
