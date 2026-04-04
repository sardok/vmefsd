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

    pub fn create(&mut self, parent: u64, encrypted_meta_file: EncryptedMetaFile, flags: i32) -> Result<FsOpResponse> {
        let EncryptedMetaFile {
            name,
            metadata,
        } = encrypted_meta_file;
        let op_req = FsOpRequest::Create {
            parent,
            name,
            metadata,
            flags,
        };

        self.send_recv(&op_req)
    }

    pub fn read(&mut self, ino: u64) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::Read { ino };
        self.send_recv(&op_req)
    }

    pub fn write(&mut self, ino: u64, content: Vec<u8>, flags: i32) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::Write { ino, content, flags };
        self.send_recv(&op_req)
    }

    pub fn mkdir(&mut self, ino: u64, encrypted_meta_file: EncryptedMetaFile) -> Result<FsOpResponse> {
        let EncryptedMetaFile {
            name,
            metadata,
        } = encrypted_meta_file;
        let op_req = FsOpRequest::Mkdir {
            ino,
            name,
            metadata,
        };

        self.send_recv(&op_req)
    }

    pub fn readdir(&mut self, ino: u64) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::ReadDir { ino };
        self.send_recv(&op_req)
    }

    pub fn setattr(&mut self, ino: u64, encrypted_metadata: Vec<u8>) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::SetAttr {
            ino,
            metadata: encrypted_metadata,
        };
        self.send_recv(&op_req)
    }

    pub fn getattr(&mut self, ino: u64) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::GetAttr { ino };
        self.send_recv(&op_req)
    }

    pub fn lookup(&mut self, ino: u64, name: String) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::Lookup { ino, name };
        self.send_recv(&op_req)
    }

    pub fn unlink(&mut self, ino: u64, name: String) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::Unlink { ino, name };
        self.send_recv(&op_req)
    }

    pub fn rmdir(&mut self, ino: u64, name: String) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::RmDir { ino, name };
        self.send_recv(&op_req)
    }

    fn send_recv(&mut self, payload: &FsOpRequest) -> Result<FsOpResponse> {
        let payload = serde_cbor::to_vec(payload)?;
        self.stream.write_all(&payload)?;
        let resp = serde_cbor::from_reader(&mut self.stream)?;
        Ok(resp)
    }
}
