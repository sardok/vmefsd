use std::io::{self, Read, Write};

use fortanix_vme_abi::{SERVER_PORT, Request, Response};
use fortanix_vme_abi::fs::{FsOpResponse, FsOpRequest};
use vsock::{VsockStream, VsockAddr};

use crate::Result;
use crate::error::Error;
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

    pub fn initroot(&mut self, encrypted_meta_file: EncryptedMetaFile) -> Result<FsOpResponse> {
        let EncryptedMetaFile {
            name: _,
            metadata,
        } = encrypted_meta_file;
        let op_req = FsOpRequest::InitRoot { metadata };
        self.send_recv(op_req)
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

        self.send_recv(op_req)
    }

    pub fn read(&mut self, ino: u64) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::Read { ino };
        self.send_recv(op_req)
    }

    pub fn write(&mut self, ino: u64, content: Vec<u8>, flags: i32) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::Write { ino, content, flags };
        self.send_recv(op_req)
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

        self.send_recv(op_req)
    }

    pub fn readdir(&mut self, ino: u64, offset: i64) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::ReadDir { ino, offset };
        self.send_recv(op_req)
    }

    pub fn setattr(&mut self, ino: u64, encrypted_metadata: Vec<u8>) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::SetAttr {
            ino,
            metadata: encrypted_metadata,
        };
        self.send_recv(op_req)
    }

    pub fn getattr(&mut self, ino: u64) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::GetAttr { ino };
        self.send_recv(op_req)
    }

    pub fn lookup(&mut self, ino: u64, name: String) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::Lookup { ino, name };
        self.send_recv(op_req)
    }

    pub fn unlink(&mut self, ino: u64, name: String) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::Unlink { ino, name };
        self.send_recv(op_req)
    }

    pub fn rmdir(&mut self, ino: u64, name: String) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::RmDir { ino, name };
        self.send_recv(op_req)
    }

    fn send_recv(&mut self, op_req: FsOpRequest) -> Result<FsOpResponse> {
        self.send(op_req)?;
        let response = self.recv()?;
        match response {
            Response::FileSystem(resp) => Ok(resp),
            Response::Failed(e) => Err(Error::AbiError(e.to_string())),
            r => Err(Error::AbiError(format!("Unexpected response type from runner: {:?}", r))),
        }
    }

    fn send(&mut self, op_req: FsOpRequest) -> Result<()> {
        let request = Request::FileSystem(op_req);
        let payload = serde_cbor::to_vec(&request)?;

        self.stream.write_all(&payload.len().to_le_bytes())?;
        self.stream.write_all(&payload)?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Response> {
        let mut size_buf = [0u8; std::mem::size_of::<usize>()];
        self.stream.read_exact(&mut size_buf)?;
        let size = usize::from_le_bytes(size_buf);

        let mut resp_buf = vec![0u8; size];
        self.stream.read_exact(&mut resp_buf)?;
        let response: Response = serde_cbor::from_slice(&resp_buf)?;
        Ok(response)
    }
}
