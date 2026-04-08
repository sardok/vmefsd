use std::io::{self, Error as IoError, Read, Write};

use fortanix_vme_abi::{SERVER_PORT, Error as AbiError, Request, Response};
use fortanix_vme_abi::fs::{FsOpResponse, FsOpRequest, LinkTarget};
use vsock::{VsockStream, VsockAddr};

use crate::Result;
use crate::error::Error;
use crate::crypto::EncryptedMetaFile;

pub struct VmeClient {
    addr: VsockAddr,
}

impl VmeClient {
    pub fn new(cid: u32) -> Self {
        let addr = VsockAddr::new(cid, SERVER_PORT);
        Self { addr }
    }

    fn try_connect(cid: u32) -> io::Result<()> {
        let addr = VsockAddr::new(cid, SERVER_PORT);
        let res = VsockStream::connect(&addr);
        if let Err(e) = res {
            log::warn!("Unable to connect to CID {}: {}", cid, SERVER_PORT);
            return Err(e);
        }

        log::info!("Successfully connected to CID {}", cid);
        {
            // TODO: Should not be necessary
            let mut stream = res?;
            Self::send(&mut stream, Request::Init).expect("send");
            let _ = Self::recv(&mut stream).expect("recv");
        }
        Ok(())
    }

    pub fn from_cids() -> io::Result<Self> {
        match Self::try_connect(vsock::VMADDR_CID_HOST) {
            Ok(_) => Ok(Self::new(vsock::VMADDR_CID_HOST)),
            Err(_) => {
                let _ = Self::try_connect(vsock::VMADDR_CID_LOCAL)?;
                Ok(Self::new(vsock::VMADDR_CID_LOCAL))
            }
        }
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

    pub fn rename(
        &mut self,
        parent: u64,
        name: String,
        new_parent: u64,
        new_name: String,
    ) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::Rename { parent, name, new_parent, new_name };
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

    pub fn symlink(
        &mut self,
        parent: u64,
        name: String,
        target: LinkTarget,
        metadata: Vec<u8>,
    ) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::Symlink {
            parent,
            name,
            target,
            metadata,
        };
        self.send_recv(op_req)
    }

    pub fn readlink(&mut self, ino: u64) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::Readlink { ino };
        self.send_recv(op_req)
    }

    pub fn link(
        &mut self,
        ino: u64,
        new_parent: u64,
        new_name: String,
        metadata: Vec<u8>,
    ) -> Result<FsOpResponse> {
        let op_req = FsOpRequest::Link {
            ino,
            new_parent,
            new_name,
            metadata,
        };
        self.send_recv(op_req)
    }

    fn send_recv(&mut self, op_req: FsOpRequest) -> Result<FsOpResponse> {
        let mut stream = VsockStream::connect(&self.addr)?;
        Self::send(&mut stream, Request::FileSystem(op_req))?;
        let response = Self::recv(&mut stream)?;
        match response {
            Response::FileSystem(resp) => Ok(resp),
            Response::Failed(AbiError::Command(kind)) => {
                let err_kind = io::ErrorKind::from(kind);
                let io_error = IoError::from(err_kind);
                Err(Error::IoError(io_error))
            }
            Response::Failed(AbiError::SystemError(errno)) => {
                let io_error = IoError::from_raw_os_error(errno);
                Err(Error::IoError(io_error))
            }
            Response::Failed(e) => Err(Error::AbiError(e.to_string())),
            r => Err(Error::AbiError(format!("Unexpected response type from runner: {:?}", r))),
        }
    }

    fn send(stream: &mut VsockStream, req: Request) -> Result<()> {
        let payload = serde_cbor::to_vec(&req)?;

        stream.write_all(&payload.len().to_le_bytes())?;
        stream.write_all(&payload)?;
        Ok(())
    }

    fn recv(stream: &mut VsockStream) -> Result<Response> {
        let mut size_buf = [0u8; usize::BITS as usize / 8];
        stream.read_exact(&mut size_buf)?;
        let size = usize::from_le_bytes(size_buf);

        let mut resp_buf = vec![0u8; size];
        stream.read_exact(&mut resp_buf)?;
        let response: Response = serde_cbor::from_slice(&resp_buf)?;
        Ok(response)
    }
}
