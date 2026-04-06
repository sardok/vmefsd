use std::ffi::OsStr;
use std::time::{Duration, SystemTime};

use fortanix_vme_abi::fs::FsOpResponse;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyWrite, Request,
};
use libc::{EINVAL, EIO, ENOENT};

use crate::Result;
use crate::crypto::{self, EncryptedMetaFile};
use crate::error::Error;
use crate::extensions::ToEpochExt;
use crate::meta::{MetaFile, Metadata};
use crate::client::VmeClient;

macro_rules! to_str_or_reply_err {
    ($name:expr, $reply:expr) => {
        match $name.to_str() {
            Some(name) => name,
            None => {
                $reply.error(EINVAL);
                return;
            }
        }
    };
}

macro_rules! to_string_or_reply_err {
    ($name:expr, $reply:expr) => {
        to_str_or_reply_err!($name, $reply).to_owned()
    };
}

pub struct VmeFs {
    client: VmeClient,
}

impl VmeFs {
    pub fn new(client: VmeClient) -> Self {
        Self { client }
    }

    pub fn initialize(&mut self) -> Result<()> {
        let metafile = MetaFile {
            name: ".".to_owned(), // ignored
            metadata: Metadata {
                size: 0,
                mode: 0o755 | libc::S_IFDIR,
                uid: 0,
                gid: 0,
                atime: None,
                mtime: None,
                ctime: None,
            }
        };

        let encrypted: EncryptedMetaFile = metafile.try_into()?;
        let FsOpResponse::Empty = self.client.initroot(encrypted)? else {
            return Err(Error::AbiError("Empty response expected".to_owned()));
        };

        Ok(())
    }

    fn create_impl(
        &mut self,
        req: &Request,
        parent: u64,
        name: String,
        mode: u32,
        umask: u32,
        flags: i32
    ) -> Result<FileAttr> {

        let metafile = MetaFile {
            name: name,
            metadata: Metadata {
                size: 0,
                mode: mode & !umask,
                uid: req.uid(),
                gid: req.gid(),
                atime: None,
                mtime: None,
                ctime: None,
            }
        };

        let encrypted: EncryptedMetaFile = metafile.try_into()?;
        let FsOpResponse::GetAttr { entry } = self.client.create(parent, encrypted, flags)? else {
            return Err(Error::AbiError("GetAttr response expected".to_owned()));
        };
        let host_metadata = entry.host_metadata.clone();
        let metafile: MetaFile = entry.try_into()?;
        let attr = metafile.to_file_attr(host_metadata)?;
        Ok(attr)
    }

    fn mkdir_impl(
        &mut self,
        req: &Request,
        parent: u64,
        name: String,
        mode: u32,
        umask: u32
    ) -> Result<FileAttr> {

        let metafile = MetaFile {
            name: name,
            metadata: Metadata {
                size: 0,
                mode: mode & !umask,
                uid: req.uid(),
                gid: req.gid(),
                atime: None,
                mtime: None,
                ctime: None,
            }
        };

        let encrypted: EncryptedMetaFile = metafile.try_into()?;
        let FsOpResponse::GetAttr { entry } = self.client.mkdir(parent, encrypted)? else {
            return Err(Error::AbiError("GetAttr response expected".to_owned()));
        };
        let host_metadata = entry.host_metadata.clone();
        let metafile: MetaFile = entry.try_into()?;
        let attr = metafile.to_file_attr(host_metadata)?;
        Ok(attr)
    }

    fn read_impl(&mut self, ino: u64) -> Result<Vec<u8>> {
        let FsOpResponse::FileContent { content } = self.client.read(ino)? else {
            return Err(Error::AbiError("FileContent response expected".to_owned()));
        };
        crypto::decrypt(&content)
    }

    fn write_impl(&mut self, ino: u64, mut offset: u64, data: &[u8], flags: i32) -> Result<usize> {
        let mut content = self.read_impl(ino)?;
        let mut flags = flags;
        if flags & libc::O_APPEND != 0 {
            offset = content.len() as u64;
            // Host ignores, but clear it anyway
            flags &= !libc::O_APPEND;
        }

        let offset = offset as usize;
        if offset + data.len() > content.len() {
            content.resize(offset + data.len(), 0);
        }
        content[offset..offset + data.len()].copy_from_slice(data);
        let encrypted = crypto::encrypt(&content)?;
        match self.client.write(ino, encrypted, flags)? {
            FsOpResponse::Empty => Ok(data.len()),
            _ => Err(Error::AbiError("Empty response expected".to_owned())),
        }
    }

    fn getattr_impl(&mut self, ino: u64) -> Result<FileAttr> {
        let FsOpResponse::GetAttr { entry } = self.client.getattr(ino)? else {
            return Err(Error::AbiError("GetAttr response expected".to_owned()));
        };
        let host_metadata = entry.host_metadata.clone();
        let metafile: MetaFile = entry.try_into()?;
        metafile.to_file_attr(host_metadata)
    }

    fn lookup_impl(&mut self, parent: u64, name: &str) -> Result<FileAttr> {
        let encrypted_name = crypto::encrypt_name(name)?;
        let FsOpResponse::GetAttr { entry } = self.client.lookup(parent, encrypted_name)? else {
            return Err(Error::AbiError("GetAttr response expected".to_owned()));
        };
        let host_metadata = entry.host_metadata.clone();
        let metafile: MetaFile = entry.try_into()?;
        metafile.to_file_attr(host_metadata)
    }

    fn readdir_impl(&mut self, ino: u64, offset: i64) -> Result<Vec<ReaddirEntry>> {
        let host_offset = std::cmp::max(0, offset - 2);
        let FsOpResponse::ReadDir { entries } = self.client.readdir(ino, host_offset)? else {
            return Err(Error::AbiError("ReadDir response expected".to_owned()));
        };
        let mut dirs = Vec::with_capacity(entries.len());

        for entry in entries {
            let host_metadata = entry.host_metadata.clone();
            let metafile: MetaFile = entry.try_into()?;
            let attr = metafile.to_file_attr(host_metadata)?;

            dirs.push(ReaddirEntry {
                name: metafile.name,
                ino: attr.ino,
                kind: attr.kind,
            });
        }

        Ok(dirs)
    }

    fn unlink_impl(&mut self, parent: u64, name: &str) -> Result<()> {
        let encrypted_name = crypto::encrypt_name(name)?;
        let _ = self.client.unlink(parent, encrypted_name)?;
        Ok(())
    }

    fn rmdir_impl(&mut self, parent: u64, name: &str) -> Result<()> {
        let encrypted_name = crypto::encrypt_name(name)?;
        let _ = self.client.rmdir(parent, encrypted_name)?;
        Ok(())
    }

    fn get_metafile_impl(&mut self, ino: u64) -> Result<MetaFile> {
        let FsOpResponse::GetAttr { entry } = self.client.getattr(ino)? else {
            return Err(Error::AbiError("GetAttr response expected".to_owned()));
        };
        let metafile: MetaFile = entry.try_into()?;
        Ok(metafile)
    }

    fn setattr_impl(&mut self, ino: u64, metadata: Metadata) -> Result<FileAttr> {
        let serialized = serde_cbor::to_vec(&metadata)?;
        let encrypted = crypto::encrypt(&serialized)?;
        let FsOpResponse::GetAttr { entry } = self.client.setattr(ino, encrypted)? else {
            return Err(Error::AbiError("GetAttr response expected".to_owned()));
        };
        let host_metadata = entry.host_metadata.clone();
        let metafile: MetaFile = entry.try_into()?;
        metafile.to_file_attr(host_metadata)
    }
}

const TTL: Duration = Duration::from_secs(1); // 1 second attribute cache

struct ReaddirEntry {
    name: String,
    ino: u64,
    kind: FileType,
}

impl Filesystem for VmeFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if name.to_string_lossy().ends_with(".meta") {
            reply.error(ENOENT);
            return;
        }
        let name_str = to_string_or_reply_err!(name, reply);

        match self.lookup_impl(parent, &name_str) {
            Ok(attr) => reply.entry(&TTL, &attr, 0),
            Err(e) => {
                log::error!("lookup failed for name {}: {:?}", name_str, e);
                reply.error(ENOENT);
            }
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match self.getattr_impl(ino) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => {
                log::error!("getattr failed for ino {}: {:?}", ino, e);
                reply.error(ENOENT);
            }
        }
    }

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let metafile = match self.get_metafile_impl(ino) {
            Ok(m) => m,
            Err(e) => {
                log::error!("setattr failed to get metafile for ino {}: {:?}", ino, e);
                reply.error(ENOENT);
                return;
            }
        };
        let MetaFile {
            name: _,
            mut metadata,
        } = metafile;

        if let Some(mode) = mode {
            metadata.mode = mode;
        }
        if let Some(uid) = uid {
            metadata.uid = uid;
        }
        if let Some(gid) = gid {
            metadata.gid = gid;
        }
        if let Some(size) = size {
            metadata.size = size;
        }
        if let Some(t) = atime {
            metadata.atime = Some(t.to_u64());
        }
        if let Some(t) = mtime {
            metadata.mtime = Some(t.to_u64());
        }
        if let Some(t) = ctime {
            metadata.ctime = Some(t.to_u64());
        }

        match self.setattr_impl(ino, metadata) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => {
                log::error!("setattr failed for ino {}: {:?}", ino, e);
                reply.error(EIO);
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let entries = match self.readdir_impl(ino, offset) {
            Ok(e) => e,
            Err(e) => {
                log::error!("readdir failed for ino {}: {:?}", ino, e);
                reply.error(EIO);
                return;
            }
        };

        let mut current_offset = offset;

        // Host returns only real files. Guest injects . and ..
        if current_offset == 0 {
            if reply.add(ino, 1, FileType::Directory, ".") {
                reply.ok();
                return;
            }
            current_offset += 1;
        }

        if current_offset == 1 {
            // We use parent ino if we can find it, but for now just use ino
            if reply.add(ino, 2, FileType::Directory, "..") {
                reply.ok();
                return;
            }
            current_offset += 1;
        }

        for entry in entries {
            current_offset += 1;
            if reply.add(entry.ino, current_offset, entry.kind, &entry.name) {
                break;
            }
        }
        reply.ok();
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        let content = self.read_impl(ino).expect("read_impl");
        let offset = offset as usize;
        let size = size as usize;
        if offset < content.len() {
            let end = std::cmp::min(offset + size, content.len());
            reply.data(&content[offset..end]);
        } else {
            reply.data(&[]);
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        flags: i32,
        _lock: Option<u64>,
        reply: ReplyWrite,
    ) {
        match self.write_impl(ino, offset as u64, data, flags) {
            Ok(written) => reply.written(written as u32),
            Err(e) => {
                log::error!("write failed for ino {}: {:?}", ino, e);
                reply.error(EIO);
            }
        }
    }

    fn create(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let name_str = to_string_or_reply_err!(name, reply);
        match self.create_impl(req, parent, name_str, mode, umask, flags) {
            Ok(attr) => reply.created(&TTL, &attr, 0, 0, 0),
            Err(e) => {
                log::error!("create failed: {:?}", e);
                reply.error(EIO);
            }
        }
    }

    fn mkdir(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let name_str = to_string_or_reply_err!(name, reply);
        match self.mkdir_impl(req, parent, name_str, mode, umask) {
            Ok(attr) => reply.entry(&TTL, &attr, 0),
            Err(e) => {
                log::error!("mkdir failed: {:?}", e);
                reply.error(EIO);
            }
        }
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let name = to_str_or_reply_err!(name, reply);

        match self.unlink_impl(parent, name) {
            Ok(_) => reply.ok(),
            Err(e) => {
                log::error!("unlink failed for name {}: {:?}", name, e);
                reply.error(ENOENT);
            }
        }
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let name = to_str_or_reply_err!(name, reply);
        match self.rmdir_impl(parent, name) {
            Ok(_) => reply.ok(),
            Err(e) => {
                log::error!("rmdir failed for name {}: {:?}", name, e);
                reply.error(ENOENT);
            }
        }
    }
}
