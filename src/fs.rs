use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
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
use crate::meta::{self, MetaFile, Metadata};
use crate::client::VmeClient;

macro_rules! to_string_or_reply_err {
    ($name:expr, $reply:expr) => {
        match $name.to_str() {
            Some(name) => name.to_owned(),
            None => {
                $reply.error(EINVAL);
                return;
            }
        }
    };
}

macro_rules! try_into_or_reply_err {
    ($obj:expr, $reply:expr) => {
        match $obj.try_into() {
            Ok(obj) => obj,
            Err(err) => {
                log::error!("Conversion failed for {}, error: {}", stringify!($obj), err);
                $reply.error(EINVAL);
                return;
            }
        }
    };
}

macro_rules! client_op_or_reply_err {
    ($self:expr, $op:ident, ($($arg:expr),*), $reply:expr, $variant:ident) => {
        match $self.client.$op($($arg),*) {
            Ok(FsOpResponse::$variant { entry }) => entry,
            Ok(_) => {
                $reply.error(EINVAL);
                return;
            }
            Err(e) => {
                log::error!("Client {} failed: {:?}", stringify!($op), e);
                $reply.error(EIO);
                return;
            }
        }
    };
}

pub struct VmeFS {
    root: PathBuf,
    client: VmeClient,
}

impl VmeFS {
    pub fn new(root: PathBuf, client: VmeClient) -> Self {
        Self { root, client }
    }

    fn find_path_by_ino(&self, target_ino: u64) -> Option<PathBuf> {
        if target_ino == 1 {
            return Some(self.root.clone());
        }
        self.find_path_recursive(&self.root, target_ino)
    }

    fn find_path_recursive(&self, dir: &Path, target_ino: u64) -> Option<PathBuf> {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(metadata) = entry.metadata() {
                    if metadata.ino() == target_ino {
                        return Some(path);
                    }
                    if metadata.is_dir() {
                        if let Some(found) = self.find_path_recursive(&path, target_ino) {
                            return Some(found);
                        }
                    }
                }
            }
        }
        None
    }

    fn get_attr(&self, path: &Path) -> Result<FileAttr, i32> {
        let metadata = fs::metadata(path).map_err(|e| e.raw_os_error().unwrap_or(ENOENT))?;

        let kind = if metadata.is_dir() {
            FileType::Directory
        } else if metadata.is_file() {
            FileType::RegularFile
        } else if metadata.is_symlink() {
            FileType::Symlink
        } else {
            FileType::BlockDevice
        };

        let mut ino = metadata.ino();
        if path == self.root {
            ino = 1;
        }

        // Read metadata from .meta file, error out if it fails (except for root)
        let (size, mode, uid, gid) = if path == self.root {
            (0, metadata.mode(), metadata.uid(), metadata.gid())
        } else {
            let m = meta::load_metadata(path)?;
            (
                m.metadata.size,
                m.metadata.mode,
                m.metadata.uid,
                m.metadata.gid,
            )
        };

        Ok(FileAttr {
            ino,
            size,
            blocks: metadata.blocks(),
            atime: SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.atime() as u64),
            mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.mtime() as u64),
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.ctime() as u64),
            crtime: SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.ctime() as u64),
            kind,
            perm: mode as u16,
            nlink: metadata.nlink() as u32,
            uid,
            gid,
            rdev: metadata.rdev() as u32,
            flags: 0,
            blksize: metadata.blksize() as u32,
        })
    }

    fn create_impl(
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
            }
        };

        let encrypted: EncryptedMetaFile = metafile.try_into()?;
        let FsOpResponse::GetAttr { entry } = self.client.create(parent, encrypted)? else {
            return Err(Error::AbiError("GetAttr response expected"));
        };
        let host_metadata = entry.host_metadata.clone();
        let metafile: MetaFile = entry.try_into()?;
        let attr = metafile.to_file_attr(host_metadata)?;
        Ok(attr)
    }

    fn read_impl(&mut self, ino: u64) -> Result<Vec<u8>> {
        let FsOpResponse::FileContent { content } = self.client.read(ino)? else {
            return err(Error::AbiError("FileContent response expected"));
        };
        crypto::decrypt(&content)
    }

    fn readdir_impl(&mut self, ino: u64) -> Result<Vec<ReaddirEntry>> {
        let FsOpResponse::ReadDir { entries } = self.client.readdir(ino)? else {
            return Err(Error::AbiError("ReadDir response expected"));
        };
        let dirs = Vec::with_capacity(entries.len() + 2);

        // Add . and ..
        dirs.push(ReaddirEntry {
            name: ".".to_string(),
            ino: metadata.ino(),
            kind: FileType::Directory,
        });
        // For simplicity, we use current dir metadata for ..
        dirs.push(ReaddirEntry {
            name: "..".to_string(),
            ino: metadata.ino(),
            kind: FileType::Directory,
        });
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
}

const TTL: Duration = Duration::from_secs(1); // 1 second attribute cache

struct ReaddirEntry {
    name: String,
    ino: u64,
    kind: FileType,
}

impl Filesystem for VmeFS {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if name.to_string_lossy().ends_with(".meta") {
            reply.error(ENOENT);
            return;
        }
        let parent_path = match self.find_path_by_ino(parent) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let child_path = parent_path.join(name);

        if child_path.exists() {
            match self.get_attr(&child_path) {
                Ok(attr) => reply.entry(&TTL, &attr, 0),
                Err(e) => reply.error(e),
            }
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        let path = match self.find_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };

        match self.get_attr(&path) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(e),
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
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let path = match self.find_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };

        let metadata_update = meta::MetadataUpdate {
            size,
            mode,
            uid,
            gid,
        };
        if let Some(s) = size {
            let encrypted_content = fs::read(&path).unwrap_or_default();
            let mut content = match crypto::decrypt(&encrypted_content) {
                Ok(c) => c,
                Err(e) => {
                    reply.error(EIO);
                    return;
                }
            };
            content.resize(s as usize, 0);
            match crypto::encrypt(&content) {
                Ok(encrypted) => {
                    if let Err(e) = fs::write(&path, encrypted) {
                        reply.error(e.raw_os_error().unwrap_or(ENOENT));
                        return;
                    }
                }
                Err(e) => {
                    reply.error(EIO);
                    return;
                }
            }
        }

        if metadata_update != Default::default() {
            let _ = meta::update_metadata(&path, metadata_update);
        }

        match self.get_attr(&path) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(e),
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
        let path = match self.find_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };

        let mut entries = Vec::new();

        // Add . and ..
        if let Ok(metadata) = fs::metadata(&path) {
            entries.push(ReaddirEntry {
                name: ".".to_string(),
                ino: metadata.ino(),
                kind: FileType::Directory,
            });
            // For simplicity, we use current dir metadata for ..
            entries.push(ReaddirEntry {
                name: "..".to_string(),
                ino: metadata.ino(),
                kind: FileType::Directory,
            });
        }

        if let Ok(dir) = fs::read_dir(&path) {
            for entry in dir.flatten() {
                let file_name = entry.file_name().to_string_lossy().into_owned();
                if file_name.ends_with(".meta") {
                    continue;
                }
                if let Ok(metadata) = entry.metadata() {
                    let kind = if metadata.is_dir() {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    };
                    entries.push(ReaddirEntry {
                        name: file_name,
                        ino: metadata.ino(),
                        kind,
                    });
                }
            }
        }

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            let mut ent_ino = entry.ino;
            if entry.name == "." || (entry.name == ".." && path == self.root) {
                if path == self.root {
                    ent_ino = 1;
                }
            }

            if reply.add(ent_ino, (i + 1) as i64, entry.kind, &entry.name) {
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
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyWrite,
    ) {
        let path = match self.find_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };

        let encrypted_content = fs::read(&path).unwrap_or_default();
        let mut content = match self.decrypt(&encrypted_content) {
            Ok(c) => c,
            Err(e) => {
                reply.error(e);
                return;
            }
        };

        let offset = offset as usize;
        if offset + data.len() > content.len() {
            content.resize(offset + data.len(), 0);
        }

        content[offset..offset + data.len()].copy_from_slice(data);

        match self.encrypt(&content) {
            Ok(encrypted) => match fs::write(&path, encrypted) {
                Ok(_) => {
                    let update = meta::MetadataUpdate {
                        size: Some(content.len() as u64),
                        ..Default::default()
                    };
                    let _ = meta::update_metadata(&path, update);
                    reply.written(data.len() as u32)
                }
                Err(e) => reply.error(e.raw_os_error().unwrap_or(ENOENT)),
            },
            Err(e) => reply.error(e),
        }
    }

    fn create(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let name_str = to_string_or_reply_err!(name, reply);
        let attr = self.create_impl(req, parent, name_str, mode, umask).expect("create impl");
        reply.created(&TTL, &attr, 0, 0, 0);
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
        let parent_path = match self.find_path_by_ino(parent) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let child_path = parent_path.join(name);

        match fs::create_dir(&child_path) {
            Ok(_) => {
                let _ = meta::create_metadata(
                    &child_path,
                    meta::MetadataUpdate {
                        size: Some(0),
                        mode: Some(mode & !umask),
                        uid: Some(req.uid()),
                        gid: Some(req.gid()),
                    },
                );
                match self.get_attr(&child_path) {
                    Ok(attr) => reply.entry(&TTL, &attr, 0),
                    Err(e) => reply.error(e),
                }
            }
            Err(e) => reply.error(e.raw_os_error().unwrap_or(ENOENT)),
        }
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.find_path_by_ino(parent) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let child_path = parent_path.join(name);

        match fs::remove_file(&child_path) {
            Ok(_) => {
                let _ = meta::remove_metadata(&child_path);
                reply.ok()
            }
            Err(e) => reply.error(e.raw_os_error().unwrap_or(ENOENT)),
        }
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.find_path_by_ino(parent) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let child_path = parent_path.join(name);

        match fs::remove_dir(&child_path) {
            Ok(_) => {
                let _ = meta::remove_metadata(&child_path);
                reply.ok()
            }
            Err(e) => reply.error(e.raw_os_error().unwrap_or(ENOENT)),
        }
    }
}
