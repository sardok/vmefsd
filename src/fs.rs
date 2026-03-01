use crate::meta;

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyWrite, Request,
};
use libc::{EIO, ENOENT, EINVAL};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

pub struct VmeFS {
    root: PathBuf,
}

impl VmeFS {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, i32> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        if data.len() < TAG_SIZE {
            return Err(EINVAL);
        }
        let cipher = Aes256Gcm::new(STATIC_KEY.into());
        let nonce = Nonce::from_slice(STATIC_NONCE);
        cipher
            .decrypt(nonce, data)
            .map_err(|_| EIO)
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, i32> {
        let cipher = Aes256Gcm::new(STATIC_KEY.into());
        let nonce = Nonce::from_slice(STATIC_NONCE);
        cipher
            .encrypt(nonce, data)
            .map_err(|_| EIO)
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

        // Read size from .meta file, error out if it fails (except for root)
        let size = if path == self.root {
            0
        } else {
            meta::load_metadata(path).map(|m| m.metadata.size)?
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
            perm: metadata.mode() as u16,
            nlink: metadata.nlink() as u32,
            uid: metadata.uid(),
            gid: metadata.gid(),
            rdev: metadata.rdev() as u32,
            flags: 0,
            blksize: metadata.blksize() as u32,
        })
    }
}

const STATIC_KEY: &[u8; 32] = b"static_encryption_key_32_bytes!!";
const STATIC_NONCE: &[u8; 12] = b"static_nonce";
const TAG_SIZE: usize = 16;
const TTL: Duration = Duration::from_secs(1); // 1 second attribute cache

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
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
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

        if let Some(s) = size {
            let encrypted_content = fs::read(&path).unwrap_or_default();
            let mut content = match self.decrypt(&encrypted_content) {
                Ok(c) => c,
                Err(e) => {
                    reply.error(e);
                    return;
                }
            };
            content.resize(s as usize, 0);
            match self.encrypt(&content) {
                Ok(new_encrypted_content) => {
                    if let Err(e) = fs::write(&path, new_encrypted_content) {
                        reply.error(e.raw_os_error().unwrap_or(ENOENT));
                        return;
                    }
                    let _ = meta::update_metadata(&path, meta::VmeMetadataUpdate { size: Some(s) });
                }
                Err(e) => {
                    reply.error(e);
                    return;
                }
            }
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

        struct ReaddirEntry {
            name: String,
            ino: u64,
            kind: FileType,
        }

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
        let path = match self.find_path_by_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };

        match fs::read(&path) {
            Ok(encrypted_content) => {
                match self.decrypt(&encrypted_content) {
                    Ok(content) => {
                        let offset = offset as usize;
                        if offset < content.len() {
                            let end = std::cmp::min(offset + size as usize, content.len());
                            reply.data(&content[offset..end]);
                        } else {
                            reply.data(&[]);
                        }
                    }
                    Err(e) => reply.error(e),
                }
            }
            Err(e) => reply.error(e.raw_os_error().unwrap_or(ENOENT)),
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
            Ok(new_encrypted_content) => {
                match fs::write(&path, new_encrypted_content) {
                    Ok(_) => {
                        let _ = meta::update_metadata(&path, meta::VmeMetadataUpdate { size: Some(content.len() as u64) });
                        reply.written(data.len() as u32)
                    },
                    Err(e) => reply.error(e.raw_os_error().unwrap_or(ENOENT)),
                }
            }
            Err(e) => reply.error(e),
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let parent_path = match self.find_path_by_ino(parent) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let child_path = parent_path.join(name);
        
        match fs::File::create(&child_path) {
            Ok(_) => {
                let _ = meta::create_metadata(&child_path, meta::VmeMetadataUpdate { size: Some(0) });
                match self.get_attr(&child_path) {
                    Ok(attr) => reply.created(&TTL, &attr, 0, 0, 0),
                    Err(e) => reply.error(e),
                }
            }
            Err(e) => reply.error(e.raw_os_error().unwrap_or(ENOENT)),
        }
    }

    fn mkdir(&mut self, _req: &Request, parent: u64, name: &OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
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
                let _ = meta::create_metadata(&child_path, Default::default());
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
            },
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
                let _  = meta::remove_metadata(&child_path);
                reply.ok()
            },
            Err(e) => reply.error(e.raw_os_error().unwrap_or(ENOENT)),
        }
    }
}
