use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyWrite, Request,
};
use libc::ENOENT;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const TTL: Duration = Duration::from_secs(1); // 1 second attribute cache

pub struct VmeFS {
    root: PathBuf,
}

impl VmeFS {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
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

        Ok(FileAttr {
            ino,
            size: metadata.size(),
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

impl Filesystem for VmeFS {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
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
            if let Err(e) = fs::File::open(&path).and_then(|f| f.set_len(s)) {
                reply.error(e.raw_os_error().unwrap_or(ENOENT));
                return;
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

        let mut entries = vec![
            (ino, FileType::Directory, ".".to_string()),
            (ino, FileType::Directory, "..".to_string()),
        ];

        if let Ok(dir) = fs::read_dir(&path) {
            for entry in dir.flatten() {
                let file_name = entry.file_name().to_string_lossy().into_owned();
                let metadata = entry.metadata().unwrap();
                let kind = if metadata.is_dir() {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };
                entries.push((metadata.ino(), kind, file_name));
            }
        }

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(entry.0, (i + 1) as i64, entry.1, &entry.2) {
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
            Ok(content) => {
                let offset = offset as usize;
                if offset < content.len() {
                    let end = std::cmp::min(offset + size as usize, content.len());
                    reply.data(&content[offset..end]);
                } else {
                    reply.data(&[]);
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

        let mut content = fs::read(&path).unwrap_or_default();
        let offset = offset as usize;
        
        if offset + data.len() > content.len() {
            content.resize(offset + data.len(), 0);
        }
        
        content[offset..offset + data.len()].copy_from_slice(data);
        
        match fs::write(&path, content) {
            Ok(_) => reply.written(data.len() as u32),
            Err(e) => reply.error(e.raw_os_error().unwrap_or(ENOENT)),
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
            Ok(_) => reply.ok(),
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
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e.raw_os_error().unwrap_or(ENOENT)),
        }
    }
}
