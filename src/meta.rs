use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use fortanix_vme_abi::fs::{HostMetadata, FileType as AbiFileType};
use fuser::FileAttr;
use libc::{EIO, ENOENT};
use serde::{Deserialize, Serialize};

use crate::Result;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Metadata {
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Default, Debug, PartialEq, Clone)]
pub struct MetadataUpdate {
    pub size: Option<u64>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

// This structure represents properties of
// certain file.
// A file where this structure contain information about called source file.
// 
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct MetaFile {
    // Filename of the source file 
    pub name: String,

    // Metadata of the source file
    pub metadata: Metadata,
}

impl MetaFile {
    pub fn to_file_attr(&self, host_metadata: HostMetadata) -> Result<FileAttr> {
        let HostMetadata {
            blocks, ino, kind, nlink, rdev, atime, mtime, ctime,
        } = host_metadata;
        let kind = match kind {
            AbiFileType::Directory => fuser::FileType::Directory,
            AbiFileType::RegularFile => fuser::FileType::RegularFile,
            AbiFileType::Symlink => fuser::FileType::Symlink,
        };

        let Self {
            name: _,
            metadata,
        } = self;
        let Metadata {
            size,
            mode,
            uid,
            gid,
        } = *metadata;

        Ok(FileAttr {
            ino,
            size,
            blocks,
            atime: SystemTime::UNIX_EPOCH + Duration::from_secs(atime),
            mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(mtime),
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(ctime),
            crtime: SystemTime::UNIX_EPOCH + Duration::from_secs(ctime),
            kind,
            perm: mode as u16,
            nlink,
            uid,
            gid,
            rdev,
            flags: 0,
            blksize: 4096,
        })
    }
}

fn meta_file_path(path: &Path) -> PathBuf {
    let mut meta_path = path.to_path_buf();
    meta_path.set_extension("meta");
    meta_path
}

pub fn create_metadata(path: &Path, metadata: MetadataUpdate) -> Result<(), i32> {
    let name = path
        .file_name()
        .ok_or(ENOENT)?
        .to_string_lossy()
        .into_owned();
    let vme_file_meta = MetaFile {
        name,
        metadata: Metadata {
            size: metadata.size.unwrap_or(0),
            mode: metadata.mode.unwrap_or(0o644),
            uid: metadata.uid.unwrap_or(0),
            gid: metadata.gid.unwrap_or(0),
        },
    };

    let meta_path = meta_file_path(path);

    let f = fs::File::create(meta_path).map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
    serde_cbor::to_writer(f, &vme_file_meta).map_err(|_| EIO)?;
    Ok(())
}

pub fn update_metadata(path: &Path, update: MetadataUpdate) -> Result<(), i32> {
    let mut metadata = load_metadata(path)?;
    if let Some(size) = update.size {
        metadata.metadata.size = size;
    }
    if let Some(mode) = update.mode {
        metadata.metadata.mode = mode;
    }
    if let Some(uid) = update.uid {
        metadata.metadata.uid = uid;
    }
    if let Some(gid) = update.gid {
        metadata.metadata.gid = gid;
    }

    let meta_path = meta_file_path(path);
    let f = fs::File::create(meta_path).map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
    serde_cbor::to_writer(f, &metadata).map_err(|_| EIO)?;
    Ok(())
}

pub fn load_metadata(path: &Path) -> Result<MetaFile, i32> {
    let meta_path = meta_file_path(path);

    let f = fs::File::open(meta_path).map_err(|e| e.raw_os_error().unwrap_or(ENOENT))?;
    serde_cbor::from_reader::<MetaFile, _>(f).map_err(|_| EIO)
}

pub fn remove_metadata(path: &Path) -> Result<(), i32> {
    let meta_path = meta_file_path(path);
    fs::remove_file(meta_path).map_err(|e| e.raw_os_error().unwrap_or(ENOENT))
}
