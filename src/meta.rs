use std::time::{Duration, SystemTime};

use fortanix_vme_abi::fs::{HostMetadata, FileType as AbiFileType};
use fuser::FileAttr;
use serde::{Deserialize, Serialize};

use crate::Result;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Metadata {
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime: Option<u64>,
    pub mtime: Option<u64>,
    pub ctime: Option<u64>,
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
            blocks,
            ino, kind,
            nlink,
            rdev,
            atime: host_atime,
            mtime: host_mtime,
            ctime: host_ctime,
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
            atime,
            mtime,
            ctime,
        } = *metadata;

        Ok(FileAttr {
            ino,
            size,
            blocks,
            atime: SystemTime::UNIX_EPOCH + Duration::from_secs(atime.unwrap_or(host_atime)),
            mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(mtime.unwrap_or(host_mtime)),
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(ctime.unwrap_or(host_ctime)),
            crtime: SystemTime::UNIX_EPOCH + Duration::from_secs(ctime.unwrap_or(host_ctime)),
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
