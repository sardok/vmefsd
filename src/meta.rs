use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use libc::{EIO, ENOENT};

#[derive(Serialize, Deserialize)]
pub struct VmeMetadata {
    pub size: u64,
}

#[derive(Default)]
pub struct VmeMetadataUpdate {
    pub size: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct VmeFileMeta {
    pub name: String,
    pub metadata: VmeMetadata,
}

fn meta_file_path(path: &Path) -> PathBuf {
    let mut meta_path = path.to_path_buf();
    meta_path.set_extension("meta");
    meta_path
}

pub fn create_metadata(path: &Path, metadata: VmeMetadataUpdate) -> Result<(), i32> {
    let name = path
        .file_name().ok_or(ENOENT)?
        .to_string_lossy()
        .into_owned();
    let vme_file_meta = VmeFileMeta {
        name,
        metadata: VmeMetadata { size: metadata.size.unwrap_or(0) },
    };

    let meta_path = meta_file_path(path);

    let f = fs::File::create(meta_path).map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
    serde_cbor::to_writer(f, &vme_file_meta).map_err(|_| EIO)?;
    Ok(())
}

pub fn update_metadata(path: &Path, update: VmeMetadataUpdate) -> Result<(), i32> {
    let mut metadata = load_metadata(path)?;
    if let Some(size) = update.size {
        metadata.metadata.size = size;
    }

    let meta_path = meta_file_path(path);
    let f = fs::File::create(meta_path).map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
    serde_cbor::to_writer(f, &metadata).map_err(|_| EIO)?;
    Ok(())
}

pub fn load_metadata(path: &Path) -> Result<VmeFileMeta, i32> {
    let meta_path = meta_file_path(path);

    let f = fs::File::open(meta_path).map_err(|e| e.raw_os_error().unwrap_or(ENOENT))?;
    serde_cbor::from_reader::<VmeFileMeta, _>(f).map_err(|_| EIO)
}

pub fn remove_metadata(path: &Path) -> Result<(), i32> {
    let meta_path = meta_file_path(path);
    fs::remove_file(meta_path).map_err(|e| e.raw_os_error().unwrap_or(ENOENT))
}