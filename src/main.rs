#![feature(normalize_lexically)]

use std::env;
use std::fs as std_fs;
use std::path::PathBuf;

use vmefs::VmeFs;

mod client;
mod crypto;
mod error;
mod extensions;
mod vmefs;
mod meta;

type Result<T> = std::result::Result<T, error::Error>;

fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        println!("Usage: {} <mountpoint> [backend_dir]", args[0]);
        return;
    }
    let mountpoint = &args[1];

    let backend_path = if args.len() == 3 {
        PathBuf::from(&args[2])
    } else {
        PathBuf::from("/tmp/vmefs_backend")
    };

    if !backend_path.exists() {
        std_fs::create_dir_all(&backend_path).expect("Failed to create backend directory");
    }

    let options = vec![
        fuser::MountOption::FSName("vmefs".to_string()),
        fuser::MountOption::DirSync,
        fuser::MountOption::Sync,
    ];

    println!(
        "Mounting VmeFs at {} with backend {}",
        mountpoint,
        backend_path.display()
    );
    let client = client::VmeClient::from_cids().expect("Failed to find vme-runner cid");
    let mut vmefs = VmeFs::new(client, mountpoint.clone());
    vmefs.initialize().expect("Failed to initialize VmeFs");
    fuser::mount2(vmefs, mountpoint, &options).unwrap();
}
