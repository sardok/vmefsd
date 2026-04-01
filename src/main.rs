use std::env;
use std::fs as std_fs;
use std::path::PathBuf;

use fs::VmeFS;

mod client;
mod crypto;
mod error;
mod extensions;
mod fs;
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

    let options = vec![fuser::MountOption::FSName("vmefs".to_string())];

    println!(
        "Mounting VmeFS at {} with backend {}",
        mountpoint,
        backend_path.display()
    );
    let Ok(client) = client::VmeClient::new(u32::MAX) else {
        panic!("Unable to connect to {}", u32::MAX);
    };
    fuser::mount2(VmeFS::new(client), mountpoint, &options).unwrap();
}
