mod fs;

use fs::VmeFS;
use std::env;
use std::fs as std_fs;
use std::path::PathBuf;

fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <mountpoint>", args[0]);
        return;
    }
    let mountpoint = &args[1];

    let backend_path = PathBuf::from("/tmp/vmefs_backend");
    if !backend_path.exists() {
        std_fs::create_dir_all(&backend_path).expect("Failed to create backend directory");
    }

    let options = vec![
        fuser::MountOption::FSName("vmefs".to_string()),
    ];
    
    println!("Mounting VmeFS at {} with backend {}", mountpoint, backend_path.display());
    fuser::mount2(VmeFS::new(backend_path), mountpoint, &options).unwrap();
}
