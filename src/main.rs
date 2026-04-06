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

    let options = vec![fuser::MountOption::FSName("vmefs".to_string())];

    println!(
        "Mounting VmeFs at {} with backend {}",
        mountpoint,
        backend_path.display()
    );
    let client = match client::VmeClient::new(vsock::VMADDR_CID_HOST) {
        Ok(client) => {
            log::info!("Connected to CID_HOST");
            client
        },
        Err(e) => {
            log::warn!("Unable to connect to CID_HOST: {}", e);
            let Ok(client) = client::VmeClient::new(vsock::VMADDR_CID_LOCAL) else {
                log::error!("Unable to connect to CID_LOCAL: {}", e);
                std::process::exit(1);
            };

            log::info!("Connected to CID_LOCAL");
            client
        }
    };
    let mut vmefs = VmeFs::new(client);
    vmefs.initialize().expect("Failed to initialize VmeFs");
    fuser::mount2(vmefs, mountpoint, &options).unwrap();
}
