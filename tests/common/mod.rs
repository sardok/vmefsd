use std::process::{Command, Child};
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::thread;
use std::fs;

pub struct RunnerContext {
    pub runner_child: Child,
    pub vmefs_child: Child,
    pub mountpoint: PathBuf,
    pub backend: PathBuf,
}

impl Drop for RunnerContext {
    fn drop(&mut self) {
        // Stop vmefsd first
        let _ = self.vmefs_child.kill();
        let _ = self.vmefs_child.wait();

        // Unmount
        let _ = Command::new("fusermount")
            .arg("-u")
            .arg(&self.mountpoint)
            .status();

        // Stop runner
        let _ = self.runner_child.kill();
        let _ = self.runner_child.wait();

        // Clean up directories
        let _ = fs::remove_dir_all(&self.mountpoint);
        let _ = fs::remove_dir_all(&self.backend);
    }
}

pub fn setup_integration_test() -> RunnerContext {
    // 1. Build runner
    let runner_dir = Path::new("../rust-sgx/fortanix-vme/fortanix-vme-runner");
    let status = Command::new("cargo")
        .args(&["build"])
        .current_dir(runner_dir)
        .status()
        .expect("failed to build runner");
    assert!(status.success(), "runner build failed");

    // 2. Build vmefsd
    let status = Command::new("cargo")
        .args(&["build"])
        .status()
        .expect("failed to build vmefsd");
    assert!(status.success(), "vmefsd build failed");

    // 3. Create temp directories
    let test_id = rand::random::<u32>();
    let mountpoint = PathBuf::from(format!("/tmp/vmefs_mnt_{}", test_id));
    let backend = PathBuf::from(format!("/tmp/vmefs_backend_{}", test_id));

    if mountpoint.exists() { let _ = fs::remove_dir_all(&mountpoint); }
    if backend.exists() { let _ = fs::remove_dir_all(&backend); }

    fs::create_dir_all(&mountpoint).expect("failed to create mountpoint");
    fs::create_dir_all(&backend).expect("failed to create backend");

    // 4. Run runner in standalone mode
    let runner_bin = Path::new("../rust-sgx/target/debug/fortanix-vme-runner");
    let runner_log = fs::File::create(format!("/tmp/runner_{}.log", test_id)).expect("failed to create runner log");
    let runner_child = Command::new(runner_bin)
        .env("VMEFS_BACKEND", &backend)
        .args(&[
            "--enclave-file",
            "/bin/true", // no-use
            "standalone",
            "-vv",
        ])
        .stdout(runner_log.try_clone().expect("failed to clone log"))
        .stderr(runner_log)
        .spawn()
        .expect("failed to start runner");
    
    // Wait for the runner to start its server
    thread::sleep(Duration::from_secs(2));

    // 5. Run vmefsd
    let vmefs_bin = Path::new("./target/debug/vmefsd");
    let vmefs_log = fs::File::create(format!("/tmp/vmefsd_{}.log", test_id)).expect("failed to create vmefsd log");
    let vmefs_child = Command::new(vmefs_bin)
        .args(&[
            mountpoint.to_str().unwrap(),
            backend.to_str().unwrap()
        ])
        .stdout(vmefs_log.try_clone().expect("failed to clone log"))
        .stderr(vmefs_log)
        .spawn()
        .expect("failed to start vmefsd");

    // Wait for mount
    let mut mounted = false;
    for _ in 0..10 {
        let status = Command::new("mountpoint")
            .arg("-q")
            .arg(&mountpoint)
            .status()
            .expect("failed to execute mountpoint");
        if status.success() {
            mounted = true;
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
    assert!(mounted, "vmefsd failed to mount at {:?}", mountpoint);

    RunnerContext {
        runner_child,
        vmefs_child,
        mountpoint,
        backend,
    }
}
