use std::fs;
use std::process::{Command, Child};
use std::panic;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::thread;

pub struct RunnerContext {
    pub runner_child: Child,
    pub vmefs_child: Child,
    pub mountpoint: PathBuf,
    pub backend: PathBuf,
}

impl Drop for RunnerContext {
    fn drop(&mut self) {
        cleanup_resources(
            Some(&mut self.vmefs_child),
            Some(&mut self.runner_child),
            Some(&self.mountpoint),
            Some(&self.backend),
        );
    }
}

fn cleanup_resources(
    vmefs_child: Option<&mut Child>,
    runner_child: Option<&mut Child>,
    mountpoint: Option<&PathBuf>,
    backend: Option<&PathBuf>,
) {
    // Stop vmefsd first
    if let Some(child) = vmefs_child {
        let _ = child.kill();
        let _ = child.wait();
    }

    // Unmount
    if let Some(mnt) = mountpoint {
        let _ = Command::new("fusermount")
            .arg("-u")
            .arg(mnt)
            .status();
        let _ = fs::remove_dir_all(mnt);
    }

    // Stop runner
    if let Some(child) = runner_child {
        let _ = child.kill();
        let _ = child.wait();
    }

    // Clean up backend
    if let Some(be) = backend {
        let _ = fs::remove_dir_all(be);
    }
}

struct PartialContext {
    pub runner_child: Option<Child>,
    pub vmefs_child: Option<Child>,
    pub mountpoint: Option<PathBuf>,
    pub backend: Option<PathBuf>,
}

impl Drop for PartialContext {
    fn drop(&mut self) {
        cleanup_resources(
            self.vmefs_child.as_mut(),
            self.runner_child.as_mut(),
            self.mountpoint.as_ref(),
            self.backend.as_ref(),
        );
    }
}

pub fn with_runner_context<F>(test: F)
where
    F: FnOnce(&RunnerContext) + panic::UnwindSafe,
{
    let context = setup_integration_test();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        test(&context);
    }));

    drop(context);

    if let Err(err) = result {
        panic::resume_unwind(err);
    }
}

pub fn setup_integration_test() -> RunnerContext {
    let mut partial = PartialContext {
        runner_child: None,
        vmefs_child: None,
        mountpoint: None,
        backend: None,
    };

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
    partial.mountpoint = Some(mountpoint.clone());
    fs::create_dir_all(&backend).expect("failed to create backend");
    partial.backend = Some(backend.clone());

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
    
    partial.runner_child = Some(runner_child);

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

    partial.vmefs_child = Some(vmefs_child);

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
        runner_child: partial.runner_child.take().unwrap(),
        vmefs_child: partial.vmefs_child.take().unwrap(),
        mountpoint: partial.mountpoint.take().unwrap(),
        backend: partial.backend.take().unwrap(),
    }
}
