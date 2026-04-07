mod common;

use common::with_runner_context;
use std::fs;

#[test]
fn test_missing_operations() {
    with_runner_context(|context| {
        let mountpoint = &context.mountpoint;

        // Test readdir
        fs::create_dir(mountpoint.join("dir1")).expect("failed to create dir1");
        fs::create_dir(mountpoint.join("dir2")).expect("failed to create dir2");
        fs::write(mountpoint.join("file1"), b"f1").expect("failed to create file1");

        let mut entries: Vec<_> = fs::read_dir(mountpoint).expect("failed to read dir")
            .map(|r| r.map(|e| e.file_name().into_string().unwrap()))
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to collect entries");
        entries.sort();

        // "." and ".." are filtered by read_dir in std::fs,
        assert!(entries.contains(&"dir1".to_string()));
        assert!(entries.contains(&"dir2".to_string()));
        assert!(entries.contains(&"file1".to_string()));

        // Test truncate via setattr
        let file_path = mountpoint.join("truncate_test");
        fs::write(&file_path, b"some data").expect("failed to write");
        let f = fs::OpenOptions::new().write(true).open(&file_path).expect("failed to open");
        f.set_len(4).expect("failed to truncate");
        drop(f);
        assert_eq!(fs::read(&file_path).expect("failed to read"), b"some");
    });
}
