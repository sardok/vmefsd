use std::fs;
use std::io::Write;

use serial_test::serial;

mod common;

use common::with_runner_context;

#[test]
#[serial(runner)]
fn file_ops() {
    with_runner_context(|context| {
        let mountpoint = &context.mountpoint;

        let file1 = mountpoint.join("file1.txt");
        let file2 = mountpoint.join("file2.txt");

        // 1. Create multiple files
        fs::File::create(&file1).expect("failed to create file1");
        fs::File::create(&file2).expect("failed to create file2");
        assert!(file1.is_file());
        assert!(file2.is_file());

        // 2. Change content and verify
        let content1 = b"Hello File 1";
        let content2 = b"Hello File 2";

        let mut f1 = fs::OpenOptions::new().write(true).open(&file1).expect("failed to open file1 for write");
        f1.write_all(content1).expect("failed to write to file1");
        drop(f1);

        let mut f2 = fs::OpenOptions::new().write(true).open(&file2).expect("failed to open file2 for write");
        f2.write_all(content2).expect("failed to write to file2");
        drop(f2);

        let read_content1 = fs::read(&file1).expect("failed to read file1");
        assert_eq!(read_content1, content1);

        let read_content2 = fs::read(&file2).expect("failed to read file2");
        assert_eq!(read_content2, content2);

        // 3. Rename files
        let file1_renamed = mountpoint.join("file1_renamed.txt");
        fs::rename(&file1, &file1_renamed).expect("failed to rename file1");
        assert!(!file1.exists());
        assert!(file1_renamed.exists());
        assert_eq!(fs::read(&file1_renamed).expect("failed to read renamed file1"), content1);

        // 4. Delete files
        fs::remove_file(&file1_renamed).expect("failed to remove file1_renamed");
        fs::remove_file(&file2).expect("failed to remove file2");
        assert!(!file1_renamed.exists());
        assert!(!file2.exists());
    });
}
