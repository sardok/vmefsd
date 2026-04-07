mod common;

use common::with_runner_context;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[test]
fn test_directory_operations() {
    with_runner_context(|context| {
        let mountpoint = &context.mountpoint;

        let dir_path = mountpoint.join("test_dir");

        // 1. Create dir
        fs::create_dir(&dir_path).expect("failed to create dir");
        assert!(dir_path.is_dir());

        // 2. Rename dir
        let new_dir_path = mountpoint.join("test_dir_renamed");
        fs::rename(&dir_path, &new_dir_path).expect("failed to rename dir");
        assert!(!dir_path.exists());
        assert!(new_dir_path.is_dir());

        // 3. Change properties (chmod)
        let new_mode = 0o700;
        fs::set_permissions(&new_dir_path, fs::Permissions::from_mode(new_mode)).expect("failed to set permissions");
        let metadata = fs::metadata(&new_dir_path).expect("failed to get metadata");
        assert_eq!(metadata.mode() & 0o777, new_mode);

        // 4. Delete dir
        fs::remove_dir(&new_dir_path).expect("failed to remove dir");
        assert!(!new_dir_path.exists());
    });
}
