mod common;

use common::setup_integration_test;
use std::fs;
use std::os::unix::fs::symlink;

#[test]
fn test_link_operations() {
    let context = setup_integration_test();
    let mountpoint = &context.mountpoint;

    let target = mountpoint.join("target.txt");
    fs::write(&target, b"link target").expect("failed to create target file");

    // 1. Soft link
    let symlink_path = mountpoint.join("soft_link");
    symlink("target.txt", &symlink_path).expect("failed to create symlink");
    assert!(fs::read_link(&symlink_path).is_ok());
    assert_eq!(fs::read(&symlink_path).expect("failed to read through symlink"), b"link target");

    // 2. Hard link
    let hardlink_path = mountpoint.join("hard_link");
    fs::hard_link(&target, &hardlink_path).expect("failed to create hardlink");
    assert!(hardlink_path.exists());
    assert_eq!(fs::read(&hardlink_path).expect("failed to read through hardlink"), b"link target");

    // 3. Rename links
    let symlink_renamed = mountpoint.join("soft_link_renamed");
    fs::rename(&symlink_path, &symlink_renamed).expect("failed to rename symlink");
    assert!(!symlink_path.exists());
    assert!(symlink_renamed.exists());

    let hardlink_renamed = mountpoint.join("hard_link_renamed");
    fs::rename(&hardlink_path, &hardlink_renamed).expect("failed to rename hardlink");
    assert!(!hardlink_path.exists());
    assert!(hardlink_renamed.exists());

    // 4. Delete links
    fs::remove_file(&symlink_renamed).expect("failed to remove symlink");
    fs::remove_file(&hardlink_renamed).expect("failed to remove hardlink");
    assert!(!symlink_renamed.exists());
    assert!(!hardlink_renamed.exists());
}
