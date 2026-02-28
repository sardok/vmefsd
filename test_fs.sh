#!/bin/bash

# Configuration
MOUNT_POINT="/tmp/vmefs_test_mount"
BINARY="./target/debug/vmefsd"

# Cleanup function to ensure we always unmount and remove the directory
cleanup() {
    echo "Cleaning up..."
    if mountpoint -q "$MOUNT_POINT"; then
        fusermount3 -u "$MOUNT_POINT"
    fi
    if [ -d "$MOUNT_POINT" ]; then
        rmdir "$MOUNT_POINT"
    fi
    # Kill any remaining background daemon processes
    pkill -f "$BINARY" 2>/dev/null
}

# Trap exit signals to ensure cleanup
trap cleanup EXIT

echo "Building project..."
cargo build || exit 1

echo "Creating mount point at $MOUNT_POINT..."
mkdir -p "$MOUNT_POINT"

echo "Starting FUSE daemon..."
$BINARY "$MOUNT_POINT" &
DAEMON_PID=$!

# Wait for the mount to be ready
echo "Waiting for mount..."
for i in {1..10}; do
    if mountpoint -q "$MOUNT_POINT"; then
        echo "Mounted successfully."
        break
    fi
    if [ $i -eq 10 ]; then
        echo "Error: Timeout waiting for mount."
        exit 1
    fi
    sleep 0.5
done

echo "--- Testing Filesystem ---"
echo "Directory Listing:"
ls -la "$MOUNT_POINT"

echo -e "
Reading hello.txt:"
CONTENT=$(cat "$MOUNT_POINT/hello.txt")
echo "$CONTENT"

if [ "$CONTENT" == "Hello World!" ]; then
    echo -e "
SUCCESS: File content matches expected output."
else
    echo -e "
FAILURE: Content mismatch."
    exit 1
fi

echo "--- Test Complete ---"
