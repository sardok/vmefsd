#!/bin/bash
set -e

# Use /tmp directories for testing
MOUNTPOINT="/tmp/vmefs_mnt"
BACKEND="/tmp/vmefs_backend"

# Clean up any previous mount
fusermount -u "$MOUNTPOINT" 2>/dev/null || true
# Wait a bit for unmount to settle
sleep 1

# Remove and recreate directories to ensure they are clean
rm -rf "$MOUNTPOINT" "$BACKEND"
mkdir -p "$MOUNTPOINT"
mkdir -p "$BACKEND"

# Build the project
cargo build

# Run VmeFS in the background
# Pass mountpoint and backend path
./target/debug/vmefsd "$MOUNTPOINT" "$BACKEND" &
VMEFS_PID=$!

# Wait for mount
sleep 2

# Check if mounted
if ! mount | grep -q "$MOUNTPOINT"; then
    echo "Mount failed!"
    kill $VMEFS_PID || true
    exit 1
fi

echo "Testing file creation..."
echo "Hello VmeFS!" > "$MOUNTPOINT/test.txt"
cat "$MOUNTPOINT/test.txt"

echo "Testing directory creation..."
# Directory creation on the mountpoint
mkdir "$MOUNTPOINT/subdir"
echo "Inside subdir" > "$MOUNTPOINT/subdir/subtest.txt"
ls -R "$MOUNTPOINT"

echo "Testing mode (chmod)..."
# Set specific mode
chmod 600 "$MOUNTPOINT/test.txt"
MODE=$(stat -c "%a" "$MOUNTPOINT/test.txt")
if [ "$MODE" = "600" ]; then
    echo "OK: chmod 600 successful on mountpoint"
else
    echo "ERROR: chmod failed, mode is $MODE"
    exit 1
fi

echo "Verifying backend (should be encrypted and have .meta files)..."
ls -R "$BACKEND"

# Check for .meta files (with set_extension, test.txt becomes test.meta)
if [ -f "$BACKEND/test.meta" ]; then
    echo "OK: test.meta exists"
else
    echo "ERROR: test.meta missing"
    ls -la "$BACKEND"
    exit 1
fi

if [ -f "$BACKEND/subdir.meta" ]; then
    echo "OK: subdir.meta exists"
else
    echo "ERROR: subdir.meta missing"
    exit 1
fi

if [ -f "$BACKEND/subdir/subtest.meta" ]; then
    echo "OK: subdir/subtest.meta exists"
else
    echo "ERROR: subdir/subtest.meta missing"
    ls -la "$BACKEND/subdir"
    exit 1
fi

hexdump -C "$BACKEND/test.txt" || true

# Clean up
fusermount -u "$MOUNTPOINT"
kill $VMEFS_PID || true

echo "Test completed successfully!"
