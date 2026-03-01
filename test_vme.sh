#!/bin/bash
set -e

MOUNTPOINT="/tmp/vmefs_mnt"
BACKEND="/tmp/vmefs_backend"

# Ensure directories exist
mkdir -p $MOUNTPOINT
mkdir -p $BACKEND

# Clean up any previous mount
fusermount -u $MOUNTPOINT || true
rm -rf $MOUNTPOINT/*
rm -rf $BACKEND/*

# Build the project
cargo build

# Run VmeFS in the background
RUST_BACKTRACE=1 ./target/debug/vmefsd $MOUNTPOINT &
VMEFS_PID=$!

# Wait for mount
sleep 2

# Check if mounted
if ! mount | grep -q $MOUNTPOINT; then
    echo "Mount failed!"
    kill $VMEFS_PID || true
    exit 1
fi

echo "Testing file creation..."
echo "Hello VmeFS!" > $MOUNTPOINT/test.txt
cat $MOUNTPOINT/test.txt

echo "Testing directory creation..."
mkdir $MOUNTPOINT/subdir
echo "Inside subdir" > $MOUNTPOINT/subdir/subtest.txt
ls -R $MOUNTPOINT

echo "Verifying backend..."
ls -R $BACKEND
cat $BACKEND/test.txt

# Clean up
fusermount -u $MOUNTPOINT
kill $VMEFS_PID || true

echo "Test completed successfully!"
