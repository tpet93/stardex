#!/bin/bash
# Comprehensive benchmark script for stardex
# Tests different buffer sizes and hash algorithms

set -e

BINARY="./target/release/stardex"
TEST_1024MB="/tmp/test_1024mb.tar"
LINUX_TAR="/tmp/linux-6.6.tar"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Stardex Benchmark Suite ===${NC}"
echo "Environment: $(uname -a | cut -d' ' -f1-3)"
echo "Binary: $BINARY"
echo ""

# Function to run benchmark
run_benchmark() {
  local file=$1
  local algo=$2
  local buffer=$3
  local label=$4
  
  echo -ne "${BLUE}$label${NC} "
  /usr/bin/time -f "%E" bash -c "cat $file | $BINARY --algo $algo --buffer-size $buffer > /dev/null" 2>&1 | tr -d '\n'
  echo ""
}

# Check if test files exist
if [ ! -f "$TEST_1024MB" ]; then
  echo "Creating 1024MB test file..."
  dd if=/dev/urandom of=/tmp/test_1024mb.bin bs=1M count=1024 2>/dev/null
  tar -cf $TEST_1024MB /tmp/test_1024mb.bin 2>/dev/null
  echo "✓ Created $TEST_1024MB"
fi

if [ ! -f "$LINUX_TAR" ]; then
  echo "Downloading Linux kernel tarball..."
  if wget -q --show-progress -O /tmp/linux-6.6.tar.xz https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz; then
      echo "Decompressing..."
      if xz -d /tmp/linux-6.6.tar.xz; then
          echo "✓ Created $LINUX_TAR"
      else
          echo -e "${YELLOW}Warning: Failed to decompress linux tarball.${NC}"
      fi
  else
      echo -e "${YELLOW}Warning: Failed to download linux tarball. Skipping real-world tests.${NC}"
  fi
  echo ""
fi

echo -e "${GREEN}=== Test 1: Buffer Size Comparison (1024MB file, BLAKE3) ===${NC}"
for size in 65536 131072 262144 524288 1048576 2097152 4194304 8388608 16777216 33554432; do
  kb=$((size / 1024))
  run_benchmark "$TEST_1024MB" "blake3" "$size" "Buffer ${kb}KB:"
done
echo ""

echo -e "${GREEN}=== Test 2: Hash Algorithm Comparison (1024MB, 256KB buffer) ===${NC}"
for algo in blake3 sha256 xxh3 xxh64 xxh128 md5 sha1 xxh64; do
  run_benchmark "$TEST_1024MB" "$algo" "262144" "$(printf '%-10s' $algo):"
done
echo ""

if [ -f "$LINUX_TAR" ]; then
  echo -e "${GREEN}=== Test 3: Real-world (Linux 6.6 tarball - 1.4GB, 80k+ files) ===${NC}"
  echo "Buffer size comparison with BLAKE3:"
for size in 65536 131072 262144 524288 1048576 2097152 4194304 8388608 16777216 33554432; do
    kb=$((size / 1024))
    run_benchmark "$LINUX_TAR" "blake3" "$size" "  ${kb}KB:"
  done
  echo ""
  
  echo "Hash algorithm comparison (256KB buffer):"
  for algo in blake3 sha256 xxh3 xxh64 xxh128 md5; do
    run_benchmark "$LINUX_TAR" "$algo" "262144" "  $(printf '%-10s' $algo):"
  done
  echo ""
  
  # Baseline test
  echo "Baseline (no hashing, 256KB buffer):"
  run_benchmark "$LINUX_TAR" "none" "262144" "  none:"
  echo ""
fi

echo -e "${GREEN}=== Benchmark Complete ===${NC}"
