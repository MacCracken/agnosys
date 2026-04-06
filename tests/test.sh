#!/bin/sh
CC="${1:-./build/cc2}"
echo "=== agnosys tests ==="
cat src/main.cyr | "$CC" > /tmp/agnosys_test && chmod +x /tmp/agnosys_test && /tmp/agnosys_test
echo "exit: $?"
rm -f /tmp/agnosys_test
