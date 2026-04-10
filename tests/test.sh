#!/bin/sh
echo "=== agnosys tests ==="
cyrius build src/main.cyr /tmp/agnosys_test && /tmp/agnosys_test
echo "exit: $?"
rm -f /tmp/agnosys_test
