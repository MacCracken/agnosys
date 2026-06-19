#!/bin/sh
echo "=== agnosys tests ==="
cyrius build src/main.cyr /tmp/agnodrm_test && /tmp/agnodrm_test
echo "exit: $?"
rm -f /tmp/agnodrm_test
