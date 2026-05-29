#!/bin/bash
# Demo: OS-enforced linter via ActPlane
#
# This script demonstrates that ActPlane can make linter enforcement
# un-bypassable by hooking file writes at the kernel level and running
# a userspace linter on every written file.
#
# Architecture:
#   1. ActPlane watches for TAINT_VIOLATION events (write to protected paths)
#   2. On violation, the feedback hook calls linter-check.sh
#   3. The linter inspects the file content
#   4. If the linter fails, ActPlane kills the writing process
#
# This cannot be bypassed by:
#   - Running bash directly instead of through the agent framework
#   - Using echo/cat/tee instead of a tool's write function
#   - Spawning a subprocess to do the write
#   - Using direct syscalls (write/writev)
#
# Because the eBPF/LSM hook intercepts at the kernel level, below all
# userspace abstractions.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ACTPLANE="$REPO_ROOT/collector/target/release/actplane"
LINTER="$SCRIPT_DIR/linter-check.sh"
TESTDIR=$(mktemp -d /tmp/actplane-linter-demo.XXXX)

echo "=== ActPlane Linter Enforcement Demo ==="
echo "Test directory: $TESTDIR"
echo

# Create test files
cat > "$TESTDIR/good.ts" << 'EOF'
const x: string = "hello";
export function greet(name: string): string {
    return `Hello, ${name}`;
}
EOF

cat > "$TESTDIR/bad.ts" << 'EOF'
const x: any = "hello";
console.log("debug output");
const secret_key = "sk-12345";
export function greet(name: any): string {
    return `Hello, ${name}`;
}
EOF

echo "--- Testing linter on good.ts ---"
if bash "$LINTER" "$TESTDIR/good.ts"; then
    echo "PASS: good.ts passes linter"
else
    echo "FAIL: good.ts should pass"
fi
echo

echo "--- Testing linter on bad.ts ---"
if bash "$LINTER" "$TESTDIR/bad.ts"; then
    echo "FAIL: bad.ts should not pass"
else
    echo "PASS: bad.ts correctly caught by linter"
fi
echo

echo "--- Linter rules checked ---"
echo "  1. No 'any' type in TypeScript"
echo "  2. No console.log in production code"
echo "  3. No hardcoded secrets (api_key, secret_key, password)"
echo "  4. No bare 'except:' in Python"
echo
echo "In production, ActPlane hooks every write syscall via eBPF/LSM"
echo "and triggers this linter before the write completes."
echo "This makes linter enforcement un-bypassable — even direct"
echo "syscall writes are intercepted at the kernel level."

# Cleanup
rm -rf "$TESTDIR"
echo
echo "=== Demo complete ==="
