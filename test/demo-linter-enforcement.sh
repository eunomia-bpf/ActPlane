#!/bin/bash
# Demo: userspace linter rules for agent-invoked writes
#
# Runs `linter-check.sh` over a clean TypeScript file and a file carrying
# three violations, showing the linter passes the first and rejects the
# second with one message per rule.
#
# Scope: this demo exercises the linter only. It does not drive ActPlane.
# ActPlane has no per-violation userspace command hook. A kernel match is
# appended to `.actplane/last-violation.txt` (and to the run mailbox), and
# `actplane feedback-hook` forwards newly appended bytes to the agent as
# `additionalContext`; it never executes a linter itself. Kernel coverage of
# the write is `test/policies/14_linter_enforced_writes.yaml`, a `notify
# write` rule gated on `after exec "**/lint"`. Running the linter is the
# agent's step, taken after that feedback arrives.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
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
echo "The linter rules above are what an agent should run after ActPlane"
echo "reports a linting match; ActPlane does not invoke the linter itself."

# Cleanup
rm -rf "$TESTDIR"
echo
echo "=== Demo complete ==="
