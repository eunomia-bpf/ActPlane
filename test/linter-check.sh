#!/bin/bash
# Linter PoC: called by ActPlane when a write violation is detected.
# Checks whether the written file passes a simple lint rule.
#
# Usage: linter-check.sh <filepath>
# Exit 0 = pass, Exit 1 = fail (violation)
#
# This demonstrates that ActPlane can trigger userspace linters
# on every write, making linter enforcement un-bypassable.

FILE="$1"
if [ -z "$FILE" ]; then
    echo "linter-check: no file specified" >&2
    exit 1
fi

if [ ! -f "$FILE" ]; then
    echo "linter-check: file not found: $FILE" >&2
    exit 0  # file doesn't exist yet, allow
fi

VIOLATIONS=0

# Rule 1: No `any` type in TypeScript files
if [[ "$FILE" == *.ts ]] || [[ "$FILE" == *.tsx ]]; then
    if grep -qP '\bany\b' "$FILE" 2>/dev/null; then
        echo "LINT FAIL: $FILE contains 'any' type"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi

# Rule 2: No console.log in production code (not test files)
if [[ "$FILE" == *.ts ]] || [[ "$FILE" == *.js ]]; then
    if [[ "$FILE" != *test* ]] && [[ "$FILE" != *spec* ]]; then
        if grep -q 'console\.log' "$FILE" 2>/dev/null; then
            echo "LINT FAIL: $FILE contains console.log in production code"
            VIOLATIONS=$((VIOLATIONS + 1))
        fi
    fi
fi

# Rule 3: No secrets in any file
if grep -qiP '(api_key|secret_key|password)\s*=\s*["\x27][^"\x27]+["\x27]' "$FILE" 2>/dev/null; then
    echo "LINT FAIL: $FILE contains hardcoded secret"
    VIOLATIONS=$((VIOLATIONS + 1))
fi

# Rule 4: Python — no bare except
if [[ "$FILE" == *.py ]]; then
    if grep -qP '^\s*except\s*:' "$FILE" 2>/dev/null; then
        echo "LINT FAIL: $FILE contains bare except:"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi

if [ $VIOLATIONS -gt 0 ]; then
    echo "linter-check: $VIOLATIONS violation(s) in $FILE"
    exit 1
else
    exit 0
fi
