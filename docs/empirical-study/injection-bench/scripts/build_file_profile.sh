#!/usr/bin/env bash
# Lane-owned artifact patch: enable file sink classes for a two-domain topology.
# The supplied source checkout and artifacts remain untouched.
set -euo pipefail
build="$WS_RAW/actplane-file-profile"
mkdir -p "$build"
git -C /workspaces/lanes/translation-models archive fe23a1e730f330768a7a884bd75850dc6852f299 Cargo.toml Cargo.lock bpf crates vmlinux | tar -xf - -C "$build"
cp "$build/bpf/src/lib.rs" "$WS_RAW/actplane-source-before.rs"
cp "$build/bpf/capability.bpf.h" "$WS_RAW/actplane-capability-before.h"
cp "$build/bpf/process.bpf.c" "$WS_RAW/actplane-process-before.c"
python3 - "$build/bpf/src/lib.rs" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1])
s = p.read_text()
old = 'const PINNED_POLICY_FEATURES: u32 = ALL_HOOK_FEATURES;'
new = ('const PINNED_POLICY_FEATURES: u32 = ALL_HOOK_FEATURES '
       '| FEAT_OPEN_RULES | FEAT_WRITE_RULES;')
assert s.count(old) == 1, 'unexpected source identity/profile'
p.write_text(s.replace(old, new))
h = p.parent.parent / 'capability.bpf.h'
s = h.read_text()
assert s.count('#define CAP_DOMAIN_DEPTH 8') == 1
h.write_text(s.replace('#define CAP_DOMAIN_DEPTH 8', '#define CAP_DOMAIN_DEPTH 2'))
s = h.read_text()
old = '__uint(max_entries, 4);\n\t__type(key, __u32);\n\t__type(value, __u64);\n} cap_stats'
assert s.count(old) == 1
s = s.replace(old, old.replace('max_entries, 4', 'max_entries, 13'))
start, end = s.index('cap_check_fields('), s.index('static __always_inline int cap_check_request')
block = s[start:end]
assert block.count('return -1;') == 6
codes = iter(range(1, 7))
block = re.sub(r'return -1;', lambda _: f'return -{next(codes)};', block)
s = s[:start] + block + s[end:]
for name, next_name in [('cap_append_update_admit(', 'cap_append_rule_admit('),
                        ('cap_append_rule_admit(', 'cap_append_update_entry(')]:
    start, end = s.index(name), s.index(next_name)
    block = s[start:end]
    assert block.count('return -1;') == 2
    block = block.replace('return -1;', 'return -7;', 1).replace('return -1;', 'return -8;', 1)
    s = s[:start] + block + s[end:]
for kind in ('update', 'rule'):
    old = (f'if (!r || cap_append_{kind}_admit(r, ctx->current_pid) != 0 ||\n'
           f'\t\t    cap_append_{kind}_entry(r) != 0) {{\n'
           '\t\t\tcap_count(CAP_STAT_REJECT);')
    new = (f'int admit_rc = r ? cap_append_{kind}_admit(r, ctx->current_pid) : -9;\n'
           f'\t\tif (admit_rc != 0 || cap_append_{kind}_entry(r) != 0) {{\n'
           '\t\t\tcap_count(admit_rc < 0 && admit_rc >= -8 ? 3 - admit_rc : 12);\n'
           '\t\t\tcap_count(CAP_STAT_REJECT);')
    assert s.count(old) == 1, kind
    s = s.replace(old, new)
h.write_text(s)
PY
diff -u "$WS_RAW/actplane-source-before.rs" "$build/bpf/src/lib.rs" > "$WS_RAW/actplane-file-profile.patch" || test "$?" = 1
diff -u "$WS_RAW/actplane-capability-before.h" "$build/bpf/capability.bpf.h" >> "$WS_RAW/actplane-file-profile.patch" || test "$?" = 1
diff -u "$WS_RAW/actplane-process-before.c" "$build/bpf/process.bpf.c" >> "$WS_RAW/actplane-file-profile.patch" || test "$?" = 1
mkdir -p "$build/bpf/.output/bpf" "$build/bpf/.output/bpftool/bootstrap"
cp /workspaces/lanes/translation-models/bpf/.output/libbpf.a "$build/bpf/.output/libbpf.a"
cp -r /workspaces/lanes/translation-models/bpf/.output/bpf/. "$build/bpf/.output/bpf/"
cp /workspaces/lanes/translation-models/bpf/.output/bpftool/bootstrap/bpftool "$build/bpf/.output/bpftool/bootstrap/bpftool"
make -C "$build/bpf" .output/process.bpf.o
cp "$build/bpf/.output/process.bpf.o" "$build/bpf/prebuilt/process.bpf.o"
cd "$build"
unset ACTPLANE_REBUILD_BPF
cargo build --release -p actplane
cp target/release/actplane "$WS_RAW/actplane-file-profile-bin"
sha256sum bpf/prebuilt/process.bpf.o "$WS_RAW/actplane-file-profile-bin" > "$WS_RAW/actplane-file-profile-sha256.txt"
printf '%s\n' 'Built lane-owned file-profile artifact with CAP_DOMAIN_DEPTH=2; kernel object changed.'
