#!/usr/bin/env python3
"""Build a minimal experiment loader with equivalent verifier-bounded matchers.

All source copies and binaries go in --raw. No product source or prebuilt object
is edited. The same patched engine is used for references and every model.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

from prepare import HERE, ROOT, DEFAULT_RAW, sha, csv_write


def run(args, cwd, log):
    p = subprocess.run(list(map(str, args)), cwd=cwd, text=True, capture_output=True)
    with log.open('a') as f:
        f.write(' '.join(map(str, args)) + '\n' + p.stdout + p.stderr)
    if p.returncode:
        raise RuntimeError(f'Command failed; inspect {log}')
    return p.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--raw', type=Path, default=DEFAULT_RAW)
    ap.add_argument('--clang', default='clang')
    args = ap.parse_args()
    out = args.raw / 'bounded-loader'
    out.mkdir(parents=True, exist_ok=True)
    for p in (ROOT / 'bpf').glob('*'):
        if p.suffix in ('.h', '.c'):
            shutil.copyfile(p, out / p.name)
    shutil.copyfile(HERE / 'verifier_matchers.h', out / 'verifier_matchers.h')
    engine = out / 'taint_engine.bpf.h'
    text = engine.read_text()
    marker = '#endif /* __BPF__ */\n\n#ifdef ACTPLANE_LEGACY_KERNEL'
    assert text.count(marker) == 1
    text = text.replace(marker, '#include "verifier_matchers.h"\n' + marker)
    # Replace the two calls in the modern path dispatcher only. The original
    # matchers remain present for native equivalence checks.
    text = text.replace('return taint_suffix(text, pat);', 'return tm_suffix(text, pat);')
    text = text.replace('return taint_contains(text, pat);', 'return tm_contains(text, pat);')
    # Remove a wrapper frame introduced by file-source materialization. This
    # changes inlining only, retaining the wrapper's full body and call order.
    wrapper = 'static __noinline void te_materialize_file_source(pid_t pid,'
    assert text.count(wrapper) == 1
    text = text.replace(wrapper, wrapper.replace('__noinline', '__always_inline'))
    wrapper = 'static __noinline void te_materialize_file_source_domain(pid_t pid,'
    assert text.count(wrapper) == 1
    text = text.replace(wrapper, wrapper.replace('__noinline', '__always_inline'))
    engine.write_text(text)
    test = out / 'matcher_equivalence.c'
    test.write_text(r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
#define __noinline __attribute__((noinline))
#include "taint.h"
static int bpf_loop(unsigned n, long (*f)(__u32, void *), void *c, unsigned flags) {
    (void)flags; for (unsigned i=0; i<n; i++) if (f(i,c)) break; return 0;
}
/* Exercise the actual BPF matcher branch with deterministic native helpers. */
#define __BPF__ 1
#define __uint(name,value) int name
#define __type(name,type) type *name
#define SEC(name)
static void *bpf_map_lookup_elem(void *map, const void *key) {
    (void)map; (void)key; static _Alignas(8) unsigned char scratch[512]; return scratch;
}
static int bpf_probe_read_kernel_str(void *dst, unsigned n, const char *src) {
    size_t len=strnlen(src,n-1); memcpy(dst,src,len); ((char *)dst)[len]=0; return len+1;
}
#include "verifier_matchers.h"
static uint32_t rng=0x12345678;
static uint32_t next(void) { rng ^= rng<<13; rng ^= rng>>17; rng ^= rng<<5; return rng; }
int main(void) {
    unsigned mismatches=0, cases=0;
    for (unsigned iteration=0; iteration<200000; iteration++) {
        char text[TAINT_TEXT_BUF]={0}, pat[TAINT_PAT_LEN]={0};
        unsigned tn=next()%(TAINT_PAT_LEN+1), pn=next()%(TAINT_PAT_LEN+1);
        for (unsigned i=0; i<tn; i++) text[i]="ab/.xyz"[next()%7];
        for (unsigned i=0; i<pn; i++) pat[i]="ab/.xyz"[next()%7];
        if (iteration%3==0 && pn<=tn) memcpy(pat,text+tn-pn,pn);
        if (iteration%3==1 && pn<=tn) memcpy(pat,text+next()%(tn-pn+1),pn);
        int a=taint_suffix(text,pat), b=tm_suffix(text,pat);
        mismatches += a!=b; cases++;
        /* Kernel contains rejects literals over TAINT_SUF_MAX. Native strstr
           fallback does not enforce that bound, so state it explicitly. */
        a=pn>0 && pn<=TAINT_SUF_MAX ? taint_contains(text,pat) : 0;
        b=tm_contains(text,pat); mismatches += a!=b; cases++;
    }
    printf("%u,%u\n",cases,mismatches);
    return mismatches ? 1 : 0;
}
''')
    log = out / 'build.log'
    log.write_text('')
    run(['cc', '-O2', '-I.', test, '-o', out / 'matcher_equivalence'], out, log)
    cases, mismatches = run([out / 'matcher_equivalence'], out, log).strip().split(',')
    csv_write(HERE / 'matcher-equivalence.csv', [dict(cases=cases, mismatches=mismatches,
              test_sha256=sha(test.read_bytes()), matcher_sha256=sha((out / 'verifier_matchers.h').read_bytes()))])
    bpftool = ROOT / 'bpf/.output/bpftool/bootstrap/bpftool'
    run([args.clang, '-g', '-O2', '-target', 'bpf', '-D__TARGET_ARCH_x86', '-I.',
         '-I' + str(ROOT / 'bpf/.output'), '-I' + str(ROOT / 'libbpf/include/uapi'),
         '-I' + str(ROOT / 'vmlinux/x86'), '-idirafter', '/usr/include/x86_64-linux-gnu',
         '-c', 'process.bpf.c', '-o', 'process.bpf.o'], out, log)
    skel = run([bpftool, 'gen', 'skeleton', out / 'process.bpf.o'], out, log)
    (out / 'process.skel.h').write_text(skel)
    run(['cc', '-g', '-Wall', '-I.', '-I' + str(ROOT / 'bpf/.output'),
         'process.c', ROOT / 'bpf/.output/libbpf.a', '-lelf', '-lz', '-o', 'process'], out, log)
    metadata = dict(clang=run([args.clang, '--version'], out, log).splitlines()[0],
                    original_engine_sha256=sha((ROOT / 'bpf/taint_engine.bpf.h').read_bytes()),
                    patched_engine_sha256=sha(engine.read_bytes()),
                    bpf_sha256=sha((out / 'process.bpf.o').read_bytes()),
                    loader_sha256=sha((out / 'process').read_bytes()))
    (out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps(metadata, indent=2))


if __name__ == '__main__':
    main()
