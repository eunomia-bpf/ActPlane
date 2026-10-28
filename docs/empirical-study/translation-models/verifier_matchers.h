/* Experiment-only bounded-callback equivalents of the byte matchers.
 * Modern verifier loops in the unmodified suffix/contains byte scans exceed
 * the instruction budget for this corpus. The policy ABI/predicates do not
 * change. build_loader.py checks native equivalence before building BPF.
 */
#ifdef __BPF__
struct tm_length_buf { char data[TAINT_PAT_LEN + 1]; __u64 a[2], b[2]; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tm_length_buf);
} tm_length_scratch SEC(".maps");
static __always_inline int tm_length(const char *text)
{
    __u32 key = 0;
    struct tm_length_buf *b = bpf_map_lookup_elem(&tm_length_scratch, &key);
    if (!b) return 0;
    int n = bpf_probe_read_kernel_str(b->data, sizeof(b->data), text);
    if (n < 1) return 0;
    if (n > TAINT_PAT_LEN + 1) return TAINT_PAT_LEN;
    return n - 1;
}
#else
static inline int tm_length(const char *text) {
    int n=0; while (n<TAINT_PAT_LEN && text[n]) n++; return n;
}
#endif


static __always_inline __u64 tm_mask(int n)
{
    if (n <= 0) return 0;
    if (n >= 8) return ~0ULL;
    return (1ULL << (n * 8)) - 1;
}

static __always_inline int tm_window(const char *text, const char *pat, int n)
{
#ifdef __BPF__
    __u32 key = 0;
    struct tm_length_buf *s = bpf_map_lookup_elem(&tm_length_scratch, &key);
    if (!s) return 0;
    TE_COPY(s->a, sizeof(s->a), text);
    TE_COPY(s->b, sizeof(s->b), pat);
    return (((s->a[0] ^ s->b[0]) & tm_mask(n)) |
            ((s->a[1] ^ s->b[1]) & tm_mask(n - 8))) == 0;
#else
    __u64 a[2] = {}, b[2] = {};
    TE_COPY(a, sizeof(a), text);
    TE_COPY(b, sizeof(b), pat);
    return (((a[0] ^ b[0]) & tm_mask(n)) |
            ((a[1] ^ b[1]) & tm_mask(n - 8))) == 0;
#endif
}

static __always_inline int tm_suffix(const char *text, const char *pat)
{
    int tn = tm_length(text), pn = tm_length(pat);
    if (pn == 0 || pn > tn || pn > TAINT_SUF_MAX) return 0;
    int off = tn - pn;
    if (off < 0) off = 0;
    if (off > TAINT_PAT_LEN - 1) off = TAINT_PAT_LEN - 1;
    return tm_window(text + off, pat, pn);
}

struct tm_contains_ctx {
    const char *text;
    const char *pat;
    int pn, max_pos, found;
};

static long tm_contains_cb(__u32 idx, void *vc)
{
    struct tm_contains_ctx *c = vc;
    if (idx >= TAINT_PAT_LEN) return 1;
    if (c->found || idx > (unsigned int)c->max_pos) return 1;
    if (tm_window(c->text + idx, c->pat, c->pn)) c->found = 1;
    return 0;
}

static __always_inline int tm_contains(const char *text, const char *pat)
{
    int tn = tm_length(text), pn = tm_length(pat);
    if (pn == 0 || pn > tn || pn > TAINT_SUF_MAX) return 0;
    struct tm_contains_ctx c = { .text = text, .pat = pat, .pn = pn,
                                .max_pos = tn - pn };
    bpf_loop(TAINT_PAT_LEN, tm_contains_cb, &c, 0);
    return c.found;
}
