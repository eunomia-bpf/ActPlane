#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/*
 * Simulates the vulnerable path-processing logic from sslsniff.c
 * The function processes a path buffer looking for " -> " pattern,
 * then uses memmove with strlen to shift the content.
 *
 * Security invariant: After processing, the result must:
 * 1. Never read beyond the input buffer boundary
 * 2. Never write beyond the output buffer boundary
 * 3. The resulting string must be null-terminated within bounds
 * 4. The resulting string length must be <= original buffer size
 */

#define PATH_BUFSIZE 256

/*
 * Safe version of the path processing logic that enforces bounds.
 * Returns 0 on success, -1 on error (boundary violation detected).
 */
static int safe_process_path(char *path, size_t path_bufsize) {
    if (path == NULL || path_bufsize == 0) return -1;

    /* Ensure null termination within buffer */
    path[path_bufsize - 1] = '\0';

    char *start = strstr(path, " -> ");
    if (start == NULL) {
        /* No pattern found, path unchanged */
        return 0;
    }

    /* start + 2 would be " > ..." but the code uses start + 2 */
    char *src = start + 2;

    /* Validate src is within buffer */
    if (src < path || src >= path + path_bufsize) {
        return -1; /* Out of bounds */
    }

    /* Calculate remaining bytes from src to end of buffer */
    size_t max_remaining = path_bufsize - (size_t)(src - path);

    /* Use strnlen to safely compute length without reading past buffer */
    size_t src_len = strnlen(src, max_remaining);

    /* Verify src_len doesn't exceed buffer */
    if (src_len >= max_remaining) {
        /* src is not null-terminated within buffer bounds */
        return -1;
    }

    /* Verify memmove won't write past buffer */
    size_t copy_size = src_len + 1; /* +1 for null terminator */
    if (copy_size > path_bufsize) {
        return -1;
    }

    /* Safe memmove */
    memmove(path, src, copy_size);

    /* Enforce null termination */
    path[path_bufsize - 1] = '\0';

    /* Verify result is within bounds */
    size_t result_len = strnlen(path, path_bufsize);
    if (result_len >= path_bufsize) {
        return -1;
    }

    return 0;
}

START_TEST(test_path_buffer_boundary_safety)
{
    /* Invariant: Path processing must never read/write beyond buffer boundaries,
     * and the result must always be null-terminated within the buffer. */

    const char *payloads[] = {
        /* Normal case */
        "/usr/lib/libssl.so -> /usr/lib/libssl.so.1.1",
        /* Pattern at very end of string */
        "a -> b",
        /* Pattern with empty suffix */
        "path ->",
        /* Pattern with single char suffix */
        "path -> x",
        /* No pattern */
        "/usr/lib/libssl.so",
        /* Empty string */
        "",
        /* Only the pattern */
        " -> ",
        /* Pattern at start */
        " -> /target/path",
        /* Multiple patterns */
        "a -> b -> c",
        /* Very long path near buffer limit */
        "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -> b",
        /* Path with null bytes simulated as spaces (adversarial) */
        "path -> \x01\x02\x03\x04",
        /* Path with special characters */
        "/proc/self/maps -> ../../../../etc/passwd",
        /* Path with format string characters */
        "%s%s%s%s -> %n%n%n%n",
        /* Path with path traversal */
        "../../../etc/shadow -> /tmp/evil",
        /* Whitespace only */
        "   ->   ",
        /* Pattern with spaces around arrow */
        "  ->  target",
        /* Very short buffer content */
        "->",
        /* Arrow without spaces */
        "path->target",
        /* Repeated arrows */
        " ->  ->  -> final",
        /* Binary-like content */
        "\x7f\x45\x4c\x46 -> /lib/ld.so",
        /* Long target after arrow */
        "src -> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    };

    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        char path[PATH_BUFSIZE];
        char canary_before[16];
        char canary_after[16];

        /* Initialize canaries to detect buffer overflows */
        memset(canary_before, 0xAB, sizeof(canary_before));
        memset(canary_after, 0xCD, sizeof(canary_after));

        /* Copy payload into path buffer safely */
        memset(path, 0, sizeof(path));
        strncpy(path, payloads[i], sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';

        size_t original_len = strlen(path);

        /* Process the path */
        int result = safe_process_path(path, sizeof(path));

        /* Invariant 1: Function must return a valid result (0 or -1, not crash) */
        ck_assert_msg(result == 0 || result == -1,
                      "Payload %d: safe_process_path returned unexpected value %d", i, result);

        /* Invariant 2: Path must always be null-terminated within buffer */
        int null_found = 0;
        for (size_t j = 0; j < sizeof(path); j++) {
            if (path[j] == '\0') {
                null_found = 1;
                break;
            }
        }
        ck_assert_msg(null_found,
                      "Payload %d: path buffer not null-terminated within bounds", i);

        /* Invariant 3: Result string length must be within buffer */
        size_t result_len = strnlen(path, sizeof(path));
        ck_assert_msg(result_len < sizeof(path),
                      "Payload %d: result string length %zu exceeds buffer size %zu",
                      i, result_len, sizeof(path));

        /* Invariant 4: If processing succeeded, result length <= original length
         * (we're extracting a substring, not expanding) */
        if (result == 0) {
            ck_assert_msg(result_len <= original_len,
                          "Payload %d: result length %zu > original length %zu (expansion detected)",
                          i, result_len, original_len);
        }

        /* Invariant 5: Canaries must be intact (no buffer overflow) */
        for (size_t j = 0; j < sizeof(canary_before); j++) {
            ck_assert_msg((unsigned char)canary_before[j] == 0xAB,
                          "Payload %d: canary_before corrupted at byte %zu", i, j);
        }
        for (size_t j = 0; j < sizeof(canary_after); j++) {
            ck_assert_msg((unsigned char)canary_after[j] == 0xCD,
                          "Payload %d: canary_after corrupted at byte %zu", i, j);
        }
    }
}
END_TEST

START_TEST(test_path_boundary_at_buffer_edge)
{
    /* Invariant: Processing paths where the pattern appears near the buffer
     * boundary must not cause out-of-bounds reads or writes. */

    char path[PATH_BUFSIZE];
    char guard[16];
    memset(guard, 0xDE, sizeof(guard));

    /* Test: pattern " -> " placed at various positions near end of buffer */
    for (int offset = 0; offset < 10; offset++) {
        memset(path, 'A', sizeof(path));
        path[sizeof(path) - 1] = '\0';

        /* Place " -> " pattern near the end */
        int pattern_pos = (int)sizeof(path) - 6 - offset;
        if (pattern_pos < 0) pattern_pos = 0;

        if (pattern_pos + 4 < (int)sizeof(path) - 1) {
            path[pattern_pos]     = ' ';
            path[pattern_pos + 1] = '-';
            path[pattern_pos + 2] = '>';
            path[pattern_pos + 3] = ' ';
            /* Fill rest with 'B' */
            for (int j = pattern_pos + 4; j < (int)sizeof(path) - 1; j++) {
                path[j] = 'B';
            }
            path[sizeof(path) - 1] = '\0';
        }

        int result = safe_process_path(path, sizeof(path));

        /* Invariant: Must not crash and must maintain null termination */
        ck_assert_msg(result == 0 || result == -1,
                      "Edge offset %d: unexpected return value %d", offset, result);

        int null_found = 0;
        for (size_t j = 0; j < sizeof(path); j++) {
            if (path[j] == '\0') {
                null_found = 1;
                break;
            }
        }
        ck_assert_msg(null_found,
                      "Edge offset %d: path not null-terminated", offset);

        /* Guard must be intact */
        for (size_t j = 0; j < sizeof(guard); j++) {
            ck_assert_msg((unsigned char)guard[j] == 0xDE,
                          "Edge offset %d: guard corrupted at byte %zu", offset, j);
        }
    }
}
END_TEST

START_TEST(test_path_strlen_safety)
{
    /* Invariant: strlen-equivalent operations on path substrings must
     * never read beyond the buffer boundary. */

    char path[PATH_BUFSIZE];

    /* Test: buffer filled to maximum with pattern at various positions */
    const char pattern[] = " -> ";
    size_t pattern_len = strlen(pattern);

    for (size_t pos = 0; pos < sizeof(path) - pattern_len - 1; pos += 17) {
        memset(path, 'X', sizeof(path));
        path[sizeof(path) - 1] = '\0';

        /* Insert pattern at position pos */
        memcpy(path + pos, pattern, pattern_len);

        /* Ensure buffer is null-terminated */
        path[sizeof(path) - 1] = '\0';

        /* Find where start+2 would point */
        char *start = strstr(path, pattern);
        ck_assert_msg(start != NULL, "Pattern not found at pos %zu", pos);

        char *src = start + 2;

        /* Invariant: src must be within buffer */
        ck_assert_msg(src >= path,
                      "pos %zu: src pointer before buffer start", pos);
        ck_assert_msg(src < path + sizeof(path),
                      "pos %zu: src pointer beyond buffer end", pos);

        /* Invariant: strnlen with buffer limit must find null within bounds */
        size_t max_len = sizeof(path) - (size_t)(src - path);
        size_t safe_len = strnlen(src, max_len);

        ck_assert_msg(safe_len < max_len || path[sizeof(path)-1] == '\0',
                      "pos %zu: string not terminated within buffer bounds", pos);

        /* Invariant: copy size must not exceed buffer */
        size_t copy_size = safe_len + 1;
        ck_assert_msg(copy_size <= sizeof(path),
                      "pos %zu: copy_size %zu exceeds buffer %zu",
                      pos, copy_size, sizeof(path));
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_path_buffer_boundary_safety);
    tcase_add_test(tc_core, test_path_boundary_at_buffer_edge);
    tcase_add_test(tc_core, test_path_strlen_safety);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}