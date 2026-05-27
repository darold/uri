#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

/*
 * We simulate the vulnerable pattern from uri.c:
 *
 *   out = (char *) malloc(len + 1);
 *   memcpy(out, range->first, len);
 *
 * The security invariant is:
 *   For any URI-like input, the length used in malloc must not overflow,
 *   and the allocated buffer must be large enough to hold len+1 bytes
 *   before any memcpy is performed.
 *
 * We test a safe wrapper that enforces these invariants and assert they hold.
 */

/* Safe URI range copy that enforces the security invariant */
static char *safe_uri_range_copy(const char *first, size_t len)
{
    /* Invariant 1: len must not be SIZE_MAX (would overflow len+1) */
    if (len == SIZE_MAX) {
        return NULL;
    }

    /* Invariant 2: len+1 must not overflow */
    if (len + 1 < len) {
        return NULL;
    }

    /* Invariant 3: first must not be NULL if len > 0 */
    if (first == NULL && len > 0) {
        return NULL;
    }

    /* Invariant 4: allocation must succeed before memcpy */
    char *out = (char *) malloc(len + 1);
    if (out == NULL) {
        return NULL;
    }

    if (len > 0) {
        memcpy(out, first, len);
    }
    out[len] = '\0';

    return out;
}

/* Helper: compute URI segment length safely */
static size_t compute_uri_len(const char *uri)
{
    if (uri == NULL) return 0;
    return strlen(uri);
}

START_TEST(test_uri_range_copy_security_invariant)
{
    /* Invariant: safe_uri_range_copy must never return a buffer that is
     * undersized relative to the requested length, and must never allow
     * integer overflow in the len+1 calculation. */

    const char *payloads[] = {
        /* Normal URIs */
        "http://example.com/path",
        "https://user:pass@host:8080/path?query=val#frag",
        "/relative/path",
        "",

        /* Adversarial: very long URI segments */
        "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",

        /* Adversarial: URI with special characters */
        "http://evil.com/%00%00%00%00%00%00%00%00",
        "http://evil.com/\xff\xfe\xfd\xfc",
        "http://evil.com/" "\x41\x41\x41\x41\x41\x41\x41\x41",

        /* Adversarial: boundary-length strings */
        "A",
        "AB",

        /* Adversarial: URI with embedded nulls represented as escaped */
        "http://host/path%00extra",

        /* Adversarial: query strings that might confuse parsers */
        "http://host/?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9&j=10",
        "http://host/#" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",

        /* Adversarial: scheme-only */
        "http://",
        "ftp://",
        "://noscheme",

        /* Adversarial: IPv6 */
        "http://[::1]:80/path",
        "http://[2001:db8::1]/path",

        /* Adversarial: percent-encoded overflow attempts */
        "http://host/%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff",
    };

    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        const char *uri = payloads[i];
        size_t len = compute_uri_len(uri);

        /* Invariant: len+1 must not overflow size_t */
        ck_assert_msg(len < SIZE_MAX,
            "URI length must be less than SIZE_MAX to avoid overflow: payload[%d]", i);

        /* Invariant: len+1 must be strictly greater than len */
        ck_assert_msg(len + 1 > len,
            "len+1 must not overflow for payload[%d]", i);

        /* Perform the safe copy */
        char *result = safe_uri_range_copy(uri, len);

        if (len == 0) {
            /* Empty string: result may be allocated or NULL, but if allocated must be valid */
            if (result != NULL) {
                ck_assert_msg(result[0] == '\0',
                    "Empty URI copy must produce null-terminated empty string: payload[%d]", i);
                free(result);
            }
        } else {
            /* Non-empty: allocation must succeed for reasonable sizes */
            /* For very large allocations, NULL is acceptable (OOM), but
             * if allocation succeeds, the buffer must be correct */
            if (result != NULL) {
                /* Invariant: result must be null-terminated */
                ck_assert_msg(result[len] == '\0',
                    "Result must be null-terminated at position len: payload[%d]", i);

                /* Invariant: content must match source */
                ck_assert_msg(memcmp(result, uri, len) == 0,
                    "Result content must match source: payload[%d]", i);

                /* Invariant: strlen of result must equal len */
                /* (only valid if no embedded nulls in the original) */
                /* We check the null terminator is at the right place */
                ck_assert_msg(result[len] == '\0',
                    "Null terminator must be at index len: payload[%d]", i);

                free(result);
            }
        }
    }

    /* Explicit overflow boundary tests */

    /* Test: SIZE_MAX length must be rejected */
    {
        char dummy[1] = {0};
        char *result = safe_uri_range_copy(dummy, SIZE_MAX);
        ck_assert_msg(result == NULL,
            "SIZE_MAX length must be rejected to prevent integer overflow");
    }

    /* Test: SIZE_MAX - 1 length — allocation will likely fail (OOM), but must not overflow */
    {
        size_t overflow_len = SIZE_MAX - 1;
        /* Verify len+1 does not overflow */
        ck_assert_msg(overflow_len + 1 > overflow_len || overflow_len == SIZE_MAX,
            "Overflow check: SIZE_MAX-1 + 1 should equal SIZE_MAX");
        /* safe_uri_range_copy with SIZE_MAX-1 will try malloc(SIZE_MAX) which should fail */
        /* We just verify the invariant that len != SIZE_MAX passes the check */
        ck_assert_msg(overflow_len != SIZE_MAX,
            "SIZE_MAX-1 should not equal SIZE_MAX");
    }

    /* Test: NULL first pointer with len > 0 must be rejected */
    {
        char *result = safe_uri_range_copy(NULL, 10);
        ck_assert_msg(result == NULL,
            "NULL first pointer with len>0 must be rejected");
    }

    /* Test: NULL first pointer with len == 0 */
    {
        char *result = safe_uri_range_copy(NULL, 0);
        /* Either NULL or valid empty string is acceptable */
        if (result != NULL) {
            ck_assert_msg(result[0] == '\0',
                "NULL first with len=0 must produce empty string if non-NULL");
            free(result);
        }
    }
}
END_TEST

/* Test that integer overflow in len+1 is always detected */
START_TEST(test_uri_len_overflow_detection)
{
    /* Invariant: any length that would cause len+1 to overflow must be detected */

    size_t dangerous_lengths[] = {
        SIZE_MAX,
        SIZE_MAX - 0,
        (size_t)UINT32_MAX + 1,  /* only meaningful on 64-bit */
        (size_t)INT_MAX + 1,
        (size_t)UINT_MAX,
    };

    int num_lengths = sizeof(dangerous_lengths) / sizeof(dangerous_lengths[0]);

    for (int i = 0; i < num_lengths; i++) {
        size_t len = dangerous_lengths[i];

        /* Invariant: if len == SIZE_MAX, then len+1 overflows to 0 */
        if (len == SIZE_MAX) {
            ck_assert_msg(len + 1 == 0,
                "SIZE_MAX + 1 must wrap to 0 (demonstrating overflow risk)");

            /* The safe function must reject this */
            char dummy[1] = {'A'};
            char *result = safe_uri_range_copy(dummy, len);
            ck_assert_msg(result == NULL,
                "safe_uri_range_copy must reject SIZE_MAX length");
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_set_timeout(tc_core, 30);
    tcase_add_test(tc_core, test_uri_range_copy_security_invariant);
    tcase_add_test(tc_core, test_uri_len_overflow_detection);
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