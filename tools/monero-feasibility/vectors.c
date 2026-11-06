/* Research executable: public test vectors only; never device wallet secrets. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "monero/monero.h"

static unsigned assertions;
#define ck_assert(x) do { \
  ++assertions; \
  if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } \
} while (0)
#define ck_assert_int_eq(a, b) ck_assert((a) == (b))
#define ck_assert_uint_eq(a, b) ck_assert((a) == (b))
#define ck_assert_mem_eq(a, b, n) ck_assert(memcmp((a), (b), (n)) == 0)
#define START_TEST(name) static void name(void)
#define END_TEST

/* Rotating buffers preserve separate fromhex arguments in one expression. */
static const unsigned char *fromhex(const char *s) {
  static unsigned char buffers[8][512];
  static unsigned slot;
  unsigned char *out = buffers[(slot++) % 8];
  size_t n = strlen(s);
  ck_assert(n % 2 == 0 && n / 2 <= sizeof(buffers[0]));
  for (size_t i = 0; i < n / 2; ++i) {
    unsigned v;
    ck_assert(sscanf(s + 2 * i, "%2x", &v) == 1);
    out[i] = (unsigned char)v;
  }
  return out;
}

/* Generated from this checkout's unmodified upstream vector header. */
#include "selected_vectors.h"

/* Any unexpected RNG dependency fails: the experiment is deterministic. */
void random_buffer(uint8_t *out, size_t len) {
  (void)out; (void)len;
  fputs("Unexpected RNG request in deterministic experiment\n", stderr);
  abort();
}

static double bench(void (*fn)(void), unsigned count) {
  clock_t start = clock();
  for (unsigned i = 0; i < count; ++i) fn();
  return 1000000.0 * (double)(clock() - start) / CLOCKS_PER_SEC / count;
}

int main(void) {
  run_selected_vectors();
  unsigned checks = assertions;
  double derivation = bench(test_xmr_generate_key_derivation, 100);
  double hash_to_ec = bench(test_xmr_hash_to_ec, 100);
  double commitment = bench(test_xmr_gen_c, 100);
  /* Observe a caller hazard separately from the known-answer suite. */
  uint8_t short_buffer[1] = {0};
  int truncated = xmr_write_varint(short_buffer, sizeof(short_buffer), 128);
  printf("{\"vector_groups\":%u,\"assertions_including_hex_decode\":%u,"
         "\"host_us_per_vector_group\":{\"key_derivation\":%.3f,"
         "\"hash_to_ec\":%.3f,\"commitment\":%.3f},"
         "\"short_varint_return\":%d,\"short_varint_byte\":%u}\n",
         SELECTED_VECTOR_GROUPS, checks, derivation, hash_to_ec, commitment,
         truncated, short_buffer[0]);
  return 0;
}
