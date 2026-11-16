/* Host tool: generates unittests/firmware/monero_crypto_vectors.h and a record
 * stream for monero_core_verify.cpp (Monero Core v0.18.5.4). Built and run by
 * monero_vectors_gen.sh against the production lib/firmware/monero sources,
 * with replayed RNG draws (monero_test_rng.c). Never part of firmware.
 *
 * Record stream: tag ('B' or 'C'), expect (1 = Core must accept, 0 = Core
 * must reject), then
 *   'B': m, V[m], le16 proof_len, proof (Core layout), gamma[m], le64 v[m]
 *   'C': n, message, P[n], C[n], C_offset, I, D, c1, s[n], p
 * For tampered records gamma/v and p are present but unused. */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keepkey/firmware/monero/crypto.h"
#include "monero_test_rng.h"
#include "trezor/crypto/monero/xmr.h"

#define N_BPP 6
#define N_CLSAG 3
#define RING 16

static const uint64_t BPP_AMOUNTS[N_BPP][2] = {
    {0, 0}, {1, 0}, {UINT64_MAX, 0}, {UINT64_MAX, 1}, {0, 0},
    {1234567890123ULL, 98765ULL}};
static const uint8_t BPP_M[N_BPP] = {1, 1, 1, 2, 2, 2};
static const uint8_t CLSAG_L[N_CLSAG] = {0, 7, 15};

typedef struct {
  uint8_t m;
  uint64_t amounts[2];
  uint8_t gamma[2][32];
  uint8_t seed[32];
  uint8_t V[2][32];
  uint8_t proof[XMR_BPP_SERIALIZED_MAX];
  size_t proof_len;
} bpp_vec;

typedef struct {
  uint8_t l;
  uint8_t msg[32], P[RING][32], C[RING][32], Coff[32], p[32], z[32];
  uint8_t seed[32];
  xmr_clsag_sig sig;
} clsag_vec;

/* tamper ops on the verify buffers (V || proof, or the CLSAG buffer) */
enum { T_XOR = 0, T_SWAP = 1, T_REPLACE = 2 };
typedef struct {
  char kind;
  uint8_t vec, op;
  uint16_t a, b;
  uint8_t x;
  uint8_t data[32];
  const char *what;
} tamper;

static bpp_vec bv[N_BPP];
static clsag_vec cv[N_CLSAG];
static tamper tv[64];
static size_t ntv;
static xmr_bpp_workspace bws __attribute__((aligned(8)));
static xmr_clsag_workspace cws __attribute__((aligned(8)));
static const uint8_t INPUT_SEED[32] = "KeepKey 7.17 Monero vectors v1";

static void scalar(uint8_t out[32], const char *label, uint32_t ctr) {
  uint8_t h[32];
  bignum256modm s;
  xmr_test_stream(h, label, INPUT_SEED, ctr);
  expand256_modm(s, h, 32);
  contract256_modm(out, s);
}

static void point(uint8_t out[32], const char *label, uint32_t ctr) {
  uint8_t k[32];
  bignum256modm s;
  ge25519 P;
  scalar(k, label, ctr);
  expand256_modm(s, k, 32);
  ge25519_scalarmult_base_wrapper(&P, s);
  ge25519_pack(out, &P);
}

static void commit(uint8_t out[32], const uint8_t mask[32], uint64_t v) {
  bignum256modm a;
  ge25519 P;
  expand256_modm(a, mask, 32);
  xmr_gen_c(&P, a, v);
  ge25519_pack(out, &P);
}

static size_t bpp_buf(const bpp_vec *v, uint8_t *b) {
  memcpy(b, v->V, 32u * v->m);
  memcpy(b + 32u * v->m, v->proof, v->proof_len);
  return 32u * v->m + v->proof_len;
}

static size_t clsag_buf(const clsag_vec *v, uint8_t *b) {
  uint8_t *o = b;
  memcpy(o, v->msg, 32), o += 32;
  memcpy(o, v->P, sizeof(v->P)), o += sizeof(v->P);
  memcpy(o, v->C, sizeof(v->C)), o += sizeof(v->C);
  memcpy(o, v->Coff, 32), o += 32;
  memcpy(o, v->sig.I, 32), o += 32;
  memcpy(o, v->sig.D, 32), o += 32;
  memcpy(o, v->sig.c1, 32), o += 32;
  memcpy(o, v->sig.s, sizeof(v->sig.s)), o += sizeof(v->sig.s);
  return (size_t)(o - b);
}

static void apply(const tamper *t, uint8_t *b) {
  uint8_t tmp[32];
  if (t->op == T_XOR) {
    b[t->a] ^= t->x;
  } else if (t->op == T_SWAP) {
    memcpy(tmp, b + t->a, 32);
    memcpy(b + t->a, b + t->b, 32);
    memcpy(b + t->b, tmp, 32);
  } else {
    memcpy(b + t->a, t->data, 32);
  }
}

static void add_t(char kind, uint8_t vec, uint8_t op, uint16_t a, uint16_t b,
                  uint8_t x, const uint8_t *data, const char *what) {
  tamper *t = &tv[ntv++];
  memset(t, 0, sizeof(*t));
  t->kind = kind;
  t->vec = vec;
  t->op = op;
  t->a = a;
  t->b = b;
  t->x = x;
  if (data) memcpy(t->data, data, 32);
  t->what = what;
}

static void w8(FILE *f, uint8_t v) { fputc(v, f); }
static void wb(FILE *f, const void *d, size_t n) { fwrite(d, 1, n, f); }

static void write_bpp(FILE *f, const bpp_vec *v, const uint8_t *buf,
                      int expect) {
  w8(f, 'B');
  w8(f, (uint8_t)expect);
  w8(f, v->m);
  wb(f, buf, 32u * v->m);
  w8(f, (uint8_t)v->proof_len);
  w8(f, (uint8_t)(v->proof_len >> 8));
  wb(f, buf + 32u * v->m, v->proof_len);
  wb(f, v->gamma, 32u * v->m);
  for (unsigned j = 0; j < v->m; j++)
    for (int k = 0; k < 8; k++) w8(f, (uint8_t)(v->amounts[j] >> (8 * k)));
}

static void write_clsag(FILE *f, const clsag_vec *v, const uint8_t *buf,
                        size_t len, int expect) {
  w8(f, 'C');
  w8(f, (uint8_t)expect);
  w8(f, RING);
  wb(f, buf, len);
  wb(f, v->p, 32);
}

static void hexrow(FILE *h, const char *ind, const uint8_t *d, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (i % 12 == 0) fprintf(h, "%s%s", i ? "\n" : "", ind);
    fprintf(h, "0x%02x,%s", d[i], (i % 12 == 11 || i + 1 == n) ? "" : " ");
  }
  fprintf(h, "\n");
}

/* Positional aggregate member: C++14 has no designated initializers. */
static void hexarr(FILE *h, const char *name, const uint8_t *d, size_t n) {
  fprintf(h, "     /* %s */ {\n", name);
  hexrow(h, "         ", d, n);
  fprintf(h, "     },\n");
}

static void hexarr2(FILE *h, const char *name, const uint8_t *d, size_t rows) {
  fprintf(h, "     /* %s */ {\n", name);
  for (size_t r = 0; r < rows; r++) {
    fprintf(h, "      {\n");
    hexrow(h, "         ", d + 32 * r, 32);
    fprintf(h, "      },\n");
  }
  fprintf(h, "     },\n");
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s RECORDS.bin VECTORS.h\n", argv[0]);
    return 2;
  }

  /* BP+ */
  for (int i = 0; i < N_BPP; i++) {
    bpp_vec *v = &bv[i];
    xmr_bpp_proof pr;
    v->m = BPP_M[i];
    v->amounts[0] = BPP_AMOUNTS[i][0];
    v->amounts[1] = BPP_AMOUNTS[i][1];
    for (unsigned j = 0; j < v->m; j++) scalar(v->gamma[j], "bpp-gamma", i * 2 + j);
    xmr_test_stream(v->seed, "bpp-rng-seed", INPUT_SEED, (uint32_t)i);
    xmr_test_rng_replay(v->seed);
    if (!xmr_bpp_prove(&pr, v->amounts, (const uint8_t(*)[32])v->gamma, v->m,
                       &bws, NULL, NULL) ||
        xmr_test_rng_draws() != 1 ||
        !xmr_bpp_serialize(&pr, v->proof, sizeof(v->proof), &v->proof_len)) {
      fprintf(stderr, "bpp vector %d failed\n", i);
      return 1;
    }
    memcpy(v->V, pr.V, sizeof(v->V));
  }

  /* CLSAG */
  for (int i = 0; i < N_CLSAG; i++) {
    clsag_vec *v = &cv[i];
    uint8_t x[32], xo[32];
    bignum256modm a, b, s;
    ge25519 P;
    const uint64_t amount = 2500000000000ULL + (uint64_t)i;
    v->l = CLSAG_L[i];
    for (int r = 0; r < RING; r++) {
      point(v->P[r], "clsag-ring-P", (uint32_t)(i * RING + r));
      point(v->C[r], "clsag-ring-C", (uint32_t)(i * RING + r));
    }
    scalar(v->p, "clsag-p", (uint32_t)i);
    expand256_modm(s, v->p, 32);
    ge25519_scalarmult_base_wrapper(&P, s);
    ge25519_pack(v->P[v->l], &P);
    scalar(x, "clsag-input-mask", (uint32_t)i);
    scalar(xo, "clsag-pseudo-mask", (uint32_t)i);
    commit(v->C[v->l], x, amount);
    commit(v->Coff, xo, amount);
    expand256_modm(a, x, 32);
    expand256_modm(b, xo, 32);
    sub256_modm(s, a, b);
    contract256_modm(v->z, s);
    xmr_test_stream(v->msg, "clsag-message", INPUT_SEED, (uint32_t)i);
    xmr_test_stream(v->seed, "clsag-rng-seed", INPUT_SEED, (uint32_t)i);
    xmr_test_rng_replay(v->seed);
    if (!xmr_clsag_sign(&v->sig, v->msg, (const uint8_t(*)[32])v->P,
                        (const uint8_t(*)[32])v->C, v->Coff, RING, v->l, v->p,
                        v->z, &cws, NULL, NULL) ||
        xmr_test_rng_draws() != 1) {
      fprintf(stderr, "clsag vector %d failed\n", i);
      return 1;
    }
  }

  /* Tampers. BP+ buffer: V[m] || A A1 B r1 s1 d1 | n L[n] | n R[n]. */
  for (uint8_t i = 0; i < N_BPP; i += 3) {
    const bpp_vec *v = &bv[i];
    uint16_t o = (uint16_t)(32u * v->m), nlr = v->m == 1 ? 6 : 7;
    uint16_t L0 = (uint16_t)(o + 193), R0 = (uint16_t)(L0 + 32 * nlr + 1);
    uint8_t vb[32];
    add_t('B', i, T_XOR, o + 96, 0, 0x01, NULL, "r1 bit flip");
    add_t('B', i, T_XOR, o + 128 + 5, 0, 0x10, NULL, "s1 byte flip");
    add_t('B', i, T_XOR, o + 160, 0, 0x01, NULL, "d1 bit flip");
    add_t('B', i, T_XOR, o + 1, 0, 0x01, NULL, "A bit flip");
    add_t('B', i, T_XOR, o + 32 + 2, 0, 0x01, NULL, "A1 bit flip");
    add_t('B', i, T_XOR, o + 64 + 3, 0, 0x01, NULL, "B bit flip");
    add_t('B', i, T_XOR, L0, 0, 0x01, NULL, "L[0] bit flip");
    add_t('B', i, T_XOR, (uint16_t)(R0 + 32 * (nlr - 1)), 0, 0x01, NULL,
          "R[last] bit flip");
    add_t('B', i, T_SWAP, (uint16_t)(L0 + 64), (uint16_t)(L0 + 96), 0, NULL,
          "L[2] and L[3] swapped");
    commit(vb, v->gamma[0], v->amounts[0] + 1);
    {
      /* V = C/8 */
      bignum256modm i8;
      ge25519 P;
      static const uint8_t inv8[32] = {
          0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c,
          0x7d, 0xb3, 0x9d, 0xd3, 0x07, 0,    0,    0,    0,    0,    0,
          0,    0,    0,    0,    0,    0,    0,    0,    0,    0x06};
      expand256_modm(i8, inv8, 32);
      ge25519_unpack_vartime(&P, vb);
      ge25519_scalarmult(&P, &P, i8);
      ge25519_pack(vb, &P);
    }
    add_t('B', i, T_REPLACE, 0, 0, 0, vb, "V[0] commits to amount + 1");
  }
  /* CLSAG buffer: msg | P[16] | C[16] | Coff | I | D | c1 | s[16] */
  for (uint8_t i = 0; i < N_CLSAG; i++) {
    const uint16_t P0 = 32, C0 = 32 + 512, OFF = 32 + 1024, I0 = OFF + 32,
                   D0 = I0 + 32, c10 = D0 + 32, s0 = c10 + 32;
    uint16_t l = cv[i].l, d = (uint16_t)((l + 3) % RING);
    add_t('C', i, T_XOR, (uint16_t)(s0 + 32 * l), 0, 0x01, NULL,
          "s[real] bit flip");
    add_t('C', i, T_XOR, (uint16_t)(s0 + 32 * d), 0, 0x01, NULL,
          "s[decoy] bit flip");
    add_t('C', i, T_XOR, c10, 0, 0x01, NULL, "c1 bit flip");
    add_t('C', i, T_XOR, (uint16_t)(D0 + 4), 0, 0x01, NULL, "D bit flip");
    add_t('C', i, T_XOR, (uint16_t)(I0 + 4), 0, 0x01, NULL, "I bit flip");
    add_t('C', i, T_XOR, 0, 0, 0x01, NULL, "message bit flip");
    add_t('C', i, T_SWAP, P0, P0 + 32, 0, NULL, "P[0] and P[1] swapped");
    add_t('C', i, T_XOR, (uint16_t)(C0 + 32 * l + 7), 0, 0x01, NULL,
          "C[real] bit flip");
    add_t('C', i, T_XOR, (uint16_t)(OFF + 9), 0, 0x01, NULL,
          "C_offset bit flip");
  }

  FILE *f = fopen(argv[1], "wb");
  if (!f) return 1;
  uint8_t buf[2048];
  for (int i = 0; i < N_BPP; i++) {
    bpp_buf(&bv[i], buf);
    write_bpp(f, &bv[i], buf, 1);
  }
  for (int i = 0; i < N_CLSAG; i++) {
    size_t n = clsag_buf(&cv[i], buf);
    write_clsag(f, &cv[i], buf, n, 1);
  }
  for (size_t t = 0; t < ntv; t++) {
    if (tv[t].kind == 'B') {
      bpp_buf(&bv[tv[t].vec], buf);
      apply(&tv[t], buf);
      write_bpp(f, &bv[tv[t].vec], buf, 0);
    } else {
      size_t n = clsag_buf(&cv[tv[t].vec], buf);
      apply(&tv[t], buf);
      write_clsag(f, &cv[tv[t].vec], buf, n, 0);
    }
  }
  fclose(f);

  FILE *h = fopen(argv[2], "w");
  if (!h) return 1;
  fprintf(h,
          "/* GENERATED by unittests/firmware/monero_vectors_gen.sh. Do not "
          "edit.\n"
          " * Every positive vector below was accepted, and every tamper "
          "rejected,\n"
          " * by Monero Core v0.18.5.4 (bulletproof_plus_VERIFY, "
          "verRctCLSAGSimple)\n"
          " * when this file was generated. Outputs are the production prover "
          "and\n"
          " * signer with the replayed RNG of monero_test_rng.c. */\n"
          "#ifndef MONERO_CRYPTO_VECTORS_H\n#define MONERO_CRYPTO_VECTORS_H\n\n"
          "#include <stddef.h>\n#include <stdint.h>\n\n"
          "typedef struct XmrBppVector {\n  uint8_t m;\n  uint64_t amounts[2];\n"
          "  uint8_t gamma[2][32];\n  uint8_t rng_seed[32];\n"
          "  uint8_t V[2][32];\n  uint16_t proof_len;\n"
          "  uint8_t proof[642];\n} XmrBppVector;\n\n"
          "typedef struct XmrClsagVector {\n  uint8_t l;\n  uint8_t message[32];\n"
          "  uint8_t P[16][32];\n  uint8_t C[16][32];\n  uint8_t C_offset[32];\n"
          "  uint8_t p[32];\n  uint8_t z[32];\n  uint8_t rng_seed[32];\n"
          "  uint8_t I[32];\n  uint8_t D[32];\n  uint8_t c1[32];\n"
          "  uint8_t s[16][32];\n} XmrClsagVector;\n\n"
          "/* op 0: buf[a] ^= x; 1: swap 32 B at a and b; 2: 32 B at a = data.\n"
          " * BP+ buf = V[m] || proof; CLSAG buf = message || P[16] || C[16] "
          "||\n"
          " * C_offset || I || D || c1 || s[16]. */\n"
          "typedef struct XmrTamper {\n  char kind;\n  uint8_t vec;\n  uint8_t op;\n"
          "  uint16_t a;\n  uint16_t b;\n  uint8_t x;\n  uint8_t data[32];\n"
          "  const char *what;\n} XmrTamper;\n\n");
  fprintf(h, "static const XmrBppVector kXmrBppVectors[%d] = {\n", N_BPP);
  for (int i = 0; i < N_BPP; i++) {
    const bpp_vec *v = &bv[i];
    fprintf(h, "    {/* m */ %u,\n     /* amounts */ {%" PRIu64 "ULL, %" PRIu64
               "ULL},\n",
            v->m, v->amounts[0], v->amounts[1]);
    hexarr2(h, "gamma", (const uint8_t *)v->gamma, 2);
    hexarr(h, "rng_seed", v->seed, 32);
    hexarr2(h, "V", (const uint8_t *)v->V, 2);
    fprintf(h, "     /* proof_len */ %u,\n", (unsigned)v->proof_len);
    hexarr(h, "proof", v->proof, v->proof_len);
    fprintf(h, "    },\n");
  }
  fprintf(h, "};\n\n");
  fprintf(h, "static const XmrClsagVector kXmrClsagVectors[%d] = {\n",
          N_CLSAG);
  for (int i = 0; i < N_CLSAG; i++) {
    const clsag_vec *v = &cv[i];
    fprintf(h, "    {/* l */ %u,\n", v->l);
    hexarr(h, "message", v->msg, 32);
    hexarr2(h, "P", (const uint8_t *)v->P, RING);
    hexarr2(h, "C", (const uint8_t *)v->C, RING);
    hexarr(h, "C_offset", v->Coff, 32);
    hexarr(h, "p", v->p, 32);
    hexarr(h, "z", v->z, 32);
    hexarr(h, "rng_seed", v->seed, 32);
    hexarr(h, "I", v->sig.I, 32);
    hexarr(h, "D", v->sig.D, 32);
    hexarr(h, "c1", v->sig.c1, 32);
    hexarr2(h, "s", (const uint8_t *)v->sig.s, RING);
    fprintf(h, "    },\n");
  }
  fprintf(h, "};\n\n");
  fprintf(h, "static const XmrTamper kXmrTampers[%u] = {\n", (unsigned)ntv);
  for (size_t t = 0; t < ntv; t++) {
    const tamper *x = &tv[t];
    fprintf(h, "    {'%c', %u, %u, %u, %u, 0x%02x,\n     {", x->kind, x->vec,
            x->op, x->a, x->b, x->x);
    if (x->op == T_REPLACE) {
      fprintf(h, "\n");
      hexrow(h, "         ", x->data, 32);
      fprintf(h, "     ");
    } else {
      fprintf(h, "0");
    }
    fprintf(h, "},\n     \"%s\"},\n", x->what);
  }
  fprintf(h, "};\n\n#endif\n");
  fclose(h);
  printf("bpp=%d clsag=%d tampers=%u\n", N_BPP, N_CLSAG, (unsigned)ntv);
  return 0;
}
