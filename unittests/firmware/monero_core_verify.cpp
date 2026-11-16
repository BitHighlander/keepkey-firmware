// Host tool: checks monero_vectors_gen's record stream with unmodified Monero
// Core v0.18.5.4. Every record carries the verdict Core must reach: positive
// vectors must verify (and their commitments and key images must match Core's
// own derivation), tampered copies must be rejected. Exit 0 only if every
// record agrees. Built by monero_vectors_gen.sh; never part of firmware.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto/crypto.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "serialization/binary_utils.h"

static std::vector<unsigned char> buf;
static size_t pos = 0;

static rct::key K() {
  rct::key k;
  memcpy(k.bytes, &buf.at(pos), 32);
  pos += 32;
  return k;
}
static unsigned U8() { return buf.at(pos++); }

template <class F>
static bool TRY(F f) {
  try {
    return f();
  } catch (const std::exception &) {
    return false;
  }
}

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  std::ifstream f(argv[1], std::ios::binary);
  buf.assign(std::istreambuf_iterator<char>(f), {});
  int records = 0, accepted = 0, rejected = 0, disagree = 0;
  while (pos < buf.size()) {
    unsigned tag = U8(), expect = U8();
    bool ok = false, extra = true;
    records++;
    if (tag == 'B') {
      unsigned m = U8();
      std::vector<rct::key> V;
      for (unsigned j = 0; j < m; j++) V.push_back(K());
      size_t len = U8();
      len |= (size_t)U8() << 8;
      std::string blob((const char *)&buf.at(pos), len);
      pos += len;
      rct::BulletproofPlus p;
      bool parsed = ::serialization::parse_binary(blob, p);
      if (parsed) {
        p.V = V;
        ok = TRY([&] { return rct::bulletproof_plus_VERIFY(p); });
      }
      // Commitment binding: 8 V[j] == gamma_j G + v_j H (positive only).
      std::vector<rct::key> gamma;
      for (unsigned j = 0; j < m; j++) gamma.push_back(K());
      for (unsigned j = 0; j < m; j++) {
        uint64_t v = 0;
        for (int b = 0; b < 8; b++) v |= (uint64_t)U8() << (8 * b);
        if (expect) {
          rct::key C;
          rct::addKeys2(C, gamma[j], rct::d2h(v), rct::H);
          extra = extra && rct::scalarmult8(V[j]) == C;
        }
      }
      printf("BP+ m=%u len=%zu parsed=%d core=%s%s\n", m, len, parsed,
             ok ? "accept" : "reject",
             expect && !extra ? " COMMITMENT-MISMATCH" : "");
    } else if (tag == 'C') {
      unsigned n = U8();
      rct::key msg = K();
      rct::ctkeyV pubs(n);
      for (unsigned i = 0; i < n; i++) pubs[i].dest = K();
      for (unsigned i = 0; i < n; i++) pubs[i].mask = K();
      rct::key Coff = K();
      rct::clsag s;
      s.I = K();
      s.D = K();
      s.c1 = K();
      for (unsigned i = 0; i < n; i++) s.s.push_back(K());
      rct::key p = K();
      ok = TRY([&] { return rct::verRctCLSAGSimple(msg, s, pubs, Coff); });
      // Key image must be Core's own: I = p * Hp(p G).
      if (expect) {
        crypto::public_key pub;
        crypto::secret_key sec;
        crypto::key_image ki;
        memcpy((void *)&sec, p.bytes, 32);
        extra = crypto::secret_key_to_public_key(sec, pub);
        crypto::generate_key_image(pub, sec, ki);
        extra = extra && memcmp(&ki, s.I.bytes, 32) == 0;
      }
      printf("CLSAG n=%u core=%s%s\n", n, ok ? "accept" : "reject",
             expect && !extra ? " KEY-IMAGE-MISMATCH" : "");
    } else {
      printf("bad tag %u\n", tag);
      return 2;
    }
    (ok ? accepted : rejected)++;
    if (ok != (expect != 0) || !extra) {
      disagree++;
      printf("  ^ expected %s\n", expect ? "accept" : "reject");
    }
  }
  printf("records=%d accepted=%d rejected=%d disagreements=%d\n", records,
         accepted, rejected, disagree);
  return disagree ? 1 : 0;
}
