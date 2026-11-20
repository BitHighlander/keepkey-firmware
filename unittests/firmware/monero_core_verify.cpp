// Host tool: checks monero_vectors_gen's record stream with unmodified Monero
// Core v0.18.5.4. Every record carries the verdict Core must reach: positive
// vectors must verify (and their commitments and key images must match Core's
// own derivation), tampered copies must be rejected. Exit 0 only if every
// record agrees. Built by monero_vectors_gen.sh; never part of firmware.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto/crypto.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "serialization/binary_utils.h"

template <class F>
static bool TRY(F f) {
  try {
    return f();
  } catch (const std::exception &) {
    return false;
  }
}

static int verify_records(std::istream &input) {
  auto read = [&](void *out, size_t count) {
    if (!input.read(static_cast<char *>(out), count))
      throw std::runtime_error("incomplete or unreadable record");
  };
  auto key = [&]() {
    rct::key value;
    read(value.bytes, sizeof(value.bytes));
    return value;
  };
  auto byte = [&]() {
    unsigned char value;
    read(&value, 1);
    return value;
  };

  size_t records = 0, accepted = 0, rejected = 0, disagree = 0;
  while (input.peek() != std::char_traits<char>::eof()) {
    unsigned tag = byte(), expect = byte();
    bool ok = false, extra = true;
    records++;
    if (tag == 'B') {
      unsigned m = byte();
      std::vector<rct::key> V;
      for (unsigned j = 0; j < m; j++) V.push_back(key());
      size_t len = byte();
      len |= (size_t)byte() << 8;
      std::string blob(len, '\0');
      if (len) read(&blob[0], len);
      rct::BulletproofPlus p;
      bool parsed = ::serialization::parse_binary(blob, p);
      if (parsed) {
        p.V = V;
        ok = TRY([&] { return rct::bulletproof_plus_VERIFY(p); });
      }
      // Commitment binding: 8 V[j] == gamma_j G + v_j H (positive only).
      std::vector<rct::key> gamma;
      for (unsigned j = 0; j < m; j++) gamma.push_back(key());
      for (unsigned j = 0; j < m; j++) {
        uint64_t v = 0;
        for (int b = 0; b < 8; b++) v |= (uint64_t)byte() << (8 * b);
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
      unsigned n = byte();
      rct::key msg = key();
      rct::ctkeyV pubs(n);
      for (unsigned i = 0; i < n; i++) pubs[i].dest = key();
      for (unsigned i = 0; i < n; i++) pubs[i].mask = key();
      rct::key Coff = key();
      rct::clsag s;
      s.I = key();
      s.D = key();
      s.c1 = key();
      for (unsigned i = 0; i < n; i++) s.s.push_back(key());
      rct::key p = key();
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
  if (input.bad() || !input.eof() || records == 0)
    throw std::runtime_error("empty or unreadable record stream");
  printf("records=%zu accepted=%zu rejected=%zu disagreements=%zu\n", records,
         accepted, rejected, disagree);
  return disagree ? 1 : 0;
}

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  std::ifstream input(argv[1], std::ios::binary);
  if (!input) {
    fprintf(stderr, "could not open %s\n", argv[1]);
    return 2;
  }
  try {
    return verify_records(input);
  } catch (const std::exception &error) {
    fprintf(stderr, "%s: %s\n", argv[1], error.what());
    return 2;
  }
}
