/* Address derivation for the emulator-only Monero command experiment. */
#include "monero_research.h"

#if !USE_MONERO
#error "Monero research address derivation requires the Monero crypto primitives"
#endif

#include <string.h>
#include "memzero.h"
#include "monero/monero.h"

bool monero_research_path_valid(const uint32_t* path, size_t count) {
  return path && count == 3 && path[0] == (0x80000000u | 44u) &&
         path[1] == (0x80000000u | 128u) && (path[2] & 0x80000000u) != 0;
}

const char* monero_research_network_name(uint32_t network) {
  static const char* const names[] = {"Mainnet", "Testnet", "Stagenet"};
  return network < 3 ? names[network] : NULL;
}

/* Unlike upstream xmr_hash_to_scalar/hasher_Raw, scrub this helper's private
 * hash input/digest context before returning. */
static void monero_research_hash_scalar(bignum256modm scalar,
                                        const uint8_t* input, size_t size) {
  Hasher hasher = {0};
  uint8_t hash[32] = {0};
  hasher_Init(&hasher, HASHER_SHA3K);
  hasher_Update(&hasher, input, size);
  hasher_Final(&hasher, hash);
  expand256_modm(scalar, hash, sizeof(hash));
  memzero(hash, sizeof(hash));
  memzero(&hasher, sizeof(hasher));
}

bool monero_research_get_address(
    const uint8_t node_key[32], uint32_t network, uint32_t major, uint32_t minor,
    char address[MONERO_RESEARCH_ADDRESS_CAPACITY]) {
  struct {
    bignum256modm spend, view, sub;
    uint8_t spend_bytes[32];
    uint8_t subaddr_input[48];
    ge25519 B, A, D, C;
    uint8_t public_keys[64];
  } scratch = {0};
  bool ok = false;
  const bool is_subaddress = major != 0 || minor != 0;
  static const uint8_t base_prefix[] = {18, 53, 24};
  static const uint8_t sub_prefix[] = {42, 63, 36};
  static const uint8_t neutral[32] = {1};

  if (!address) goto cleanup;
  memset(address, 0, MONERO_RESEARCH_ADDRESS_CAPACITY);
  if (!node_key || network >= 3) goto cleanup;

  /* Trezor convention: reduce the SLIP-0010 node key directly. */
  expand256_modm(scratch.spend, node_key, 32);
  if (iszero256_modm(scratch.spend)) goto cleanup;
  contract256_modm(scratch.spend_bytes, scratch.spend);
  monero_research_hash_scalar(scratch.view, scratch.spend_bytes,
                               sizeof(scratch.spend_bytes));
  if (iszero256_modm(scratch.view)) goto cleanup;
  ge25519_scalarmult_base_wrapper(&scratch.B, scratch.spend);
  ge25519_scalarmult_base_wrapper(&scratch.A, scratch.view);

  if (is_subaddress) {
    static const uint8_t domain[8] = {'S','u','b','A','d','d','r',0};
    memcpy(scratch.subaddr_input, domain, sizeof(domain));
    contract256_modm(scratch.subaddr_input + sizeof(domain), scratch.view);
    for (unsigned i = 0; i < 4; ++i) {
      scratch.subaddr_input[40 + i] = (uint8_t)(major >> (8 * i));
      scratch.subaddr_input[44 + i] = (uint8_t)(minor >> (8 * i));
    }
    monero_research_hash_scalar(scratch.sub, scratch.subaddr_input,
                                 sizeof(scratch.subaddr_input));
    ge25519_scalarmult_base_wrapper(&scratch.D, scratch.sub);
    ge25519_add(&scratch.D, &scratch.D, &scratch.B, 0);
    ge25519_scalarmult(&scratch.C, &scratch.D, scratch.view);
  } else {
    ge25519_copy(&scratch.D, &scratch.B);
    ge25519_copy(&scratch.C, &scratch.A);
  }
  ge25519_pack(scratch.public_keys, &scratch.D);
  ge25519_pack(scratch.public_keys + 32, &scratch.C);
  if (!memcmp(scratch.public_keys, neutral, 32) ||
      !memcmp(scratch.public_keys + 32, neutral, 32)) goto cleanup;
  const uint8_t prefix = is_subaddress ? sub_prefix[network] : base_prefix[network];
  int written = xmr_base58_addr_encode_check(prefix, scratch.public_keys,
      sizeof(scratch.public_keys), address, MONERO_RESEARCH_ADDRESS_CAPACITY);
  if (written != (int)MONERO_RESEARCH_ADDRESS_LENGTH) goto cleanup;
  address[MONERO_RESEARCH_ADDRESS_LENGTH] = '\0';
  ok = true;

cleanup:
  memzero(&scratch, sizeof(scratch));
  if (!ok && address) memzero(address, MONERO_RESEARCH_ADDRESS_CAPACITY);
  return ok;
}
