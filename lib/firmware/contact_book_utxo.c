#include "keepkey/firmware/contact_book_utxo.h"

#include <string.h>

#include "keepkey/firmware/contact_book.h"
#include "trezor/crypto/address.h"
#include "trezor/crypto/base58.h"
#include "trezor/crypto/bip32.h"
#include "trezor/crypto/cash_addr.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/segwit_addr.h"

/* The CAIP-2 strings KeepKey Desktop and Pioneer send. The Dogecoin and Dash
 * ones are Pioneer's, not the genesis-hash convention: the device compares
 * bytes, and these are the bytes it receives. */
static const struct {
  const char* network;
  const char* coin_name;
} UTXO_NETWORKS[] = {
    {"bip122:000000000019d6689c085ae165831e93", "Bitcoin"},
    {"bip122:000000000933ea01ad0ee984209779ba", "Testnet"},
#if !BITCOIN_ONLY
    {"bip122:12a765e31ffd4059bada1e25190f6e98", "Litecoin"},
    {"bip122:00000000001a91e3dace36e2be3bf030", "Dogecoin"},
    {"bip122:000000000000000000651ef99cb9fcbe", "BitcoinCash"},
    {"bip122:000007d91d1254d60e2dd1ae58038307", "Dash"},
    {"bip122:00040fe8ec8471911baa1db1266ea15d", "Zcash"},
    {"bip122:4da631f2ac1bed857bd968c67c913978", "DigiByte"},
#endif
};

#define UTXO_NETWORK_COUNT (sizeof(UTXO_NETWORKS) / sizeof(UTXO_NETWORKS[0]))

const char* contact_book_utxo_network(const CoinType* coin) {
  if (!coin || !coin->has_coin_name) return NULL;
  for (size_t i = 0; i < UTXO_NETWORK_COUNT; i++) {
    if (strcmp(UTXO_NETWORKS[i].coin_name, coin->coin_name) == 0)
      return UTXO_NETWORKS[i].network;
  }
  return NULL;
}

const CoinType* contact_book_utxo_coin(const char* network) {
  if (!network) return NULL;
  for (size_t i = 0; i < UTXO_NETWORK_COUNT; i++) {
    if (strcmp(UTXO_NETWORKS[i].network, network) == 0)
      return coinByName(UTXO_NETWORKS[i].coin_name);
  }
  return NULL;
}

/* Base58Check of the coin's version bytes and a 20-byte hash. */
static bool render_base58(const CoinType* coin, uint32_t version,
                          const uint8_t hash[20], char* out, size_t out_len) {
  const curve_info* curve = get_curve_by_name(coin->curve_name);
  if (!curve) return false;
  uint8_t raw[4 + 20];
  const size_t prefix_len = address_prefix_bytes_len(version);
  address_write_prefix_bytes(version, raw);
  memcpy(raw + prefix_len, hash, 20);
  const int len = base58_encode_check(raw, (int)(prefix_len + 20),
                                      curve->hasher_base58, out, (int)out_len);
  memzero(raw, sizeof(raw));
  return len > 0;
}

/* CashAddr with its "bitcoincash:" prefix, as the send screen shows it. */
static bool render_cashaddr(const CoinType* coin, uint8_t type,
                            const uint8_t hash[20], char* out) {
  uint8_t raw[21];
  raw[0] = type;
  memcpy(raw + 1, hash, 20);
  return cash_addr_encode(out, coin->cashaddr_prefix, raw, sizeof(raw)) == 1;
}

bool contact_book_utxo_address(const CoinType* coin, const uint8_t* script,
                               size_t script_len, char* out, size_t out_len) {
  if (!coin || !script || !out || out_len < MAX_ADDR_SIZE) return false;
  out[0] = '\0';
  /* OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG */
  if (script_len == 25 && script[0] == 0x76 && script[1] == 0xa9 &&
      script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac) {
    if (coin->has_cashaddr_prefix)
      return render_cashaddr(coin, 0x00, script + 3, out);
    return coin->has_address_type &&
           render_base58(coin, coin->address_type, script + 3, out, out_len);
  }
  /* OP_HASH160 <20> OP_EQUAL */
  if (script_len == 23 && script[0] == 0xa9 && script[1] == 0x14 &&
      script[22] == 0x87) {
    if (coin->has_cashaddr_prefix)
      return render_cashaddr(coin, 0x08, script + 2, out);
    return coin->has_address_type_p2sh &&
           render_base58(coin, coin->address_type_p2sh, script + 2, out,
                         out_len);
  }
  /* v0 <20> (P2WPKH), v0 <32> (P2WSH), v1 <32> (P2TR) */
  const bool v0 = script_len >= 2 && script[0] == 0x00 &&
                  ((script_len == 22 && script[1] == 0x14) ||
                   (script_len == 34 && script[1] == 0x20));
  const bool v1 = script_len == 34 && script[0] == 0x51 && script[1] == 0x20;
  if ((v0 || v1) && coin->has_bech32_prefix)
    return segwit_addr_encode(out, coin->bech32_prefix, v1 ? 1 : 0, script + 2,
                              script_len - 2) == 1;
  return false;
}

bool contact_book_utxo_accept_proof(const CoinType* coin, const uint8_t* proof,
                                    size_t proof_len,
                                    const uint8_t expected_pubkey[33]) {
  const char* network = contact_book_utxo_network(coin);
  if (network &&
      contact_book_process_proof(proof, proof_len, expected_pubkey) &&
      contact_book_holds(network, CONTACT_BOOK_DEST_UTXO_SCRIPT))
    return true;
  contact_book_clear();
  return false;
}

const char* contact_book_utxo_label(const CoinType* coin,
                                    const TxOutputType* output,
                                    const uint8_t* script, size_t script_len,
                                    char* address, size_t address_len) {
  if (!output || output->address_n_count != 0 || !output->has_address ||
      output->script_type == OutputScriptType_PAYTOOPRETURN)
    return NULL;
  const char* network = contact_book_utxo_network(coin);
  if (!network ||
      !contact_book_match(network, CONTACT_BOOK_DEST_UTXO_SCRIPT, script,
                          script_len) ||
      !contact_book_utxo_address(coin, script, script_len, address,
                                 address_len))
    return NULL;
  return contact_book_label();
}
