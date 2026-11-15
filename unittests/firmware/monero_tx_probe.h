#ifndef MONERO_TX_PROBE_H
#define MONERO_TX_PROBE_H

/* C-side helpers for monero_tx.cpp, built with the trezor-crypto Monero
 * primitives (USE_MONERO=1): they play the other wallets and the chain, so
 * the test can hand the signer real, spendable inputs. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint8_t tx_pub[32];     /* R of the transaction that paid the wallet */
  uint8_t additional[32]; /* its additional key at this output's index */
  uint8_t out_key[32];    /* one-time key P */
  uint8_t commitment[32]; /* mask*G + amount*H */
  uint8_t mask[32];
  uint8_t secret[32]; /* x with x*G == P; for the Core key-image check */
} MoneroTxProbeOwned;

/* A deterministic canonical scalar / prime-order point. */
void monero_tx_probe_scalar(uint8_t out[32], const char* label, uint32_t ctr);
void monero_tx_probe_point(uint8_t out[32], const char* label, uint32_t ctr);

/* Spend and view public keys of subaddress (major, minor) of the wallet
 * with these secrets; (0, 0) is the primary address. */
void monero_tx_probe_address_keys(const uint8_t spend[32],
                                  const uint8_t view[32], uint32_t major,
                                  uint32_t minor, uint8_t keys[64]);

/* Pays `amount` to (major, minor) of the wallet as output `index` of a
 * transaction, as Core would: R = r*G, or r*D for a subaddress. With
 * via_additional the output hangs off an additional key and R is unrelated. */
void monero_tx_probe_owned(const uint8_t spend[32], const uint8_t view[32],
                           uint32_t major, uint32_t minor, uint32_t index,
                           uint64_t amount, bool via_additional,
                           const char* label, uint32_t ctr,
                           MoneroTxProbeOwned* out);

/* Opens a sealed CLSAG with the key TxFinal released. */
bool monero_tx_probe_open(const uint8_t key[32], uint32_t position,
                          const uint8_t* sealed, size_t size, uint8_t* plain);

/* base58 address -> prefix tag and payload. */
bool monero_tx_probe_decode_address(const char* address, uint64_t* tag,
                                    uint8_t* data, size_t* size);

/* A small-order point, a point with a torsion component, and an encoding
 * whose y is not reduced. */
void monero_tx_probe_bad_points(uint8_t small_order[32], uint8_t torsioned[32],
                                uint8_t noncanonical[32]);

#ifdef __cplusplus
}
#endif

#endif
