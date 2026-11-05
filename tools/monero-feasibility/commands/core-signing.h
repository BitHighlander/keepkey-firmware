#ifndef KEEPKEY_MONERO_CORE_SIGNING_H
#define KEEPKEY_MONERO_CORE_SIGNING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MONERO_CORE_MAX_INPUTS 4u
#define MONERO_CORE_MAX_OUTPUTS 4u
#define MONERO_CORE_RING_SIZE 16u
#define MONERO_CORE_MAX_ADDITIONAL_KEYS 16u
#define MONERO_CORE_MAX_TX_BYTES 16384u
#define MONERO_CORE_ERROR_CAPACITY 192u

typedef struct monero_core_ring_member {
  uint64_t global_index;
  uint8_t public_key[32];
  uint8_t commitment[32];
} monero_core_ring_member;

typedef struct monero_core_source {
  uint64_t amount;
  uint32_t real_member;
  uint32_t output_index;
  uint32_t subaddress_major;
  uint32_t subaddress_minor;
  uint8_t tx_public_key[32];
  uint8_t mask[32];
  uint32_t additional_key_count;
  uint8_t additional_tx_public_keys[MONERO_CORE_MAX_ADDITIONAL_KEYS][32];
  monero_core_ring_member ring[MONERO_CORE_RING_SIZE];
} monero_core_source;

typedef struct monero_core_destination {
  uint64_t amount;
  char address[96];
  uint32_t is_change;
  uint32_t change_major;
  uint32_t change_minor;
} monero_core_destination;

typedef struct monero_core_plan {
  uint32_t network;
  uint32_t input_count;
  uint32_t output_count;
  uint64_t fee;
  monero_core_source sources[MONERO_CORE_MAX_INPUTS];
  monero_core_destination destinations[MONERO_CORE_MAX_OUTPUTS];
} monero_core_plan;

typedef struct monero_core_summary {
  uint64_t input_total;
  uint64_t output_total;
  uint64_t fee;
  uint32_t output_count;
  uint8_t plan_hash[32];
  monero_core_destination destinations[MONERO_CORE_MAX_OUTPUTS];
} monero_core_summary;

/* All functions return 1 on success and 0 on failure. Errors are bounded,
 * public diagnostic strings. The key is an Ed25519 SLIP-0010 node private key;
 * it is reduced directly to the Monero spend key inside this native engine.
 * The bridge never returns spend/view secrets or transaction secret keys.
 */
int monero_core_validate(const monero_core_plan *plan,
                         const uint8_t node_private_key[32],
                         monero_core_summary *summary,
                         char error[MONERO_CORE_ERROR_CAPACITY]);
int monero_core_sign(const monero_core_plan *plan,
                     const uint8_t node_private_key[32],
                     uint8_t *transaction, size_t capacity,
                     size_t *transaction_size, uint8_t transaction_hash[32],
                     char error[MONERO_CORE_ERROR_CAPACITY]);
int monero_core_verify(const monero_core_plan *plan,
                       const uint8_t *transaction, size_t transaction_size,
                       char error[MONERO_CORE_ERROR_CAPACITY]);
size_t monero_core_plan_size(void);
size_t monero_core_summary_size(void);

#ifdef __cplusplus
}
#endif
#endif
