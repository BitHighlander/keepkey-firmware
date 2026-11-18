#ifndef KEEPKEY_FIRMWARE_CONTACT_BOOK_H
#define KEEPKEY_FIRMWARE_CONTACT_BOOK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CONTACT_BOOK_LABEL_MAX 24
#define CONTACT_BOOK_NETWORK_MAX 63
#define CONTACT_BOOK_DESTINATION_MAX 255
#define CONTACT_BOOK_MAX_ENTRIES 16
#define CONTACT_BOOK_MAX_DEPTH 4

/* Destination encodings are shared by every chain. New chains add an adapter,
 * not a new address-book envelope or signature scheme. */
#define CONTACT_BOOK_DEST_EVM_ADDRESS 1
#define CONTACT_BOOK_DEST_UTXO_SCRIPT 2
#define CONTACT_BOOK_DEST_ACCOUNT_BYTES 3
#define CONTACT_BOOK_DEST_ADDRESS_TEXT 4

typedef struct {
  char network[CONTACT_BOOK_NETWORK_MAX + 1]; /* canonical CAIP-2 */
  uint8_t destination_type;
  uint8_t destination_len;
  uint8_t destination[CONTACT_BOOK_DESTINATION_MAX];
  char label[CONTACT_BOOK_LABEL_MAX + 1];
} ContactBookEntry;

typedef struct {
  uint32_t revision;
  uint8_t count;
  uint8_t root[32];
} ContactBookManifest;

/* Parse a device-attestation request, recompute its Merkle root, and expose
 * every entry for mandatory on-device review. */
bool contact_book_parse_request(
    const uint8_t* data, size_t data_len, ContactBookManifest* manifest,
    ContactBookEntry entries[CONTACT_BOOK_MAX_ENTRIES], size_t* signed_len);
void contact_book_manifest_bytes(const ContactBookManifest* manifest,
                                 uint8_t out[46]);

/* Verify a compact inclusion proof signed by this seed's attestor key and
 * retain its contact label for the next supported signing attempt. Status
 * requests and that workflow's continuations keep it; completion, refusal,
 * cancellation, locking or an unrelated operation drops it. */
bool contact_book_process_proof(const uint8_t* data, size_t data_len,
                                const uint8_t expected_pubkey[33]);
bool contact_book_match(const char* network, uint8_t destination_type,
                        const uint8_t* destination, size_t destination_len);
const char* contact_book_label(void);
void contact_book_clear(void);

/* A proof belongs to one signing attempt (including all its continuations),
 * never the next attempt after a refusal or a completed signature. */
void contact_book_begin(void);
bool contact_book_consuming(void);

/* Adds a name page only for an exact network and device-validated destination.
 * Callers must still show their complete raw destination and must propagate a
 * rejected name page as cancellation. It never enables a signing policy. */
#if BITCOIN_ONLY
static inline bool contact_book_confirm_address(const char* network,
                                                const char* address) {
  (void)network;
  (void)address;
  return true;
}
static inline bool contact_book_confirm_coin(const char* coin,
                                             const char* address) {
  (void)coin;
  (void)address;
  return true;
}
#else
bool contact_book_confirm_address(const char* network, const char* address);
bool contact_book_confirm_coin(const char* coin, const char* address);
bool contact_book_confirm_chain(const char* family, const char* chain,
                                const char* address);
bool contact_book_confirm_chain_hash(const char* family, const uint8_t* chain,
                                     size_t chain_size, const char* address);
#endif

#endif
