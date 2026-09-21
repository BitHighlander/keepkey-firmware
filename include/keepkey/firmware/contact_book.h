#ifndef KEEPKEY_FIRMWARE_CONTACT_BOOK_H
#define KEEPKEY_FIRMWARE_CONTACT_BOOK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CONTACT_BOOK_LABEL_MAX 24
#define CONTACT_BOOK_MAX_ENTRIES 16
#define CONTACT_BOOK_MAX_DEPTH 4

typedef struct {
  uint32_t chain_id;
  uint8_t address[20];
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
 * retain its contact label for exactly one subsequent EVM signing request. */
bool contact_book_process_proof(const uint8_t* data, size_t data_len,
                                const uint8_t expected_pubkey[33]);
bool contact_book_match(uint32_t chain_id, const uint8_t address[20]);
const char* contact_book_label(void);
void contact_book_clear(void);

#endif
