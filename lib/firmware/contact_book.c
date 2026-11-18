#include "keepkey/firmware/contact_book.h"

#include <string.h>
#include <stdio.h>

#include "keepkey/board/confirm_sm.h"

#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"

#define REQUEST_MAGIC "KKABREQ1"
#define ROOT_MAGIC "KKABRT01"
#define PROOF_MAGIC "KKABPRF1"
#define CONTACT_BOOK_VERSION 1

static bool proof_available;
static bool proof_consuming;
static ContactBookEntry proof_entry;

static bool address_text_valid(const uint8_t* address, size_t len) {
  if (!address || !len || len > CONTACT_BOOK_DESTINATION_MAX) return false;
  for (size_t i = 0; i < len; i++)
    if (address[i] < 0x21 || address[i] > 0x7e) return false;
  return true;
}

static uint32_t read_be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}

static void write_be32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static bool label_valid(const uint8_t* label, size_t len) {
  if (len == 0 || len > CONTACT_BOOK_LABEL_MAX) return false;
  /* "Alice" and "Alice " must not be two contacts, nor a label be blank. */
  if (label[0] == ' ' || label[len - 1] == ' ') return false;
  for (size_t i = 0; i < len; i++) {
    /* Alpha format is deliberately ASCII-only: no controls, bidi overrides,
     * invisible Unicode, or display-confusable normalization. */
    if (label[i] < 0x20 || label[i] > 0x7e || label[i] == '%') return false;
    /* Padding could push text onto another line of the review. */
    if (i && label[i] == ' ' && label[i - 1] == ' ') return false;
  }
  return true;
}

static bool network_valid(const uint8_t* network, size_t len) {
  if (len == 0 || len > CONTACT_BOOK_NETWORK_MAX) return false;
  bool colon = false;
  for (size_t i = 0; i < len; i++) {
    if (network[i] == ':') colon = true;
    if (!((network[i] >= 'a' && network[i] <= 'z') ||
          (network[i] >= 'A' && network[i] <= 'Z') ||
          (network[i] >= '0' && network[i] <= '9') || network[i] == ':' ||
          network[i] == '-'))
      return false;
  }
  return colon;
}

static void leaf_hash(const ContactBookEntry* entry, uint8_t out[32]) {
  SHA256_CTX ctx;
  uint8_t network_len = (uint8_t)strlen(entry->network);
  uint8_t label_len = (uint8_t)strlen(entry->label);
  sha256_Init(&ctx);
  sha256_Update(&ctx, (const uint8_t*)"KKABLEAF", 8);
  sha256_Update(&ctx, &network_len, 1);
  sha256_Update(&ctx, (const uint8_t*)entry->network, network_len);
  sha256_Update(&ctx, &entry->destination_type, 1);
  sha256_Update(&ctx, &entry->destination_len, 1);
  sha256_Update(&ctx, entry->destination, entry->destination_len);
  sha256_Update(&ctx, &label_len, 1);
  sha256_Update(&ctx, (const uint8_t*)entry->label, label_len);
  sha256_Final(&ctx, out);
}

static void pair_hash(const uint8_t left[32], const uint8_t right[32],
                      uint8_t out[32]) {
  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, left, 32);
  sha256_Update(&ctx, right, 32);
  sha256_Final(&ctx, out);
}

static uint8_t tree_depth(uint8_t count) {
  uint8_t depth = 0, width = 1;
  while (width < count) {
    width <<= 1;
    depth++;
  }
  return depth;
}

static void merkle_root(const ContactBookEntry* entries, uint8_t count,
                        uint8_t out[32]) {
  uint8_t nodes[CONTACT_BOOK_MAX_ENTRIES][32];
  uint8_t width = 1;
  while (width < count) width <<= 1;
  for (uint8_t i = 0; i < count; i++) leaf_hash(&entries[i], nodes[i]);
  for (uint8_t i = count; i < width; i++)
    memcpy(nodes[i], nodes[count - 1], 32);
  while (width > 1) {
    for (uint8_t i = 0; i < width; i += 2)
      pair_hash(nodes[i], nodes[i + 1], nodes[i / 2]);
    width >>= 1;
  }
  memcpy(out, nodes[0], 32);
  memzero(nodes, sizeof(nodes));
}

bool contact_book_parse_request(
    const uint8_t* data, size_t data_len, ContactBookManifest* manifest,
    ContactBookEntry entries[CONTACT_BOOK_MAX_ENTRIES], size_t* signed_len) {
  if (!data || !manifest || !entries || data_len < 14 ||
      memcmp(data, REQUEST_MAGIC, 8) != 0 || data[8] != CONTACT_BOOK_VERSION)
    return false;
  size_t off = 9;
  manifest->revision = read_be32(data + off);
  off += 4;
  manifest->count = data[off++];
  if (manifest->revision == 0 || manifest->count == 0 ||
      manifest->count > CONTACT_BOOK_MAX_ENTRIES)
    return false;
  memset(entries, 0, sizeof(ContactBookEntry) * CONTACT_BOOK_MAX_ENTRIES);
  for (uint8_t i = 0; i < manifest->count; i++) {
    if (off + 5 > data_len) return false;
    uint8_t network_len = data[off++];
    if (off + network_len + 3 > data_len ||
        !network_valid(data + off, network_len))
      return false;
    memcpy(entries[i].network, data + off, network_len);
    off += network_len;
    entries[i].destination_type = data[off++];
    entries[i].destination_len = data[off++];
    if (entries[i].destination_type == 0 || entries[i].destination_len == 0 ||
        off + entries[i].destination_len + 1 > data_len)
      return false;
    memcpy(entries[i].destination, data + off, entries[i].destination_len);
    if (entries[i].destination_type == CONTACT_BOOK_DEST_ADDRESS_TEXT &&
        !address_text_valid(entries[i].destination, entries[i].destination_len))
      return false;
    off += entries[i].destination_len;
    uint8_t len = data[off++];
    if (off + len > data_len || !label_valid(data + off, len)) return false;
    memcpy(entries[i].label, data + off, len);
    entries[i].label[len] = '\0';
    off += len;
    /* One name per address and one address per name on a network: otherwise
     * the host chooses which of two certified answers the device shows. */
    for (uint8_t j = 0; j < i; j++) {
      if (strcmp(entries[j].network, entries[i].network) != 0) continue;
      if (strcmp(entries[j].label, entries[i].label) == 0 ||
          (entries[j].destination_type == entries[i].destination_type &&
           entries[j].destination_len == entries[i].destination_len &&
           memcmp(entries[j].destination, entries[i].destination,
                  entries[i].destination_len) == 0))
        return false;
    }
  }
  if (off != data_len) return false;
  merkle_root(entries, manifest->count, manifest->root);
  if (signed_len) *signed_len = off;
  return true;
}

void contact_book_manifest_bytes(const ContactBookManifest* manifest,
                                 uint8_t out[46]) {
  memcpy(out, ROOT_MAGIC, 8);
  out[8] = CONTACT_BOOK_VERSION;
  write_be32(out + 9, manifest->revision);
  out[13] = manifest->count;
  memcpy(out + 14, manifest->root, 32);
}

bool contact_book_process_proof(const uint8_t* data, size_t data_len,
                                const uint8_t expected_pubkey[33]) {
  contact_book_clear();
  /* magic + manifest + pubkey + sig + entry + index/depth */
  if (!data || !expected_pubkey || data_len < 8 + 38 + 33 + 64 + 8 ||
      memcmp(data, PROOF_MAGIC, 8) != 0 || data[8] != CONTACT_BOOK_VERSION)
    return false;
  size_t off = 9;
  ContactBookManifest manifest;
  manifest.revision = read_be32(data + off);
  off += 4;
  manifest.count = data[off++];
  memcpy(manifest.root, data + off, 32);
  off += 32;
  if (manifest.revision == 0 || manifest.count == 0 ||
      manifest.count > CONTACT_BOOK_MAX_ENTRIES)
    return false;
  const uint8_t* pubkey = data + off;
  off += 33;
  const uint8_t* signature = data + off;
  off += 64;
  if (memcmp(pubkey, expected_pubkey, 33) != 0) return false;

  if (off + 5 > data_len) return false;
  ContactBookEntry entry;
  memset(&entry, 0, sizeof(entry));
  uint8_t network_len = data[off++];
  if (off + network_len + 3 > data_len ||
      !network_valid(data + off, network_len))
    return false;
  memcpy(entry.network, data + off, network_len);
  off += network_len;
  entry.destination_type = data[off++];
  entry.destination_len = data[off++];
  if (entry.destination_type == 0 || entry.destination_len == 0 ||
      off + entry.destination_len + 1 > data_len)
    return false;
  memcpy(entry.destination, data + off, entry.destination_len);
  if (entry.destination_type == CONTACT_BOOK_DEST_ADDRESS_TEXT &&
      !address_text_valid(entry.destination, entry.destination_len))
    return false;
  off += entry.destination_len;
  uint8_t label_len = data[off++];
  if (off + label_len + 2 > data_len || !label_valid(data + off, label_len))
    return false;
  memcpy(entry.label, data + off, label_len);
  off += label_len;
  uint8_t index = data[off++];
  uint8_t depth = data[off++];
  if (index >= manifest.count || depth != tree_depth(manifest.count) ||
      depth > CONTACT_BOOK_MAX_DEPTH || off + (size_t)depth * 32 != data_len)
    return false;

  uint8_t hash[32], combined[32];
  leaf_hash(&entry, hash);
  uint8_t cursor = index;
  for (uint8_t i = 0; i < depth; i++) {
    const uint8_t* sibling = data + off + (size_t)i * 32;
    if (cursor & 1)
      pair_hash(sibling, hash, combined);
    else
      pair_hash(hash, sibling, combined);
    memcpy(hash, combined, 32);
    cursor >>= 1;
  }
  if (memcmp(hash, manifest.root, 32) != 0) {
    memzero(&entry, sizeof(entry));
    return false;
  }

  uint8_t encoded[46], digest[32];
  contact_book_manifest_bytes(&manifest, encoded);
  sha256_Raw(encoded, sizeof(encoded), digest);
  bool ok = ecdsa_verify_digest(&secp256k1, pubkey, signature, digest) == 0;
  memzero(encoded, sizeof(encoded));
  memzero(digest, sizeof(digest));
  memzero(hash, sizeof(hash));
  memzero(combined, sizeof(combined));
  if (!ok) {
    memzero(&entry, sizeof(entry));
    return false;
  }
  proof_entry = entry;
  proof_available = true;
  memzero(&entry, sizeof(entry));
  return true;
}

bool contact_book_match(const char* network, uint8_t destination_type,
                        const uint8_t* destination, size_t destination_len) {
  return proof_available && network && destination &&
         strcmp(proof_entry.network, network) == 0 &&
         proof_entry.destination_type == destination_type &&
         proof_entry.destination_len == destination_len &&
         memcmp(proof_entry.destination, destination, destination_len) == 0;
}

const char* contact_book_label(void) {
  return proof_available ? proof_entry.label : NULL;
}

void contact_book_clear(void) {
  proof_available = false;
  proof_consuming = false;
  memzero(&proof_entry, sizeof(proof_entry));
}

void contact_book_begin(void) {
  if (proof_consuming) contact_book_clear();
  proof_consuming = proof_available;
}

bool contact_book_consuming(void) { return proof_consuming; }

bool contact_book_confirm_address(const char* network, const char* address) {
  if (!address || !contact_book_match(network, CONTACT_BOOK_DEST_ADDRESS_TEXT,
                                      (const uint8_t*)address, strlen(address)))
    return true;
  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Certified contact", "%s\n%s", proof_entry.label, network);
}

bool contact_book_confirm_chain(const char* family, const char* chain,
                                const char* address) {
  if (!family || !chain) return true;
  char network[CONTACT_BOOK_NETWORK_MAX + 1];
  const int n = snprintf(network, sizeof(network), "%s:%s", family, chain);
  if (n < 0 || (size_t)n >= sizeof(network)) return true;
  return contact_book_confirm_address(network, address);
}

bool contact_book_confirm_chain_hash(const char* family, const uint8_t* chain,
                                     size_t chain_size, const char* address) {
  if (!chain || !chain_size || chain_size > 28) return true;
  static const char hex[] = "0123456789abcdef";
  char reference[57];
  for (size_t i = 0; i < chain_size; i++) {
    reference[2 * i] = hex[chain[i] >> 4];
    reference[2 * i + 1] = hex[chain[i] & 15];
  }
  reference[2 * chain_size] = 0;
  return contact_book_confirm_chain(family, reference, address);
}

bool contact_book_confirm_coin(const char* coin, const char* address) {
  static const struct {
    const char* coin;
    const char* network;
  } networks[] = {{"Bitcoin", "bip122:000000000019d6689c085ae165831e93"},
                  {"Testnet", "bip122:000000000933ea01ad0ee984209779ba"},
                  {"BitcoinCash", "bip122:000000000000000000651ef99cb9fcbe"},
                  {"Litecoin", "bip122:12a765e31ffd4059bada1e25190f6e98"},
                  {"Dogecoin", "bip122:00000000001a91e3dace36e2be3bf030"},
                  {"Dash", "bip122:000007d91d1254d60e2dd1ae58038307"},
                  {"DigiByte", "bip122:4da631f2ac1bed857bd968c67c913978"},
                  {"Zcash", "bip122:00040fe8ec8471911baa1db1266ea15d"},
                  {"Nano", "nano:mainnet"},
                  {"Banano", "banano:mainnet"}};
  if (!coin) return true;
  for (size_t i = 0; i < sizeof(networks) / sizeof(networks[0]); i++)
    if (!strcmp(coin, networks[i].coin))
      return contact_book_confirm_address(networks[i].network, address);
  /* Private CAIP namespace for firmware coins without a registered mapping.
   * Hex of the exact coin name is reversible and cannot alias spaces/case. */
  return contact_book_confirm_chain_hash("keepkey", (const uint8_t*)coin,
                                         strlen(coin), address);
}
