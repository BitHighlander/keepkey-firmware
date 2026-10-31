#include "keepkey/firmware/erc7730_settle.h"

#include <stdio.h>
#include <string.h>

#include "keepkey/firmware/erc7730_capabilities.h"
#include "keepkey/firmware/erc7730_field.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "trezor/crypto/bignum.h"
#include "trezor/crypto/memzero.h"

static bool all_zero(const uint8_t* bytes, size_t length) {
  uint8_t any = 0;
  for (size_t i = 0; i < length; i++) any |= bytes[i];
  return any == 0;
}

/* The firmware table's token at `token` on this chain, or NULL. */
static const TokenType* table_token(uint64_t chain_id,
                                    const uint8_t token[20]) {
  const TokenType* known = chain_id <= UINT32_MAX
                               ? tokenByChainAddress((uint32_t)chain_id, token)
                               : UnknownToken;
  return known && known != UnknownToken ? known : NULL;
}

typedef struct {
  uint32_t chain_id;
  uint8_t address[20];
} ChainAddress;

/* The chain's wrapped native coin, where the token table lists it: it nets
 * as the native coin, since a filler can pay one with the other. */
static const ChainAddress wrapped_native[] = {
    {1, {0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c,
         0x4f, 0x27, 0xea, 0xd9, 0x08, 0x3c, 0x75, 0x6c, 0xc2}}, /* WETH */
};

/* ERC-721 collections whose IDs are hashes or packed coordinates, so an ID
 * of 2^64 or more is theirs to have. */
static const ChainAddress hashed_id_collections[] = {
    {1, {0x57, 0xf1, 0x88, 0x7a, 0x8b, 0xf1, 0x9b, 0x14, 0xfc, 0x0d,
         0xf6, 0xfd, 0x9b, 0x2a, 0xcc, 0x9a, 0xf1, 0x47, 0xea, 0x85}}, /* ENS */
    {1, {0x04, 0x9a, 0xba, 0x75, 0x10, 0xf4, 0x5b, 0xa5, 0xb6, 0x4e,
         0xa9, 0xe6, 0x58, 0xe3, 0x42, 0xf9, 0x04, 0xdb, 0x35, 0x8d}},
    /* Unstoppable Domains */
    {1, {0xd1, 0xe5, 0xb0, 0xff, 0x12, 0x87, 0xaa, 0x9f, 0x9a, 0x26,
         0x87, 0x59, 0x06, 0x2e, 0x4a, 0xb0, 0x8b, 0x9d, 0xac, 0xbe}},
    /* Unstoppable Domains .crypto (CNS) */
    {1, {0xf8, 0x7e, 0x31, 0x49, 0x2f, 0xaf, 0x9a, 0x91, 0xb0, 0x2e,
         0xe0, 0xde, 0xaa, 0xd5, 0x0d, 0x51, 0xd5, 0x6d, 0x5d, 0x4d}},
    /* Decentraland LAND */
    {1, {0x2a, 0x18, 0x74, 0x53, 0x06, 0x43, 0x56, 0xc8, 0x98, 0xca,
         0xe0, 0x34, 0xea, 0xed, 0x11, 0x9e, 0x16, 0x63, 0xac, 0xb8}},
    /* Decentraland Names */
    {1, {0x62, 0x9a, 0x67, 0x3a, 0x82, 0x42, 0xc2, 0xac, 0x4b, 0x7b,
         0x8c, 0x5d, 0x87, 0x35, 0xfb, 0xea, 0xc2, 0x1a, 0x62, 0x05}},
    /* Sorare */
    {1, {0xf6, 0x79, 0x3d, 0xa6, 0x57, 0x49, 0x5f, 0xfe, 0xff, 0x9e,
         0xe6, 0x35, 0x08, 0x24, 0x91, 0x0a, 0xbc, 0x21, 0x35, 0x6c}},
    /* Rarible (shared ERC-721, lazy-minted IDs) */
    /* Review r4, from real fills: every ERC-721 Seaport 1.6 moved on chain 1
     * with an ID of 2^64 or more over blocks 26263701-26313700 (63,287 fills),
     * read on chain (ERC-165 ERC-721, not ERC-1155, no decimals()); the eight
     * with the most listings. */
    {1, {0x20, 0x26, 0x2e, 0x34, 0x33, 0x30, 0x6a, 0x4f, 0xf2, 0x50,
         0xa6, 0x4d, 0x20, 0xa8, 0xe0, 0xf0, 0x9b, 0x2c, 0x7f, 0x68}},
    /* ENS Commemorative */
    {1, {0x0b, 0xfa, 0x9a, 0xff, 0x76, 0xfd, 0x91, 0x75, 0x6f, 0x83,
         0x7a, 0xb4, 0x7e, 0x11, 0xbd, 0x99, 0xe0, 0x4c, 0x15, 0xbd}},
    /* Unetwork Operator Software License */
    {1, {0x57, 0x2e, 0x33, 0xff, 0xa5, 0x23, 0x86, 0x57, 0x91, 0xab,
         0x1c, 0x26, 0xb4, 0x2a, 0x86, 0xac, 0x24, 0x4d, 0xf7, 0x84}},
    /* Gucci */
    {1, {0x51, 0xbd, 0x59, 0x48, 0xcf, 0x84, 0xa1, 0x04, 0x1d, 0x27,
         0x20, 0xf5, 0x6d, 0xed, 0x5e, 0x17, 0x33, 0x96, 0xfc, 0x95}},
    /* Zer0 Name Service (0x51bd) */
    {1, {0x05, 0xf8, 0x1f, 0x87, 0x0c, 0xbc, 0xa7, 0x9e, 0x91, 0x71,
         0xf2, 0x28, 0x86, 0xb5, 0x8b, 0x55, 0x97, 0xa6, 0x03, 0xaa}},
    /* Zer0 Name Service (0x05f8) */
    {1, {0x74, 0x15, 0x12, 0x95, 0x4c, 0xb6, 0xf8, 0xe5, 0xd3, 0xcd,
         0x93, 0x21, 0xc0, 0x74, 0x62, 0xb0, 0x5b, 0x7c, 0xc8, 0xd5}},
    /* OKX AI NFT */
    {1, {0xc2, 0xe9, 0x67, 0x8a, 0x71, 0xe5, 0x0e, 0x5a, 0xed, 0x03,
         0x6e, 0x00, 0xe9, 0xc5, 0xca, 0xeb, 0x1a, 0xc5, 0x98, 0x7d}},
    /* Zero Name Service (0xc2e9) */
    {1, {0xc9, 0x15, 0x44, 0x24, 0xb8, 0x23, 0xb1, 0x05, 0x79, 0x89,
         0x5c, 0xcb, 0xe4, 0x42, 0xd4, 0x1b, 0x9a, 0xbd, 0x96, 0xed}},
    /* Rarible (0xc915) */
};

typedef struct {
  ChainAddress where;
  const char* ticker; /* starts with a space, like the table's */
} ChainToken;

/* ERC-20s the token table does not list, which no NFT item names: such an
 * item moves its ID as an amount of the token. */
static const ChainToken never_nft[] = {
    {{1, {0xcb, 0xb7, 0xc0, 0x00, 0x0a, 0xb8, 0x8b, 0x47, 0x3b, 0x1f,
          0x5a, 0xfd, 0x9e, 0xf8, 0x08, 0x44, 0x0e, 0xed, 0x33, 0xbf}},
     " cbBTC"},
    {{1, {0x6c, 0x3e, 0xa9, 0x03, 0x64, 0x06, 0x85, 0x20, 0x06, 0x29,
          0x07, 0x70, 0xbe, 0xdf, 0xca, 0xba, 0x0e, 0x23, 0xa0, 0xe8}},
     " PYUSD"},
    {{1, {0x68, 0x74, 0x96, 0x65, 0xff, 0x8d, 0x2d, 0x11, 0x2f, 0xa8,
          0x59, 0xaa, 0x29, 0x3f, 0x07, 0xa6, 0x22, 0x78, 0x2f, 0x38}},
     " XAUt"},
    {{1, {0x1a, 0xba, 0xea, 0x1f, 0x7c, 0x83, 0x0b, 0xd8, 0x9a, 0xcc,
          0x67, 0xec, 0x4a, 0xf5, 0x16, 0x28, 0x4b, 0x1b, 0xc3, 0x3c}},
     " EURC"},
    {{1, {0xae, 0x7a, 0xb9, 0x65, 0x20, 0xde, 0x3a, 0x18, 0xe5, 0xe1,
          0x11, 0xb5, 0xea, 0xab, 0x09, 0x53, 0x12, 0xd7, 0xfe, 0x84}},
     " stETH"},
    {{1, {0x7f, 0x39, 0xc5, 0x81, 0xf5, 0x95, 0xb5, 0x3c, 0x5c, 0xb1,
          0x9b, 0xd0, 0xb3, 0xf8, 0xda, 0x6c, 0x93, 0x5e, 0x2c, 0xa0}},
     " wstETH"},
    {{1, {0x4c, 0x9e, 0xdd, 0x58, 0x52, 0xcd, 0x90, 0x5f, 0x08, 0x6c,
          0x75, 0x9e, 0x83, 0x83, 0xe0, 0x9b, 0xff, 0x1e, 0x68, 0xb3}},
     " USDe"},
    {{1, {0x4d, 0x22, 0x44, 0x52, 0x80, 0x1a, 0xce, 0xd8, 0xb2, 0xf0,
          0xae, 0xbe, 0x15, 0x53, 0x79, 0xbb, 0x5d, 0x59, 0x43, 0x81}},
     " APE"},
};

static bool listed(const ChainAddress* list, size_t count, uint64_t chain_id,
                   const uint8_t address[20]) {
  for (size_t i = 0; i < count; i++)
    if (list[i].chain_id == chain_id &&
        memcmp(list[i].address, address, 20) == 0)
      return true;
  return false;
}

/* The ticker of a coin no NFT item names: one of the firmware's table on
 * this chain, or of never_nft[]; NULL for anything else. */
static const char* coin_ticker(uint64_t chain_id, const uint8_t token[20]) {
  const TokenType* known = table_token(chain_id, token);
  if (known) return known->ticker;
  for (size_t i = 0; i < sizeof(never_nft) / sizeof(never_nft[0]); i++)
    if (never_nft[i].where.chain_id == chain_id &&
        memcmp(never_nft[i].where.address, token, 20) == 0)
      return never_nft[i].ticker;
  return NULL;
}

/* 0xEeee...EEeE: a router's name for the native coin, not a contract. */
static bool native_placeholder(const uint8_t token[20]) {
  for (size_t i = 0; i < 20; i++)
    if (token[i] != 0xee) return false;
  return true;
}

void erc7730_settle_type(Erc7730Settle* settle, const uint8_t word[32]) {
  if (!settle) return;
  /* An item type beyond Seaport's is not one the device can value. */
  if (!all_zero(word, 31) || word[31] > ERC7730_SETTLE_CRITERIA_MAX)
    settle->item_unreadable = true;
  settle->item.kind = word[31];
  settle->item_seen |= ERC7730_FORMATTER_FLAG_SETTLE_TYPE;
}

void erc7730_settle_id(Erc7730Settle* settle, const uint8_t word[32]) {
  if (!settle) return;
  memcpy(settle->item.id, word, 32);
  settle->item_seen |= ERC7730_FORMATTER_FLAG_SETTLE_ID;
}

void erc7730_settle_amount(Erc7730Settle* settle, const uint8_t amount[32],
                           const uint8_t token[20], bool native) {
  if (!settle) return;
  /* An amount shown before its item's type may have read as the wrong kind. */
  if (!(settle->item_seen & ERC7730_FORMATTER_FLAG_SETTLE_TYPE))
    settle->item_unreadable = true;
  /* Only the zero address stands for the native coin here; any other alias
   * is valued by the token table, as an ERC-20. */
  native = native && all_zero(token, 20);
  if (settle->item_seen & ERC7730_FORMATTER_FLAG_SETTLE_AMOUNT) {
    /* A start and an end amount: the item pays at least the smaller, and
     * gives at most the larger. */
    if (memcmp(settle->item.token, token, 20) != 0 ||
        settle->item_native != native)
      settle->item_unreadable = true;
    if (memcmp(amount, settle->item.amount, 32) < 0)
      memcpy(settle->item.amount, amount, 32);
    if (memcmp(amount, settle->item_max, 32) > 0)
      memcpy(settle->item_max, amount, 32);
    return;
  }
  memcpy(settle->item.amount, amount, 32);
  memcpy(settle->item_max, amount, 32);
  memcpy(settle->item.token, token, 20);
  settle->item_native = native;
  settle->item_seen |= ERC7730_FORMATTER_FLAG_SETTLE_AMOUNT;
}

void erc7730_settle_to(Erc7730Settle* settle, bool signer) {
  if (!settle) return;
  settle->item_to_signer = signer;
  settle->item_seen |= ERC7730_FORMATTER_FLAG_SETTLE_TO;
}

void erc7730_settle_unreadable(Erc7730Settle* settle) {
  if (settle) settle->item_unreadable = true;
}

/* sum += add, false (and sum unchanged) on overflow. */
static bool add_word(uint8_t sum[32], const uint8_t add[32]) {
  uint8_t total[32];
  unsigned carry = 0;
  for (int i = 31; i >= 0; i--) {
    carry += (unsigned)sum[i] + add[i];
    total[i] = (uint8_t)carry;
    carry >>= 8;
  }
  if (carry == 0) memcpy(sum, total, 32);
  memzero(total, sizeof(total));
  return carry == 0;
}

static bool same_item(const Erc7730SettleItem* a, const Erc7730SettleItem* b) {
  return a->kind == b->kind && memcmp(a->token, b->token, 20) == 0 &&
         memcmp(a->id, b->id, 32) == 0;
}

/* Adds `amount` of `item` to the slot of the same (kind, token, id), or to a
 * new slot; false when there is no slot left or the total overflows. */
static bool keep(Erc7730SettleItem slots[ERC7730_SETTLE_SLOTS], uint8_t* count,
                 const Erc7730SettleItem* item, const uint8_t amount[32]) {
  for (size_t slot = 0; slot < *count; slot++) {
    if (same_item(&slots[slot], item))
      return add_word(slots[slot].amount, amount);
  }
  if (*count >= ERC7730_SETTLE_SLOTS) return false;
  slots[*count] = *item;
  memcpy(slots[*count].amount, amount, 32);
  (*count)++;
  return true;
}

void erc7730_settle_end_item(Erc7730Settle* settle, uint64_t chain_id) {
  if (!settle) return;
  Erc7730SettleItem* item = &settle->item;
  const uint8_t seen = settle->item_seen;
  if (seen) {
    /* erc7730_settle_amount() marks an amount shown before its type. */
    bool readable = !settle->item_unreadable &&
                    (seen & ERC7730_FORMATTER_FLAG_SETTLE_AMOUNT);
    if (item->kind <= ERC7730_SETTLE_ERC20) {
      /* A coin is the native coin exactly when its token is 0x0. */
      readable = readable &&
                 settle->item_native == (item->kind == ERC7730_SETTLE_NATIVE) &&
                 !native_placeholder(item->token);
      memzero(item->id, sizeof(item->id));
    } else {
      readable = readable && (seen & ERC7730_FORMATTER_FLAG_SETTLE_ID);
    }
    /* Seaport moves an ERC-721 item with transferFrom(from, to, id), which an
     * ERC-20 answers too: an ID no collection would use moves that many
     * units. Contracts the device knows as coins have their own warning. */
    if (readable && item->kind == ERC7730_SETTLE_ERC721 &&
        !all_zero(item->id, 24) && !coin_ticker(chain_id, item->token) &&
        !listed(
            hashed_id_collections,
            sizeof(hashed_id_collections) / sizeof(hashed_id_collections[0]),
            chain_id, item->token))
      settle->large_nft_id = true;
    if (seen & ERC7730_FORMATTER_FLAG_SETTLE_TO) {
      if (settle->item_to_signer) {
        settle->received_any = true;
        if (!readable || !keep(settle->received, &settle->received_count, item,
                               item->amount))
          settle->unlisted = true;
      }
    } else {
      /* An item without a recipient is one the order gives away. Coins are
       * kept to net against what is paid back; NFTs are kept to be listed,
       * never netted. An ERC-20 the table does not list may be an NFT
       * collection: Seaport's transferFrom(from, to, amount) then moves the
       * NFT whose ID is the amount. */
      settle->gives = true;
      /* By criteria, the filler picks the identifier: any NFT of the
       * collection, or, on a token, any amount. */
      if (item->kind > ERC7730_SETTLE_ERC1155 &&
          item->kind <= ERC7730_SETTLE_CRITERIA_MAX)
        settle->gives_by_criteria = true;
      if (readable && item->kind == ERC7730_SETTLE_ERC20 &&
          !table_token(chain_id, item->token))
        settle->gives_unknown_token = true;
      if (!readable) {
        settle->given_unread = true;
      } else if (item->kind <= ERC7730_SETTLE_ERC20) {
        if (!keep(settle->given, &settle->given_count, item, settle->item_max))
          settle->given_unread = true;
      } else {
        const bool full = settle->given_nft_count >= ERC7730_SETTLE_SLOTS;
        bool kept = false;
        for (size_t i = 0; i < settle->given_nft_count; i++)
          kept = kept || same_item(&settle->given_nft[i], item);
        if (!keep(settle->given_nft, &settle->given_nft_count, item,
                  settle->item_max)) {
          if (full && !kept) {
            /* Counted, not shown: the screen does not show all it gives. */
            if (settle->given_nft_more < UINT8_MAX) settle->given_nft_more++;
          } else {
            settle->given_unread = true; /* a count that overflows */
          }
        }
      }
    }
  }
  memzero(item, sizeof(*item));
  memzero(settle->item_max, sizeof(settle->item_max));
  settle->item_seen = 0;
  settle->item_native = false;
  settle->item_to_signer = false;
  settle->item_unreadable = false;
}

/* The native coin, or the chain's wrapped native coin. */
static bool native_or_wrapped(const Erc7730SettleItem* item,
                              uint64_t chain_id) {
  if (item->kind == ERC7730_SETTLE_NATIVE) return true;
  return item->kind == ERC7730_SETTLE_ERC20 &&
         table_token(chain_id, item->token) &&
         listed(wrapped_native,
                sizeof(wrapped_native) / sizeof(wrapped_native[0]), chain_id,
                item->token);
}

/* A coin the device knows (the native coin, or an ERC-20 the firmware table
 * lists on this chain) and the floor under which it says so: 0.0001 of one
 * for more than six decimals, 0.01 for three to six, one unit below that.
 * The floor counts units, not value: the device has no prices, and paying
 * above it says nothing about the order. False for anything else. */
static bool coin_floor(const Erc7730SettleItem* item, uint64_t chain_id,
                       uint8_t floor[32]) {
  unsigned decimals = 18;
  if (item->kind == ERC7730_SETTLE_ERC20) {
    const TokenType* known = table_token(chain_id, item->token);
    if (!known) return false;
    decimals = known->decimals;
  } else if (item->kind != ERC7730_SETTLE_NATIVE) {
    return false;
  }
  memset(floor, 0, 32);
  floor[31] = 1;
  for (unsigned k = decimals > 6   ? decimals - 4
                    : decimals > 2 ? decimals - 2
                                   : 0;
       k > 0; k--) {
    unsigned carry = 0;
    for (int i = 31; i >= 0; i--) {
      carry += floor[i] * 10u;
      floor[i] = (uint8_t)carry;
      carry >>= 8;
    }
  }
  return true;
}

static bool format_count(const uint8_t value[32], char* out, size_t size) {
  bignum256 number;
  bn_read_be(value, &number);
  const size_t length = bn_format(&number, NULL, NULL, 0, 0, false, out, size);
  memzero(&number, sizeof(number));
  return length > 0 && length < size;
}

/* An NFT item as Seaport moves it: one ERC-721 by its identifier, a count of
 * an ERC-1155 (or of an ERC-721, which Seaport refuses to move), a count "by
 * criteria" (the criteria is its own screen); then the collection. */
static bool format_nft(uint8_t kind, const uint8_t amount[32],
                       const uint8_t id_word[32], const uint8_t token[20],
                       char* out, size_t size) {
  static const uint8_t one[32] = {[31] = 1};
  char count[80], id[80], collection[43];
  bool ok =
      kind >= ERC7730_SETTLE_ERC721 && kind <= ERC7730_SETTLE_CRITERIA_MAX &&
      format_count(amount, count, sizeof(count)) &&
      format_count(id_word, id, sizeof(id)) &&
      erc7730_format_address(token, false, collection, sizeof(collection));
  if (ok) {
    int length;
    if (kind == ERC7730_SETTLE_ERC721 && memcmp(amount, one, 32) == 0)
      length = snprintf(out, size, "NFT ID %s\n%s", id, collection);
    else if (kind <= ERC7730_SETTLE_ERC1155)
      length =
          snprintf(out, size, "%s of NFT ID %s\n%s", count, id, collection);
    else
      length = snprintf(out, size, "%s NFT by criteria\n%s", count, collection);
    ok = length > 0 && (size_t)length < size;
  }
  if (!ok && size) out[0] = '\0';
  memzero(count, sizeof(count));
  memzero(id, sizeof(id));
  return ok;
}

static bool format_item(const Erc7730SettleItem* item, uint64_t chain_id,
                        char* out, size_t size) {
  if (item->kind == ERC7730_SETTLE_NATIVE)
    return erc7730_format_native_amount(item->amount, chain_id, out, size);
  if (item->kind == ERC7730_SETTLE_ERC20)
    return erc7730_format_token_amount(item->amount, item->token, false,
                                       chain_id, NULL, out, size);
  return format_nft(item->kind, item->amount, item->id, item->token, out, size);
}

bool erc7730_settle_item_is_coin(const Erc7730Settle* settle) {
  return !settle || !(settle->item_seen & ERC7730_FORMATTER_FLAG_SETTLE_TYPE) ||
         settle->item.kind <= ERC7730_SETTLE_ERC20;
}

bool erc7730_settle_format_nft_amount(Erc7730Settle* settle,
                                      const uint8_t amount[32],
                                      const uint8_t token[20],
                                      uint64_t chain_id, char* out,
                                      size_t size) {
  if (!settle || !out || size == 0) return false;
  out[0] = '\0';
  const uint8_t kind = settle->item.kind;
  /* ERC-721 and ERC-1155 items are told by their identifier. */
  if (kind <= ERC7730_SETTLE_ERC1155 &&
      !(settle->item_seen & ERC7730_FORMATTER_FLAG_SETTLE_ID))
    return false;
  if (!format_nft(kind, amount, settle->item.id, token, out, size))
    return false;
  /* No NFT is a coin: such an item moves its identifier as that coin. The
   * table's 0xEeee...EEeE "ETH" is no contract at all. */
  if (native_placeholder(token)) {
    settle->nft_placeholder = true;
    return true;
  }
  const char* coin = coin_ticker(chain_id, token);
  if (coin && !settle->coin_as_nft) settle->coin_as_nft = coin;
  return true;
}

/* What `settle` receives of `received`, net of what it gives of the same
 * coin (the native coin and its wrapped coin are one); false when it gets
 * back no more than that. Each received coin is netted against all of it,
 * so the net is never more than what is received. */
static bool net_of_given(const Erc7730Settle* settle, uint64_t chain_id,
                         const Erc7730SettleItem* received,
                         Erc7730SettleItem* net) {
  *net = *received;
  for (size_t i = 0; i < settle->given_count; i++) {
    const Erc7730SettleItem* given = &settle->given[i];
    if (!same_item(given, net) && !(native_or_wrapped(given, chain_id) &&
                                    native_or_wrapped(net, chain_id)))
      continue;
    if (memcmp(net->amount, given->amount, 32) <= 0) return false;
    unsigned borrow = 0;
    for (int k = 31; k >= 0; k--) {
      const unsigned difference =
          (unsigned)net->amount[k] - given->amount[k] - borrow;
      net->amount[k] = (uint8_t)difference;
      borrow = (difference >> 8) & 1u;
    }
  }
  return true;
}

static bool append(char* body, size_t body_size, size_t* used,
                   const char* text) {
  const int length =
      snprintf(body + *used, body_size - *used, "%s%s",
               *used && body[*used - 1] != '\n' ? "\n" : "", text);
  if (length <= 0 || (size_t)length >= body_size - *used) return false;
  *used += (size_t)length;
  return true;
}

bool erc7730_settle_review(const Erc7730Settle* settle, uint64_t chain_id,
                           Erc7730SettleVerdict* verdict, char* body,
                           size_t body_size) {
  if (!settle || !verdict || !body || body_size == 0) return false;
  body[0] = '\0';
  size_t used = 0;
  char line[200];
  bool ok = true;
  Erc7730SettleItem net[ERC7730_SETTLE_SLOTS];
  size_t net_count = 0;
  bool any_known = false, any_above = false;
  Erc7730SettleItem dust;
  memzero(&dust, sizeof(dust));
  for (size_t i = 0; i < settle->received_count; i++) {
    if (net_of_given(settle, chain_id, &settle->received[i], &net[net_count])) {
      uint8_t floor[32];
      if (coin_floor(&net[net_count], chain_id, floor)) {
        if (memcmp(net[net_count].amount, floor, 32) >= 0) {
          any_above = true;
        } else if (!any_known) {
          dust = net[net_count];
          memcpy(dust.amount, floor, 32);
        }
        any_known = true;
      }
      net_count++;
    }
  }
  Erc7730SettleVerdict base = ERC7730_SETTLE_CALM;
  const char* receipt = NULL;
  if (net_count == 0 && !settle->unlisted) {
    base = ERC7730_SETTLE_NOTHING;
    receipt = settle->received_any
                  ? "This wallet gets back no more than it gives."
                  : "Nothing in this order is paid to this wallet.";
  } else if (settle->gives && !any_known) {
    base = ERC7730_SETTLE_UNVALUED;
    receipt = "This wallet gets only unknown tokens or NFTs.";
  } else if (settle->gives && !any_above) {
    base = ERC7730_SETTLE_DUST;
  }

  /* What the device can tell from the order, one line each. */
  if (settle->coin_as_nft) {
    /* The table's tickers start with a space. */
    ok = snprintf(line, sizeof(line),
                  "An NFT item names the token%s: Seaport moves its ID as an "
                  "amount of%s.",
                  settle->coin_as_nft,
                  settle->coin_as_nft) < (int)sizeof(line) &&
         append(body, body_size, &used, line);
  }
  if (ok && settle->nft_placeholder)
    ok = append(body, body_size, &used,
                "An NFT item names 0xEeee...EEeE, the native coin's "
                "placeholder: it is not an NFT contract.");
  if (ok && settle->gives_by_criteria)
    ok = append(body, body_size, &used,
                "This wallet gives an item by criteria: the buyer picks its "
                "ID (on a token, the ID is an amount).");
  if (ok && settle->large_nft_id)
    ok = append(body, body_size, &used,
                "An NFT ID is 2^64 or more: if its contract is a token, "
                "Seaport moves that many units of it.");
  if (ok && settle->gives_unknown_token)
    ok = append(body, body_size, &used,
                "This wallet gives a token the device does not know: if it is "
                "an NFT collection, Seaport moves the NFT whose ID is the "
                "amount.");
  if (ok && settle->given_unread)
    ok = append(body, body_size, &used,
                "This wallet gives an item the device cannot read.");
  if (ok && settle->given_nft_more)
    ok = append(body, body_size, &used,
                "This wallet gives more items than this screen lists.");
  if (ok && receipt) ok = append(body, body_size, &used, receipt);
  if (ok && base == ERC7730_SETTLE_DUST) {
    char floor[100];
    ok = format_item(&dust, chain_id, floor, sizeof(floor)) &&
         snprintf(line, sizeof(line), "This wallet gets under %s.", floor) <
             (int)sizeof(line) &&
         append(body, body_size, &used, line);
    memzero(floor, sizeof(floor));
  }

  /* Both sides, always: the device never says an order is fair. */
  if (ok) ok = append(body, body_size, &used, "You give:");
  for (size_t i = 0; ok && i < settle->given_nft_count; i++)
    ok = format_item(&settle->given_nft[i], chain_id, line, sizeof(line)) &&
         append(body, body_size, &used, line);
  if (ok && settle->given_nft_more)
    ok = snprintf(line, sizeof(line), "+ %u more NFT%s",
                  (unsigned)settle->given_nft_more,
                  settle->given_nft_more == 1 ? "" : "s") < (int)sizeof(line) &&
         append(body, body_size, &used, line);
  for (size_t i = 0; ok && i < settle->given_count; i++)
    ok = format_item(&settle->given[i], chain_id, line, sizeof(line)) &&
         append(body, body_size, &used, line);
  if (ok && settle->given_unread)
    ok = append(body, body_size, &used, "+ items not listed here");
  if (ok && !settle->gives) ok = append(body, body_size, &used, "Nothing");
  if (ok) ok = append(body, body_size, &used, "You receive:");
  for (size_t i = 0; ok && i < net_count; i++)
    ok = format_item(&net[i], chain_id, line, sizeof(line)) &&
         append(body, body_size, &used, line);
  if (ok && settle->unlisted)
    ok = append(body, body_size, &used, "+ items not listed here");
  if (ok && net_count == 0 && !settle->unlisted)
    ok = append(body, body_size, &used, "Nothing");

  *verdict = settle->coin_as_nft           ? ERC7730_SETTLE_COIN_AS_NFT
             : settle->nft_placeholder     ? ERC7730_SETTLE_NFT_PLACEHOLDER
             : settle->gives_by_criteria   ? ERC7730_SETTLE_GIVES_BY_CRITERIA
             : settle->large_nft_id        ? ERC7730_SETTLE_LARGE_NFT_ID
             : settle->gives_unknown_token ? ERC7730_SETTLE_GIVES_UNKNOWN_TOKEN
             : settle->given_unread        ? ERC7730_SETTLE_GIVEN_UNREAD
             : settle->given_nft_more      ? ERC7730_SETTLE_GIVEN_UNLISTED
                                           : base;
  memzero(line, sizeof(line));
  memzero(net, sizeof(net));
  memzero(&dust, sizeof(dust));
  if (!ok) body[0] = '\0';
  return ok;
}
