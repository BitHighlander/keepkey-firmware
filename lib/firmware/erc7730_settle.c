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

void erc7730_settle_give(Erc7730Settle* settle) {
  if (settle) settle->gives = true;
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
  /* Only the zero address stands for the native coin here; any other alias
   * is valued by the token table, as an ERC-20. */
  native = native && all_zero(token, 20);
  if (settle->item_seen & ERC7730_FORMATTER_FLAG_SETTLE_AMOUNT) {
    /* A start and an end amount: the item pays at least the smaller. */
    if (memcmp(settle->item.token, token, 20) != 0 ||
        settle->item_native != native)
      settle->item_unreadable = true;
    if (memcmp(amount, settle->item.amount, 32) < 0)
      memcpy(settle->item.amount, amount, 32);
    return;
  }
  memcpy(settle->item.amount, amount, 32);
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

/* sum += add; on overflow false, and sum is left as it was. */
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

void erc7730_settle_end_item(Erc7730Settle* settle, uint64_t chain_id) {
  if (!settle) return;
  Erc7730SettleItem* item = &settle->item;
  const uint8_t seen = settle->item_seen;
  if (!(seen & ERC7730_FORMATTER_FLAG_SETTLE_TYPE))
    item->kind =
        settle->item_native ? ERC7730_SETTLE_NATIVE : ERC7730_SETTLE_ERC20;
  /* An item described without a recipient is one the order gives away. An
   * ERC-20 of it the table does not list may be an NFT collection: Seaport's
   * transferFrom(from, to, amount) then moves the NFT whose ID is the
   * amount. */
  if (!(seen & ERC7730_FORMATTER_FLAG_SETTLE_TO) &&
      (seen & (ERC7730_FORMATTER_FLAG_SETTLE_TYPE |
               ERC7730_FORMATTER_FLAG_SETTLE_AMOUNT))) {
    settle->gives = true;
    if ((seen & ERC7730_FORMATTER_FLAG_SETTLE_AMOUNT) &&
        item->kind == ERC7730_SETTLE_ERC20 &&
        !table_token(chain_id, item->token))
      settle->gives_unknown_token = true;
  }
  if ((seen & ERC7730_FORMATTER_FLAG_SETTLE_TO) && settle->item_to_signer) {
    settle->received_any = true;
    bool readable = !settle->item_unreadable &&
                    (seen & ERC7730_FORMATTER_FLAG_SETTLE_AMOUNT);
    if (item->kind <= ERC7730_SETTLE_ERC20) {
      /* A coin is the native coin exactly when its token is 0x0. */
      readable = readable &&
                 settle->item_native == (item->kind == ERC7730_SETTLE_NATIVE);
      memzero(item->id, sizeof(item->id));
    } else {
      readable = readable && (seen & ERC7730_FORMATTER_FLAG_SETTLE_ID);
    }
    size_t slot = 0;
    while (slot < settle->received_count &&
           (settle->received[slot].kind != item->kind ||
            memcmp(settle->received[slot].token, item->token, 20) != 0 ||
            memcmp(settle->received[slot].id, item->id, 32) != 0))
      slot++;
    if (!readable) {
      settle->unlisted = true;
    } else if (slot < settle->received_count) {
      if (!add_word(settle->received[slot].amount, item->amount))
        settle->unlisted = true;
    } else if (slot < ERC7730_SETTLE_SLOTS) {
      settle->received[slot] = *item;
      settle->received_count++;
    } else {
      settle->unlisted = true;
    }
  }
  memzero(item, sizeof(*item));
  settle->item_seen = 0;
  settle->item_native = false;
  settle->item_to_signer = false;
  settle->item_unreadable = false;
}

/* A coin worth counting: the native coin, or an ERC-20 the firmware table
 * knows on this chain, of at least a millionth of one, or a hundredth of one
 * for six decimals or fewer (USDC, USDT: a millionth would be one base unit),
 * or one unit for fewer than two. The device has no prices: the floor counts
 * units, not value, so a listed token that is cheap per unit passes it. What
 * an amount is worth stays for the user to judge on the screen. */
static bool valued(const Erc7730SettleItem* item, uint64_t chain_id) {
  unsigned decimals = 18;
  if (item->kind == ERC7730_SETTLE_ERC20) {
    const TokenType* known = table_token(chain_id, item->token);
    if (!known) return false;
    decimals = known->decimals;
  } else if (item->kind != ERC7730_SETTLE_NATIVE) {
    return false;
  }
  uint8_t floor[32] = {0};
  floor[31] = 1;
  for (unsigned k = decimals > 6   ? decimals - 6
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
  return memcmp(item->amount, floor, 32) >= 0;
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
  /* No NFT is a coin: such an item moves its identifier as that coin. */
  const TokenType* coin = table_token(chain_id, token);
  if (coin && !settle->coin_as_nft) settle->coin_as_nft = coin->ticker;
  return true;
}

/* body += a line; false when it does not fit. */
static bool append_line(char* body, size_t size, size_t* used,
                        const char* line) {
  const int length =
      snprintf(body + *used, size - *used, "%s%s", *used ? "\n" : "", line);
  if (length <= 0 || (size_t)length >= size - *used) return false;
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
  if (settle->coin_as_nft) {
    /* The table's tickers start with a space. */
    const int length = snprintf(line, sizeof(line),
                                "An NFT item names the token%s: Seaport moves "
                                "its ID as an amount of%s.",
                                settle->coin_as_nft, settle->coin_as_nft);
    ok = length > 0 && (size_t)length < sizeof(line) &&
         append_line(body, body_size, &used, line);
  }
  if (ok && settle->gives_unknown_token)
    ok = append_line(body, body_size, &used,
                     "This wallet gives a token the device does not know: if "
                     "it is an NFT collection, Seaport moves the NFT whose ID "
                     "is the amount.");
  bool any_valued = false;
  for (size_t i = 0; i < settle->received_count; i++)
    any_valued = any_valued || valued(&settle->received[i], chain_id);
  Erc7730SettleVerdict result = !settle->received_any ? ERC7730_SETTLE_NOTHING
                                : settle->gives && !any_valued
                                    ? ERC7730_SETTLE_UNVALUED
                                    : ERC7730_SETTLE_CALM;
  const char* lead = result == ERC7730_SETTLE_NOTHING
                         ? "Nothing in this order is paid to this wallet."
                     : result == ERC7730_SETTLE_UNVALUED
                         ? "This wallet gets only unknown tokens, NFTs or dust:"
                     : used ? "You receive:"
                            : NULL;
  if (ok && lead) ok = append_line(body, body_size, &used, lead);
  for (size_t i = 0; ok && i < settle->received_count; i++)
    ok = format_item(&settle->received[i], chain_id, line, sizeof(line)) &&
         append_line(body, body_size, &used, line);
  if (ok && settle->unlisted)
    ok = append_line(body, body_size, &used, "+ items not listed here");
  if (settle->coin_as_nft)
    result = ERC7730_SETTLE_COIN_AS_NFT;
  else if (settle->gives_unknown_token)
    result = ERC7730_SETTLE_GIVES_UNKNOWN_TOKEN;
  *verdict = result;
  memzero(line, sizeof(line));
  if (!ok) body[0] = '\0';
  return ok;
}
