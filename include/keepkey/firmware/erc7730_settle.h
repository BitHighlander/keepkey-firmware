#ifndef KEEPKEY_FIRMWARE_ERC7730_SETTLE_H
#define KEEPKEY_FIRMWARE_ERC7730_SETTLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* What the signer of a typed-data order receives (7.17).
 *
 * A definition opts in with program header flag ERC7730_PROGRAM_FLAG_SETTLEMENT
 * and marks the fields that matter with ERC7730_FORMATTER_FLAG_SETTLE_*: GIVE
 * on a field of every item the order gives away, and TYPE, ID, AMOUNT and TO
 * on the fields of every item it pays out (Seaport: offer[] and
 * consideration[]). As the review shows those fields, the device keeps what
 * is paid to the signing address it derived itself; after the definition's
 * last field it shows the totals on a screen the definition cannot change or
 * skip, and a warning when this wallet receives nothing, or only what the
 * device cannot value (an unknown token, an NFT, dust) for items it gives.
 *
 * TYPE is a Seaport item type: 0 the native coin, 1 an ERC-20, 2 ERC-721,
 * 3 ERC-1155, 4 and 5 the same "by criteria". Without TYPE an item is the
 * native coin when its token is the definition's native alias, else an
 * ERC-20. An item amount's smaller of its start and end values counts.
 *
 * An item whose TYPE was shown is also shown as Seaport moves it: the AMOUNT
 * of an NFT item (types 2 to 5) reads as its identifier and count, never as
 * an amount of its token, because Seaport moves an ERC-721 item by its
 * identifier whatever its token is (an ERC-721 item naming WETH moves
 * "identifier" wei of WETH). An NFT item whose token the firmware's table
 * lists as a coin makes the last screen a warning. An item with a TYPE or an
 * AMOUNT and no TO is one the order gives away, as with GIVE. */

#define ERC7730_SETTLE_NATIVE 0u
#define ERC7730_SETTLE_ERC20 1u
#define ERC7730_SETTLE_ERC721 2u
#define ERC7730_SETTLE_ERC1155 3u
#define ERC7730_SETTLE_CRITERIA_MAX 5u
/* Items paid to the signer this many distinct (kind, token, id) at most are
 * listed; more are summed up in one line and never valued. */
#define ERC7730_SETTLE_SLOTS 2u

typedef struct {
  uint8_t amount[32]; /* big-endian */
  uint8_t id[32];     /* an NFT's identifier or criteria; 0 for coins */
  uint8_t token[20];
  uint8_t kind;
} Erc7730SettleItem;

typedef struct {
  Erc7730SettleItem item; /* the item being reviewed */
  Erc7730SettleItem received[ERC7730_SETTLE_SLOTS];
  uint8_t received_count;
  uint8_t item_seen; /* ERC7730_FORMATTER_FLAG_SETTLE_* this item showed */
  bool item_native;
  bool item_to_signer;
  bool item_unreadable;
  bool gives;
  bool received_any;
  bool unlisted; /* paid to the signer, not in received[] */
  /* An NFT item names this token of the firmware's table, or NULL. */
  const char* coin_as_nft;
} Erc7730Settle;

typedef enum {
  ERC7730_SETTLE_CALM = 0,
  ERC7730_SETTLE_NOTHING,     /* nothing is paid to this wallet */
  ERC7730_SETTLE_UNVALUED,    /* only what the device cannot value */
  ERC7730_SETTLE_COIN_AS_NFT, /* an NFT item names a coin's contract */
} Erc7730SettleVerdict;

/* One shown field's value, by the SETTLE flag it carries. A word is a whole
 * 32-byte ABI word; `native` says the definition names `token` as the chain's
 * native coin. */
void erc7730_settle_give(Erc7730Settle* settle);
void erc7730_settle_type(Erc7730Settle* settle, const uint8_t word[32]);
void erc7730_settle_id(Erc7730Settle* settle, const uint8_t word[32]);
void erc7730_settle_amount(Erc7730Settle* settle, const uint8_t amount[32],
                           const uint8_t token[20], bool native);
void erc7730_settle_to(Erc7730Settle* settle, bool signer);
/* A value the device could not read where a role expected a word. */
void erc7730_settle_unreadable(Erc7730Settle* settle);
/* True when the item being reviewed is a coin, or showed no TYPE: its
 * AMOUNT is a token amount. */
bool erc7730_settle_item_is_coin(const Erc7730Settle* settle);
/* An AMOUNT of an NFT item, as Seaport moves it: "NFT ID 7", "4 of NFT ID
 * 7" or "1 NFT by criteria", then the collection. False (and `out` empty)
 * for an item type beyond Seaport's, or an ERC-721 or ERC-1155 item whose ID
 * was not shown first. */
bool erc7730_settle_format_nft_amount(Erc7730Settle* settle,
                                      const uint8_t amount[32],
                                      const uint8_t token[20],
                                      uint64_t chain_id, char* out,
                                      size_t size);
/* The item's last field was shown (the end of an iteration element, or of
 * the program): keep it when it is paid to the signer. */
void erc7730_settle_end_item(Erc7730Settle* settle);

/* The screen after the definition's last field: the verdict, which picks
 * its title, and its body, the items this wallet receives, one per line. */
bool erc7730_settle_review(const Erc7730Settle* settle, uint64_t chain_id,
                           Erc7730SettleVerdict* verdict, char* body,
                           size_t body_size);

#endif
