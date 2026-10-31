#ifndef KEEPKEY_FIRMWARE_ERC7730_SETTLE_H
#define KEEPKEY_FIRMWARE_ERC7730_SETTLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* What the signer of a typed-data order receives (7.17).
 *
 * A definition opts in with program header flag ERC7730_PROGRAM_FLAG_SETTLEMENT
 * and marks the fields of every item of the order with
 * ERC7730_FORMATTER_FLAG_SETTLE_*: its TYPE, ID and AMOUNT (start and end)
 * and, for an item paid out, its recipient TO (Seaport: offer[] and
 * consideration[]). An item without TO is one the order gives away. As the
 * review shows those fields, the device keeps what is paid to the signing
 * address it derived itself and the coins it gives. After the definition's
 * last field it shows what this wallet receives, net of what it gives of the
 * same coin (kind and token), on a screen the definition cannot change or
 * skip. An NFT is never valued, so one given and paid back is listed. That
 * screen is a warning when this wallet receives nothing net, or only what the
 * device cannot value (an unknown token, an NFT, dust) for items it gives, or
 * when it gives an item the device could not read.
 *
 * TYPE is a Seaport item type: 0 the native coin, 1 an ERC-20, 2 ERC-721,
 * 3 ERC-1155, 4 and 5 the same "by criteria". An item is read only when its
 * TYPE comes before its AMOUNT, and an NFT item's ID too. A received item
 * counts the smaller of its start and end amounts, a given item the larger.
 *
 * An item is shown as Seaport moves it: the AMOUNT of an NFT item (types 2
 * to 5) reads as its identifier and count, never as an amount of its token,
 * because Seaport moves an ERC-721 item by its identifier whatever its token
 * is (an ERC-721 item naming WETH moves "identifier" wei of WETH). An NFT
 * item whose token the firmware's table lists as a coin makes the last
 * screen a warning.
 *
 * The other way round, Seaport moves an ERC-20 item with transferFrom(from,
 * to, amount), which an ERC-721 contract also answers: an ERC-20 item naming
 * an NFT collection gives the NFT whose ID is the amount. So an ERC-20 the
 * order gives away that the table does not list on the chain makes the last
 * screen a warning. */

#define ERC7730_SETTLE_NATIVE 0u
#define ERC7730_SETTLE_ERC20 1u
#define ERC7730_SETTLE_ERC721 2u
#define ERC7730_SETTLE_ERC1155 3u
#define ERC7730_SETTLE_CRITERIA_MAX 5u
/* Items paid to the signer this many distinct (kind, token, id) at most are
 * listed; more are summed up in one line and never valued. As many distinct
 * coins given are kept to net against them; more make the last screen a
 * warning. */
#define ERC7730_SETTLE_SLOTS 2u

typedef struct {
  uint8_t amount[32]; /* big-endian */
  uint8_t id[32];     /* an NFT's identifier or criteria; 0 for coins */
  uint8_t token[20];
  uint8_t kind;
} Erc7730SettleItem;

typedef struct {
  Erc7730SettleItem item; /* the item being reviewed */
  uint8_t item_max[32];   /* the larger of the item's two amounts */
  Erc7730SettleItem received[ERC7730_SETTLE_SLOTS];
  Erc7730SettleItem given[ERC7730_SETTLE_SLOTS]; /* coins only */
  uint8_t received_count;
  uint8_t given_count;
  uint8_t item_seen; /* ERC7730_FORMATTER_FLAG_SETTLE_* this item showed */
  bool item_native;
  bool item_to_signer;
  bool item_unreadable;
  bool gives;
  bool given_unread; /* a given item not read, or not kept */
  bool received_any;
  bool unlisted; /* paid to the signer, not in received[] */
  /* An item given away is an ERC-20 the table does not list on the chain. */
  bool gives_unknown_token;
  /* An NFT item names this token of the firmware's table, or NULL. */
  const char* coin_as_nft;
} Erc7730Settle;

typedef enum {
  ERC7730_SETTLE_CALM = 0,
  ERC7730_SETTLE_NOTHING,             /* nothing is paid to this wallet */
  ERC7730_SETTLE_UNVALUED,            /* only what the device cannot value */
  ERC7730_SETTLE_GIVEN_UNREAD,        /* a given item the device did not read */
  ERC7730_SETTLE_COIN_AS_NFT,         /* an NFT item names a coin's contract */
  ERC7730_SETTLE_GIVES_UNKNOWN_TOKEN, /* gives an ERC-20 the table lacks */
} Erc7730SettleVerdict;

/* One shown field's value, by the SETTLE flag it carries. A word is a whole
 * 32-byte ABI word; `native` says the definition names `token` as the chain's
 * native coin. */
void erc7730_settle_type(Erc7730Settle* settle, const uint8_t word[32]);
void erc7730_settle_id(Erc7730Settle* settle, const uint8_t word[32]);
void erc7730_settle_amount(Erc7730Settle* settle, const uint8_t amount[32],
                           const uint8_t token[20], bool native);
void erc7730_settle_to(Erc7730Settle* settle, bool signer);
/* A value the device could not read where a role expected a word. */
void erc7730_settle_unreadable(Erc7730Settle* settle);
/* True when the item being reviewed is a coin, or showed no TYPE (it is
 * then not read): its AMOUNT is a token amount. */
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
 * the program): keep it when it is paid to the signer or given. */
void erc7730_settle_end_item(Erc7730Settle* settle, uint64_t chain_id);

/* The screen after the definition's last field: the verdict, which picks
 * its title, and its body, the items this wallet receives net of what it
 * gives, one per line. */
bool erc7730_settle_review(const Erc7730Settle* settle, uint64_t chain_id,
                           Erc7730SettleVerdict* verdict, char* body,
                           size_t body_size);

#endif
