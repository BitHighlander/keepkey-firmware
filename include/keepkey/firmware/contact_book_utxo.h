#ifndef KEEPKEY_FIRMWARE_CONTACT_BOOK_UTXO_H
#define KEEPKEY_FIRMWARE_CONTACT_BOOK_UTXO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/coins.h"
#include "types.pb.h"

/* Certified contacts for SignTx coins (CONTACT_BOOK_DEST_UTXO_SCRIPT): the
 * exact output script, bound to one coin by its CAIP-2 network. See
 * docs/design/certified-contacts-utxo.md. */

/* The CAIP-2 network KeepKey Desktop names `coin` by, or NULL. */
const char* contact_book_utxo_network(const CoinType* coin);

/* The coin `network` names in this build, or NULL. */
const CoinType* contact_book_utxo_coin(const char* network);

/* Render a standard output script (P2PKH, P2SH, P2WPKH, P2WSH, P2TR) as
 * `coin`'s address, in the form the send screen shows it. False for any other
 * script, or one the coin cannot encode. */
bool contact_book_utxo_address(const CoinType* coin, const uint8_t* script,
                               size_t script_len, char* out, size_t out_len);

/* Verify `proof` and keep it only if it is a UTXO_SCRIPT contact for `coin`.
 * Anything else is dropped: the transaction is then reviewed as usual. */
bool contact_book_utxo_accept_proof(const CoinType* coin, const uint8_t* proof,
                                    size_t proof_len,
                                    const uint8_t expected_pubkey[33]);

/* The certified name for an output, or NULL. Only an output given by address
 * (never change or a transfer to the device's own account), never OP_RETURN,
 * and only when its compiled script and coin are the proof's. */
const char* contact_book_utxo_label(const CoinType* coin,
                                    const TxOutputType* output,
                                    const uint8_t* script, size_t script_len);

#endif
