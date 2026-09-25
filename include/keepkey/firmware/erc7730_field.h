#ifndef KEEPKEY_FIRMWARE_ERC7730_FIELD_H
#define KEEPKEY_FIRMWARE_ERC7730_FIELD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bodies for the ERC-7730 formatters beyond raw. Every fact that names an
 * asset comes from firmware tables; the signed program only says which bytes
 * are the amount and which are the token. */

/* An address, EIP-55 checksummed, followed by "(this wallet)" on its own line
 * when it is the signing account. A name is never shown instead of it. */
bool erc7730_format_address(const uint8_t address[20], bool this_wallet,
                            char* output, size_t output_size);

/* A token amount. `native` means the program's alias set named `token` as the
 * chain's native asset; otherwise decimals and ticker come only from the
 * firmware token table for `chain_id`. A token the table does not know is
 * shown as the exact integer followed by "unknown token" and its address.
 * `message`, already escaped, is shown above the amount, never instead of it.
 */
bool erc7730_format_token_amount(const uint8_t amount[32],
                                 const uint8_t token[20], bool native,
                                 uint64_t chain_id, const char* message,
                                 char* output, size_t output_size);

#endif
