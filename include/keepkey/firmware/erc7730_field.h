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

/* amount: the chain's native asset, rendered as the ordinary review renders
 * the transaction value. */
bool erc7730_format_native_amount(const uint8_t amount[32], uint64_t chain_id,
                                  char* output, size_t output_size);

/* nftName: the token id and the collection address. No registry names the
 * collection on device, so its address is always shown. */
bool erc7730_format_nft(const uint8_t token_id[32],
                        const uint8_t collection[20], char* output,
                        size_t output_size);

/* date: "YYYY-MM-DD HH:MM:SS UTC" and the raw seconds for a timestamp, or
 * "Block N" for a block height. A value outside the years 1970-9999 is shown
 * as its raw integer, marked "not a date"; it is never refused. */
bool erc7730_format_date(const uint8_t value[32], bool block_height,
                         char* output, size_t output_size);

/* duration: "Nd Nh Nm Ns" and the raw seconds. */
bool erc7730_format_duration(const uint8_t value[32], char* output,
                             size_t output_size);

/* unit: the value scaled by `decimals` with the signer's base, already
 * escaped, then the raw integer when scaling changed it. */
bool erc7730_format_unit(const uint8_t value[32], uint8_t decimals,
                         const char* base, char* output, size_t output_size);

/* enum: "label (value)", or "value (unmapped)" when no entry matches. Both
 * inputs are already rendered; the label is the signer's claim. */
bool erc7730_format_enum(const char* value, const char* label, char* output,
                         size_t output_size);

#endif
