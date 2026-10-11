#ifndef KEEPKEY_FIRMWARE_ERC7730_FORMAT_H
#define KEEPKEY_FIRMWARE_ERC7730_FORMAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/erc7730_abi_stream.h"

/* Widest rendering of one capture: a string whose every byte is escaped to
 * four characters. This also covers "0x" plus the hex of a full capture. */
#define ERC7730_FORMATTED_VALUE_MAX (4u * ERC7730_ABI_CAPTURE_MAX)

/* Render untrusted text one-to-one on the OLED (the font merges bytes >= 0x80
 * and hides controls; a line wrap or page start drops a space): '\' is
 * doubled and every byte outside 0x21-0x7e, space included, becomes \xNN
 * (lowercase hex). Per-byte and prefix-free, so distinct inputs draw distinct
 * screens however they wrap, page or split. Returns false, leaving "", if it
 * does not fit. */
bool erc7730_format_text(const uint8_t* bytes, size_t length, char* output,
                         size_t output_size);

/* Render signer-authored text: a field label, intent or intent text part,
 * enum label, unit, token message or signed constant string, all taken from
 * the definition the user-loaded signer signed. As erc7730_format_text(),
 * except that a single interior space (neither the first nor the last byte,
 * no space beside it) is copied as is; edge and doubled spaces are still
 * \x20. Labels may keep readable spaces because the signer authored and
 * signed them, they carry no transaction data, and every value they
 * introduce is escaped on its own with erc7730_format_text() (an
 * interpolated intent shows its values as separate parts). Never use this
 * for bytes captured from the calldata or typed data being signed. */
bool erc7730_format_label(const uint8_t* bytes, size_t length, char* output,
                          size_t output_size);

bool erc7730_format_raw(const Erc7730AbiProgram* program,
                        const Erc7730AbiCapture* capture, char* output,
                        size_t output_size);
bool erc7730_format_amount(const Erc7730AbiProgram* program,
                           const Erc7730AbiCapture* capture, uint8_t decimals,
                           const char* ticker, char* output,
                           size_t output_size);

#endif
