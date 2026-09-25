#ifndef KEEPKEY_FIRMWARE_ERC7730_FORMAT_H
#define KEEPKEY_FIRMWARE_ERC7730_FORMAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/erc7730_abi_stream.h"

/* Widest rendering of one capture: a string whose every byte is escaped to
 * four characters. This also covers "0x" plus the hex of a full capture. */
#define ERC7730_FORMATTED_VALUE_MAX (4u * ERC7730_ABI_CAPTURE_MAX)

/* Render untrusted text so every byte is shown one-to-one on the OLED. The
 * font draws every byte >= 0x80 as the same glyph and the pager drops leading
 * spaces, so the raw bytes are not unambiguous on screen:
 *   - any byte 0x00-0x1f or 0x7f fails closed (returns false);
 *   - printable ASCII 0x21-0x7e is copied, except a backslash, which is
 *     doubled;
 *   - a space is copied only when it is neither the first nor the last byte
 *     and neither neighbour is a space; otherwise it is written as the four
 *     characters backslash, 'x', '2', '0';
 *   - any byte >= 0x80 is written as backslash, 'x' and two lowercase hex
 *     digits.
 * The output is NUL-terminated. Returns false, leaving "" when output_size is
 * nonzero, if the rendering does not fit. */
bool erc7730_format_text(const uint8_t* bytes, size_t length, char* output,
                         size_t output_size);

bool erc7730_format_raw(const Erc7730AbiProgram* program,
                        const Erc7730AbiCapture* capture, char* output,
                        size_t output_size);
bool erc7730_format_amount(const Erc7730AbiProgram* program,
                           const Erc7730AbiCapture* capture, uint8_t decimals,
                           const char* ticker, char* output,
                           size_t output_size);
bool erc7730_format_duration(const Erc7730AbiProgram* program,
                             const Erc7730AbiCapture* capture, char* output,
                             size_t output_size);
bool erc7730_format_timestamp(const Erc7730AbiProgram* program,
                              const Erc7730AbiCapture* capture, char* output,
                              size_t output_size);
bool erc7730_format_unit(const Erc7730AbiProgram* program,
                         const Erc7730AbiCapture* capture, uint8_t decimals,
                         const char* base, bool prefix, char* output,
                         size_t output_size);

#endif
