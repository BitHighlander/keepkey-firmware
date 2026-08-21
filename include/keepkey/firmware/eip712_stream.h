/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
 *
 * Portions derived from OneKey firmware-classic1s
 * (legacy/firmware/ethereum_typed_data.h, commit 885e51d3), which is
 * LGPL-3.0-or-later and itself carries the Trezor copyright chain
 * (Alex Beregszaszi, Pavol Rusnak, Jochen Hoenicke). The encodeData rules,
 * the value validation and the encodeType dependency closure follow that
 * implementation; the memory design does not -- see eip712_stream.c.
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef KEEPKEY_FIRMWARE_EIP712_STREAM_H
#define KEEPKEY_FIRMWARE_EIP712_STREAM_H

#include <stdbool.h>
#include <stdint.h>

#include "messages-ethereum.pb.h"

/* Longest Solidity type string we will render: "uint256[10][10][10][10]" and
 * friends, plus a struct name at EthereumTypedDataStructRequest.name's 80. */
#define EIP712_MAX_TYPE_NAME 112

/* How deep the value walk may nest: message -> struct -> array -> struct ...
 * Every level costs one frame on the C stack, so this is the recursion bound
 * as well as the semantic one. EIP712_MAX_DEPTH is checked BEFORE descending,
 * never after. */
#define EIP712_MAX_DEPTH 5

/* Slots in the shared encoding pool. Each open container holds one 32-byte
 * slot per member encoded so far; when it completes, those collapse to a
 * single 32-byte digest written into the parent's next slot.
 *
 * This is the whole memory argument. A SHA3_CTX is ~400 bytes, so keeping one
 * open per container costs 2,000 bytes at depth 5 -- more than the entire SRAM
 * reserve above the linker floor. Buffering 32-byte encodings instead costs
 * EIP712_MAX_SLOTS * 32, and only ONE SHA3_CTX is ever live: the one folding a
 * finished container. */
#define EIP712_MAX_SLOTS 24

/* Widest single leaf the device will absorb. A dynamic `bytes` or `string` is
 * hashed, not stored, so this bounds one chunk rather than the whole value. */
#define EIP712_MAX_LEAF 1024

/* Render a field's Solidity type exactly as encodeType must spell it --
 * "uint256", "bytes32", "Person[3]", "int16[2][][4]". This string is part of
 * typeHash, so a divergence here is a divergence in the signature.
 * Returns false if the type is not expressible or would overflow `out`. */
bool eip712_type_name(const EthereumTypedDataStructAck_EthereumFieldType *field,
                      char *out, size_t out_len);

/* Encode one validated leaf into exactly 32 bytes, per EIP-712 encodeData.
 * `value`/`value_len` are the raw big-endian bytes from the host. */
bool eip712_encode_leaf(
    const EthereumTypedDataStructAck_EthereumFieldType *field,
    const uint8_t *value, uint16_t value_len, uint8_t out[32]);

/* Reject a leaf whose bytes cannot mean what its declared type says.
 * Runs BEFORE encoding and before display, so nothing unvalidated is shown. */
bool eip712_validate_leaf(
    const EthereumTypedDataStructAck_EthereumFieldType *field,
    const uint8_t *value, uint16_t value_len);

#endif
