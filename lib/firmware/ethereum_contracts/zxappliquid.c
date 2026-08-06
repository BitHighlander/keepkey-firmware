/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2021 ShapeShift
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "keepkey/firmware/ethereum_contracts/zxappliquid.h"
#include "keepkey/firmware/ethereum_contracts/zxliquidtx.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/font.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "trezor/crypto/bignum.h"
#include "trezor/crypto/sha3.h"

bool zx_confirmApproveLiquidity(uint32_t data_total,
                                const EthereumSignTx *msg) {
  (void)data_total;
  const char *to, *tikstr, *poolstr, *allowance, *amt;
  unsigned char data[40];
  uint8_t digest[SHA3_256_DIGEST_LENGTH] = {0};
  uint8_t tokdigest[SHA3_256_DIGEST_LENGTH] = {0};
  char digestStr[2 * SHA3_256_DIGEST_LENGTH + 1], amtStr[2 * 32 + 1] = {0};
  int32_t ctr, tokctr;
  uint32_t wethord;
  const TokenType *WETH, *ttoken;

#define UNISWAP_APPROVE_CALL_SIZE (4 + 2 * 32)
#define UNISWAP_AMOUNT_TEXT_SIZE 96

static const uint8_t UNISWAP_FACTORY_ADDRESS[20] = {
    0x5c, 0x69, 0xbe, 0xe7, 0x01, 0xef, 0x81, 0x4a, 0x2b, 0x6a,
    0x3e, 0xdd, 0x4b, 0x16, 0x52, 0xcb, 0x9c, 0xc5, 0xaa, 0x6f};
static const uint8_t UNISWAP_PAIR_INIT_CODE_HASH[32] = {
    0x96, 0xe8, 0xac, 0x42, 0x77, 0x19, 0x8f, 0xf8, 0xb6, 0xf7, 0x85,
    0x47, 0x8a, 0xa9, 0xa3, 0x9f, 0x40, 0x3c, 0xb7, 0x68, 0xdd, 0x02,
    0xcb, 0xee, 0x32, 0x6c, 0x3e, 0x7d, 0xa3, 0x48, 0x84, 0x5f};
static const uint8_t WETH_MAINNET_ADDRESS[20] = {
    0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e,
    0x5c, 0x4f, 0x27, 0xea, 0xd9, 0x08, 0x3c, 0x75, 0x6c, 0xc2};

static bool tx_value_is_zero(const EthereumSignTx* msg) {
  if (!msg->has_value && msg->value.size != 0) return false;
  for (size_t i = 0; i < msg->value.size; i++) {
    if (msg->value.bytes[i] != 0) return false;
  }

  if (tokctr != -1) {
    for (ctr = 0; ctr < SHA3_256_DIGEST_LENGTH; ctr++) {
      snprintf(&digestStr[ctr * 2], 3, "%02x", digest[ctr]);
    }
    tikstr = ttoken->ticker;
    poolstr = &digestStr[12 * 2];
  } else {
    for (ctr = 0; ctr < 20; ctr++) {
      snprintf(&digestStr[ctr * 2], 3, "%02x", to[ctr]);
    }
    tikstr = "";
    poolstr = digestStr;
  }

  allowance = (char *)(msg->data_initial_chunk.bytes + 4 + 32);
  if (memcmp(allowance, (uint8_t *)&MAX_ALLOWANCE, 32) == 0) {
    amt = "full balance";
  } else {
    for (ctr = 0; ctr < 32; ctr++) {
      snprintf(&amtStr[ctr * 2], 3, "%02x", allowance[ctr]);
    }
    amt = amtStr;
  }

  const char *appStr = "uniswap approve liquidity";
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, appStr,
               "Amount: %s", amt)) {
    return false;
  }
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, appStr,
               "approve for pool %s %s", tikstr, poolstr)) {
    return false;
  }
  return true;
}

bool zx_isZxApproveLiquid(const EthereumSignTx *msg) {
  /* UNISWAP_ROUTER_ADDRESS (as ERC20 approve spender) is an Ethereum-mainnet
   * identity. See GH #431. */
  if (!msg->has_chain_id || msg->chain_id != 1) return false;
  /* approve(address,uint256) is exactly 68 bytes and has no dynamic argument.
   * Check the extent BEFORE reading the spender word at offset 16: the chunk
   * buffer keeps bytes from an earlier message past .size, so on a short
   * calldata the comparison below would be made against stale data. And a
   * longer calldata is hashed in full while only the allowance is drawn, so
   * the tail would be signed unseen -- refusing sends it to the raw-calldata
   * path instead. */
  if (msg->data_initial_chunk.size != 4 + 2 * 32) return false;
  if (memcmp(msg->data_initial_chunk.bytes, "\x09\x5e\xa7\xb3", 4) == 0)
    if (memcmp((uint8_t *)(msg->data_initial_chunk.bytes + 4 + 32 - 20),
               UNISWAP_ROUTER_ADDRESS, 20) == 0)
      return true;
  return false;
}
