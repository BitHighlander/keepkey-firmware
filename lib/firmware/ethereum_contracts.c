/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2022 markrypto
 * Copyright (C) 2019 ShapeShift
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

#include "keepkey/firmware/ethereum_contracts.h"

#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_contracts/saproxy.h"
#include "keepkey/firmware/ethereum_contracts/thortx.h"
#include "keepkey/firmware/ethereum_contracts/zxappliquid.h"
#include "keepkey/firmware/ethereum_contracts/zxliquidtx.h"
#include "keepkey/firmware/ethereum_contracts/zxswap.h"

bool zx_isExchangeProxyChain(uint32_t chain_id) {
  /* Optimism is deliberately absent: 0x deploys a DIFFERENT Exchange Proxy
     there (0xdef1abe32c034e558cdd535791643c58a13acc10), so allowing chain 10
     for ZXSWAP_ADDRESS would let the 0x decoder narrate an unrelated contract —
     exactly the confusion the chain scoping exists to prevent. Verified against
     0xProject/protocol packages/contract-addresses/addresses.json. */
  switch (chain_id) {
    case 1:     /* Ethereum   */
    case 56:    /* BNB Chain  */
    case 137:   /* Polygon    */
    case 8453:  /* Base       */
    case 42161: /* Arbitrum   */
    case 43114: /* Avalanche  */
      return true;
    default:
      /* Including chain_id 0 / absent, which callers treat as unknown. */
      return false;
  }
}

bool zx_tokenLabelsThisChain(uint32_t chain_id, const TokenType* token) {
  if (token == NULL || token == UnknownToken) return false;
  return token->chain_id == chain_id;
}

bool ethereum_contractHandled(uint32_t data_total, const EthereumSignTx* msg,
                              const HDNode* node) {
  (void)node;

  /* Only fully received calldata is eligible for specialized review;
   * streamed tails use the AdvancedMode-gated raw-data path. */
  if (data_total != msg->data_initial_chunk.size) return false;

  /* Predicates read selectors from a reused buffer; require four live bytes. */
  if (msg->data_initial_chunk.size < 4) return false;

  if (sa_isWithdrawFromSalary(msg)) return true;
  if (zx_isZxSwap(msg)) return true;
  if (zx_isZxLiquidTx(msg)) return true;
  if (zx_isZxApproveLiquid(msg)) return true;

  if (thor_isThorchainTx(msg)) return true;

  return false;
}

bool ethereum_contractConfirmed(uint32_t data_total, const EthereumSignTx* msg,
                                const HDNode* node) {
  /* Keep the same selector bound as ethereum_contractHandled(). */
  if (msg->data_initial_chunk.size < 4) return false;

  if (sa_isWithdrawFromSalary(msg))
    return sa_confirmWithdrawFromSalary(data_total, msg);

  if (zx_isZxSwap(msg)) return zx_confirmZxSwap(data_total, msg);

  if (zx_isZxLiquidTx(msg)) return zx_confirmZxLiquidTx(data_total, msg, node);

  if (zx_isZxApproveLiquid(msg))
    return zx_confirmApproveLiquidity(data_total, msg);

  if (thor_isThorchainTx(msg)) return thor_confirmThorTx(data_total, msg);

  return false;
}
