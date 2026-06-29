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

#include "keepkey/firmware/ethereum.h"  // completes EthereumSignTx (msg fields)
#include "keepkey/firmware/ethereum_contracts/saproxy.h"
#include "keepkey/firmware/ethereum_contracts/thortx.h"
#include "keepkey/firmware/ethereum_contracts/zxappliquid.h"
#include "keepkey/firmware/ethereum_contracts/zxliquidtx.h"
#include "keepkey/firmware/ethereum_contracts/zxtransERC20.h"
#include "keepkey/firmware/ethereum_contracts/zxswap.h"
#include "keepkey/firmware/ethereum_contracts/makerdao.h"

bool ethereum_contractHandled(uint32_t data_total, const EthereumSignTx* msg,
                              const HDNode* node) {
  (void)node;

  /* Clear-sign handlers parse their fields from data_initial_chunk and confirm
   * them BEFORE the device receives any further streamed EthereumTxAck chunks.
   * Only classify a tx as a known contract call when:
   *   - the ENTIRE calldata is already in the initial chunk
   *     (data_total == data_initial_chunk.size, so data_left == 0 and no extra,
   *     unshown bytes get appended to the signed pre-image afterwards), and
   *   - it is a call to a contract (to.size == 20), never a contract CREATE
   *     (to.size == 0), which must fall through to the deploy screen.
   * Without this a host could display a benign clear-sign summary and then
   * stream additional signed calldata the user never saw, or match a handler
   * selector on an empty-to payload to suppress the deploy confirmation. */
  if (data_total != msg->data_initial_chunk.size || msg->to.size != 20) {
    return false;
  }

  if (sa_isWithdrawFromSalary(msg)) return true;
  if (zx_isZxTransformERC20(msg)) return true;
  if (zx_isZxSwap(msg)) return true;
  if (zx_isZxLiquidTx(msg)) return true;
  if (zx_isZxApproveLiquid(msg)) return true;

  if (thor_isMayachainTx(msg)) return true;
  if (thor_isThorchainTx(msg)) return true;

  if (makerdao_isMakerDAO(data_total, msg)) return true;

  return false;
}

bool ethereum_contractConfirmed(uint32_t data_total, const EthereumSignTx* msg,
                                const HDNode* node) {
  (void)node;

  if (sa_isWithdrawFromSalary(msg))
    return sa_confirmWithdrawFromSalary(data_total, msg);

  if (zx_isZxTransformERC20(msg))
    return zx_confirmZxTransERC20(data_total, msg);

  if (zx_isZxSwap(msg)) return zx_confirmZxSwap(data_total, msg);

  if (zx_isZxLiquidTx(msg)) return zx_confirmZxLiquidTx(data_total, msg);

  if (zx_isZxApproveLiquid(msg))
    return zx_confirmApproveLiquidity(data_total, msg);

  if (thor_isMayachainTx(msg)) return thor_confirmMayaTx(data_total, msg);
  if (thor_isThorchainTx(msg)) return thor_confirmThorTx(data_total, msg);

  if (makerdao_isMakerDAO(data_total, msg))
    return makerdao_confirmMakerDAO(data_total, msg);

  return false;
}
