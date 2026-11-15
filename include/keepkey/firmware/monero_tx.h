/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
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

#ifndef KEEPKEY_FIRMWARE_MONERO_TX_H
#define KEEPKEY_FIRMWARE_MONERO_TX_H

/* Monero streamed transaction signing (wire messages 1810-1825). Full builds
 * only (MONERO_SIGNING).
 *
 *   review -> begin -> set_input x n -> input_vini x n (key images strictly
 *   decreasing) -> all_inputs_set -> set_output x 2 (the second proves BP+)
 *   -> all_out_set -> sign_input x n (vini order) -> final
 *
 * The device builds the transaction itself, exactly as Monero Core's
 * construct_tx_with_tx_key does for RingCT type 6 (CLSAG + Bulletproofs+,
 * view tags, hard fork 16 or later): the tx prefix, the tx extra, every
 * output key, view tag, commitment and encrypted amount, the range proof and
 * every CLSAG. The host stores only public pieces, each with a device MAC.
 *
 * SECRETS. The spend and view keys, the per-transaction master K, the
 * transaction secret r, the output masks and the pseudo-output masks never
 * leave the device. Everything secret is derived from K:
 *
 *   K     = Keccak(pad32("KKXMR-K") || b || T || rng32)   (xmr_hedge_key)
 *   r     = Hs("KKXMR-r" || K)
 *   Kmac  = Keccak("KKXMR-mac" || K), Kopen = Keccak("KKXMR-open" || K)
 *   p_i   = Hs("KKXMR-pa" || K || i)        pseudo-output mask of input i
 *   tag   = HMAC-SHA256(Kmac, purpose[12] || le32(index) || canonical data)
 *
 * T is the digest of the reviewed plan. K is fresh for every begin, so no
 * MAC from another session ever verifies. The CLSAGs are returned encrypted
 * (ChaCha20-Poly1305 under Kopen, nonce = position); Kopen is released only
 * by final, after every input was signed in order.
 *
 * FAILURE. Every function that fails ends the session and wipes it; the
 * host restarts from review. There is no half state. The session lives in
 * the shared CONFIDENTIAL signing-session arena (signing_session.h, owner
 * SIGNING_SESSION_MONERO_TX) and expires MONERO_TX_SESSION_MS after begin.
 *
 * SCOPE (7.17). Exactly 2 outputs, of which exactly one is change: the
 * wallet's own (account, 0) address with the declared change amount, as the
 * device derives it. The other output is a recipient and is always shown.
 * Ring size 16, 1..64 inputs, at most one integrated destination with an
 * 8-byte payment ID. With one recipient and one change output Core never
 * needs additional tx keys, so none are produced. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/monero.h"
#include "keepkey/firmware/monero/crypto.h"
#include "messages-monero.pb.h"

#define MONERO_TX_RING_SIZE 16u
#define MONERO_TX_OUTPUTS 2u
#define MONERO_TX_MAX_INPUTS 64u
#define MONERO_TX_SESSION_MS 600000u
#define MONERO_TX_RCT_TYPE 6u
/* An integrated address is 106 characters. */
#define MONERO_TX_ADDRESS_CAPACITY 107u

/* Scratch each proving step needs, 8-byte aligned. The firmware lends
 * frame_arena (lib/board/messages.c); both fit its 12 KiB floor. */
#define MONERO_TX_BPP_SCRATCH_BYTES XMR_BPP_WORKSPACE_BYTES
#define MONERO_TX_CLSAG_SCRATCH_BYTES \
  (XMR_CLSAG_WORKSPACE_BYTES + 2u * MONERO_TX_RING_SIZE * 32u)

typedef enum {
  MONERO_TX_OK = 0,
  MONERO_TX_ERR_STEP,         /* wrong step, or no session */
  MONERO_TX_ERR_EXPIRED,      /* session older than MONERO_TX_SESSION_MS */
  MONERO_TX_ERR_REQUEST,      /* path, network or a missing field */
  MONERO_TX_ERR_OUTPUT_COUNT, /* not exactly 2 outputs */
  MONERO_TX_ERR_RING_SIZE,    /* ring size is not 16 */
  MONERO_TX_ERR_HARD_FORK,    /* hard fork below 16 */
  MONERO_TX_ERR_RCT_TYPE,     /* range proof version is not 4 (BP+) */
  MONERO_TX_ERR_INPUT_COUNT,  /* not 1..64 inputs */
  MONERO_TX_ERR_PAYMENT_ID,   /* payment ID is not 8 bytes, or unpaired */
  MONERO_TX_ERR_INTEGRATED,   /* more than one integrated destination */
  MONERO_TX_ERR_POINT,        /* a key is not a canonical prime-order point */
  MONERO_TX_ERR_SCALAR,       /* a scalar is not canonical */
  MONERO_TX_ERR_CHANGE,       /* no output is the wallet's own change */
  MONERO_TX_ERR_AMOUNT,       /* amounts overflow 64 bits */
  MONERO_TX_ERR_RING,         /* ring unsorted, duplicated or malformed */
  MONERO_TX_ERR_NOT_OWNED,    /* the real output is not this wallet's */
  MONERO_TX_ERR_COMMITMENT,   /* amount and mask do not open the commitment */
  MONERO_TX_ERR_MAC,          /* host-held state was changed or replayed */
  MONERO_TX_ERR_ORDER,        /* key images out of order, or input repeated */
  MONERO_TX_ERR_BALANCE,      /* inputs != outputs + fee */
  MONERO_TX_ERR_APPROVAL,     /* the plan differs from the reviewed one */
  MONERO_TX_ERR_PROOF,        /* proving failed (RNG) or was cancelled */
  MONERO_TX_ERR_INTERNAL,
} MoneroTxResult;

/* A short reason for a Failure message. Never NULL. */
const char* monero_tx_result_text(MoneroTxResult result);

typedef struct {
  uint64_t amount;
  bool is_change; /* the device's own classification, never a host label */
  bool is_subaddress;
  bool is_integrated;
  /* Re-encoded by the device from the keys, the network and the payment ID. */
  char address[MONERO_TX_ADDRESS_CAPACITY];
} MoneroTxReviewOutput;

typedef struct {
  uint32_t network;
  uint32_t account;
  uint32_t num_inputs;
  uint64_t fee;
  uint64_t total; /* every recipient amount plus the fee */
  uint64_t unlock_time;
  bool has_payment_id;
  uint8_t payment_id[8];
  MoneroTxReviewOutput outputs[MONERO_TX_OUTPUTS];
  uint8_t digest[32]; /* binds begin to exactly this review */
} MoneroTxReview;

bool monero_tx_active(void);

/* Validates the plan, classifies the outputs and fills what the user must
 * see. Opens no session and keeps no state. */
MoneroTxResult monero_tx_review(const uint8_t node_key[32],
                                const MoneroTxInitRequest* request,
                                MoneroTxReview* review);

/* Opens the session for the plan whose review digest the user approved. */
MoneroTxResult monero_tx_begin(const uint8_t node_key[32],
                               const MoneroTxInitRequest* request,
                               const uint8_t approved_digest[32],
                               MoneroTxInitAck* ack);

MoneroTxResult monero_tx_set_input(const MoneroTxSetInputRequest* request,
                                   MoneroTxSetInputAck* ack);
MoneroTxResult monero_tx_input_vini(const MoneroTxInputViniRequest* request);
MoneroTxResult monero_tx_all_inputs_set(void);

/* True when the next set_output proves the range proof (the long step). */
bool monero_tx_next_output_proves(void);

/* scratch: MONERO_TX_BPP_SCRATCH_BYTES, used only by the proving output.
 * The progress callback follows the abort contract in monero/crypto.h: when
 * it returns false this function never touches scratch again. */
MoneroTxResult monero_tx_set_output(const MoneroTxSetOutputRequest* request,
                                    MoneroTxSetOutputAck* ack, void* scratch,
                                    size_t scratch_size,
                                    xmr_progress_fn progress,
                                    void* progress_ctx);
MoneroTxResult monero_tx_all_out_set(MoneroTxAllOutSetAck* ack);

/* scratch: MONERO_TX_CLSAG_SCRATCH_BYTES; same abort contract. */
MoneroTxResult monero_tx_sign_input(const MoneroTxSignInputRequest* request,
                                    MoneroTxSignInputAck* ack, void* scratch,
                                    size_t scratch_size,
                                    xmr_progress_fn progress,
                                    void* progress_ctx);
MoneroTxResult monero_tx_final(MoneroTxFinalAck* ack);

/* Inputs and position, for the progress display. False without a session. */
bool monero_tx_progress(uint32_t* inputs, uint32_t* signed_inputs);

#endif
