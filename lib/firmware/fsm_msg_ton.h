/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2025 KeepKey
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

void fsm_msgTonGetAddress(const TonGetAddress *msg) {
    /*
     * SECURITY: TON v4r2 address = SHA256(StateInit(code_cell, data_cell))
     * where code_cell is the v4r2 wallet contract code and data_cell contains
     * the public key, wallet_id, seqno=0, and empty plugin dict.
     *
     * The previous implementation computed sha256(pubkey) which produces a
     * WRONG address. A hardware wallet must NEVER return an incorrect address
     * -- funds sent to a wrong address are permanently lost.
     *
     * Full on-device v4r2 StateInit derivation requires hardcoding the wallet
     * code cell hash and building the data cell + StateInit cell with proper
     * TVM cell representation. Until that is implemented, we fail safely and
     * let the host compute the address (the vault adapter's tonV4R2Address()
     * already does this correctly).
     *
     * Reference: Keystone firmware derives TON addresses by including the full
     * v4r2 wallet code BoC and computing StateInit::create_account_id().
     * See: keystone3-firmware/rust/apps/ton/src/vendor/wallet/mod.rs
     */
    (void)msg;
    fsm_sendFailure(FailureType_Failure_DataError,
                    _("TON address derivation not supported on-device. "
                      "Use host-side v4r2 address computation."));
    layoutHome();
}

void fsm_msgTonSignTx(TonSignTx *msg) {
    RESP_INIT(TonSignedTx);

    CHECK_INITIALIZED
    CHECK_PIN

    HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                      msg->address_n_count, NULL);
    if (!node) return;
    hdnode_fill_public_key(node);

    bool is_structured = msg->has_destination && msg->has_ton_amount &&
                         msg->has_seqno;
    bool is_legacy = msg->has_raw_tx && msg->raw_tx.size > 0;

    if (!is_structured && !is_legacy) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Must provide destination+amount+seqno or raw_tx"));
        layoutHome();
        return;
    }

    if (is_legacy && !is_structured) {
        /* ---- LEGACY BLIND-SIGN MODE ---- */
        if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                     "Blind Sign",
                     "Sign unverified TON transaction? "
                     "The device cannot verify the contents.")) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            _("Signing cancelled"));
            layoutHome();
            return;
        }

        /* Show unverified display hints if provided */
        if (msg->has_destination && msg->has_ton_amount) {
            char amount_str[32];
            ton_formatAmount(amount_str, sizeof(amount_str), msg->ton_amount);
            if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         "Unverified",
                         "Send %s to %s? (UNVERIFIED)",
                         amount_str, msg->destination)) {
                memzero(node, sizeof(*node));
                fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                _("Signing cancelled"));
                layoutHome();
                return;
            }
        }
    } else {
        /* ---- STRUCTURED MODE ---- */
        char amount_str[32];
        ton_formatAmount(amount_str, sizeof(amount_str), msg->ton_amount);

        /* Parse destination to extract bounce flag from address */
        TonParsedAddress dest_parsed;
        if (!ton_parseDestination(msg->destination, &dest_parsed)) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_DataError,
                            _("Invalid TON destination address"));
            layoutHome();
            return;
        }

        /* Truncate destination for display */
        char dest_short[20];
        size_t dlen = strlen(msg->destination);
        if (dlen > 16) {
            memcpy(dest_short, msg->destination, 6);
            memcpy(dest_short + 6, "...", 3);
            memcpy(dest_short + 9, msg->destination + dlen - 6, 6);
            dest_short[15] = '\0';
        } else {
            strncpy(dest_short, msg->destination, sizeof(dest_short) - 1);
            dest_short[sizeof(dest_short) - 1] = '\0';
        }

        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                     "Send TON",
                     "Send %s to %s?", amount_str, dest_short)) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            _("Signing cancelled"));
            layoutHome();
            return;
        }

        /* Show bounce status derived from the destination address */
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                     "Address Type",
                     "%s",
                     dest_parsed.bounceable ? "Bounceable: Yes"
                                            : "Non-bounceable address")) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            _("Signing cancelled"));
            layoutHome();
            return;
        }

        /* Show comment if present */
        if (msg->has_comment && msg->comment[0] != '\0') {
            if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         "Comment",
                         "Memo: %.60s%s", msg->comment,
                         strlen(msg->comment) > 60 ? "..." : "")) {
                memzero(node, sizeof(*node));
                fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                _("Signing cancelled"));
                layoutHome();
                return;
            }
        }
    }

    /* Final confirmation */
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                 "TON",
                 "Sign this TON transaction?")) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
    }

    if (!ton_signTx(node, msg, resp)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Signing failed"));
        layoutHome();
        return;
    }

    memzero(node, sizeof(*node));
    msg_write(MessageType_MessageType_TonSignedTx, resp);
    layoutHome();
}
