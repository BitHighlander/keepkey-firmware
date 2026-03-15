/*
 * Zcash Orchard + transparent shielding FSM message handlers.
 *
 * Supports:
 *   - Shielded-only (Orchard spend authorization via RedPallas)
 *   - Hybrid shielding (transparent ECDSA + Orchard RedPallas in a single v5 tx)
 */

#include "keepkey/firmware/zcash.h"

/* ── Zcash signing session state ──────────────────────────────────────── */

static struct {
    bool active;
    uint32_t n_actions;
    uint32_t current_action;
    uint32_t branch_id;
    uint32_t address_n[8];
    uint32_t address_n_count;
    uint32_t account;
    /* Phase 3: transparent shielding */
    uint32_t n_transparent_inputs;
    uint32_t current_transparent_input;
    bool transparent_phase_done;
} zcash_signing;

/* ── ZcashSignPCZT ────────────────────────────────────────────────────── */

void fsm_msgZcashSignPCZT(const ZcashSignPCZT *msg) {
    CHECK_INITIALIZED
    CHECK_PIN

    memset(&zcash_signing, 0, sizeof(zcash_signing));
    zcash_signing.active = true;
    zcash_signing.n_actions = msg->n_actions;
    zcash_signing.current_action = 0;
    zcash_signing.branch_id = msg->has_branch_id ? msg->branch_id : 0x37519621;
    zcash_signing.account = msg->has_account ? msg->account : 0;

    /* Copy ZIP-32 derivation path */
    zcash_signing.address_n_count = msg->address_n_count;
    for (uint32_t i = 0; i < msg->address_n_count && i < 8; i++) {
        zcash_signing.address_n[i] = msg->address_n[i];
    }

    /* Phase 3: transparent inputs */
    zcash_signing.n_transparent_inputs =
        msg->has_n_transparent_inputs ? msg->n_transparent_inputs : 0;
    zcash_signing.current_transparent_input = 0;
    zcash_signing.transparent_phase_done =
        (zcash_signing.n_transparent_inputs == 0);

    /* Display confirmation */
    char amount_str[32];
    char fee_str[32];
    bn_format_amount(msg->total_amount, "ZEC", 8, amount_str, sizeof(amount_str));
    bn_format_amount(msg->fee, "ZEC", 8, fee_str, sizeof(fee_str));

    if (zcash_signing.n_transparent_inputs > 0) {
        /* Shielding transaction: transparent → Orchard */
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                     "Shield ZEC",
                     "Shield %s\nFee: %s\nto Orchard pool?",
                     amount_str, fee_str)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
            layoutHome();
            zcash_signing.active = false;
            return;
        }
        /* Request first transparent input */
        RESP_INIT(ZcashPCZTActionAck);
        resp->next_index = 0;
        msg_write(MessageType_MessageType_ZcashPCZTActionAck, resp);
    } else {
        /* Pure Orchard transaction — request first action */
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                     "Send Shielded ZEC",
                     "Send %s\nFee: %s",
                     amount_str, fee_str)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
            layoutHome();
            zcash_signing.active = false;
            return;
        }
        RESP_INIT(ZcashPCZTActionAck);
        resp->next_index = 0;
        msg_write(MessageType_MessageType_ZcashPCZTActionAck, resp);
    }
}

/* ── ZcashTransparentInput ────────────────────────────────────────────── */

void fsm_msgZcashTransparentInput(const ZcashTransparentInput *msg) {
    if (!zcash_signing.active) {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                        _("Not in Zcash signing session"));
        layoutHome();
        return;
    }

    if (zcash_signing.transparent_phase_done) {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                        _("Transparent phase already complete"));
        layoutHome();
        return;
    }

    if (msg->index != zcash_signing.current_transparent_input) {
        fsm_sendFailure(FailureType_Failure_ProcessError,
                        _("Unexpected transparent input index"));
        zcash_signing.active = false;
        layoutHome();
        return;
    }

    if (msg->sighash.size != 32) {
        fsm_sendFailure(FailureType_Failure_ProcessError,
                        _("Transparent sighash must be 32 bytes"));
        zcash_signing.active = false;
        layoutHome();
        return;
    }

    /* Derive secp256k1 key at the provided BIP44 path */
    HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                      msg->address_n_count, NULL);
    if (!node) {
        zcash_signing.active = false;
        return;
    }

    hdnode_fill_public_key(node);

    /* ECDSA sign the 32-byte sighash */
    uint8_t sig[64];
    if (ecdsa_sign_digest(&secp256k1, node->private_key,
                          msg->sighash.bytes, sig, NULL, NULL) != 0) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_FirmwareError,
                        _("ECDSA signing failed"));
        zcash_signing.active = false;
        layoutHome();
        return;
    }

    memzero(node, sizeof(*node));

    /* DER-encode the signature */
    uint8_t der_sig[73];
    int der_len = ecdsa_sig_to_der(sig, der_sig);

    /* Send response */
    RESP_INIT(ZcashTransparentSig);
    resp->signature.size = der_len;
    memcpy(resp->signature.bytes, der_sig, der_len);

    zcash_signing.current_transparent_input++;

    if (zcash_signing.current_transparent_input >=
        zcash_signing.n_transparent_inputs) {
        /* Done with transparent phase */
        zcash_signing.transparent_phase_done = true;
        resp->has_next_index = true;
        resp->next_index = 0xFF; /* signals end of transparent phase */
    } else {
        resp->has_next_index = true;
        resp->next_index = zcash_signing.current_transparent_input;
    }

    msg_write(MessageType_MessageType_ZcashTransparentSig, resp);
}

/* ── ZcashPCZTAction ──────────────────────────────────────────────────── */
/*
 * Accepts per-action Orchard signing data, derives spend authorization key,
 * computes randomized rk, and returns RedPallas signature.
 * Only accepted after transparent_phase_done == true.
 *
 * NOTE: The actual RedPallas signing uses the Pallas curve implementation
 * in zcash.c — this handler delegates to zcash_sign_orchard_action().
 */

void fsm_msgZcashPCZTAction(const ZcashPCZTAction *msg) {
    if (!zcash_signing.active) {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                        _("Not in Zcash signing session"));
        layoutHome();
        return;
    }

    if (!zcash_signing.transparent_phase_done) {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                        _("Transparent phase not yet complete"));
        layoutHome();
        return;
    }

    if (msg->index != zcash_signing.current_action) {
        fsm_sendFailure(FailureType_Failure_ProcessError,
                        _("Unexpected Orchard action index"));
        zcash_signing.active = false;
        layoutHome();
        return;
    }

    /*
     * Derive ask (spend authorization key) from ZIP-32 path,
     * apply alpha randomizer, sign sighash with RedPallas.
     *
     * The actual cryptographic operations are in zcash.c which
     * implements Pallas curve arithmetic and RedPallas signing.
     * For now, we delegate to zcash_sign_orchard_action().
     */
    uint8_t signature[64];
    if (!zcash_sign_orchard_action(
            zcash_signing.address_n,
            zcash_signing.address_n_count,
            msg->alpha.bytes, msg->alpha.size,
            msg->sighash.bytes, msg->sighash.size,
            signature)) {
        fsm_sendFailure(FailureType_Failure_FirmwareError,
                        _("Orchard action signing failed"));
        zcash_signing.active = false;
        layoutHome();
        return;
    }

    zcash_signing.current_action++;

    if (zcash_signing.current_action >= zcash_signing.n_actions) {
        /* All actions signed — return final response */
        RESP_INIT(ZcashSignedPCZT);
        /* Signatures are collected on the host side from individual
         * ZcashPCZTActionAck responses. This final message signals completion.
         * For compatibility, we include the last signature. */
        resp->signatures_count = 1;
        memcpy(resp->signatures[0].bytes, signature, 64);
        resp->signatures[0].size = 64;
        msg_write(MessageType_MessageType_ZcashSignedPCZT, resp);
        zcash_signing.active = false;
        layoutHome();
    } else {
        /* Request next action */
        RESP_INIT(ZcashPCZTActionAck);
        resp->next_index = zcash_signing.current_action;
        msg_write(MessageType_MessageType_ZcashPCZTActionAck, resp);
    }
}

/* ── ZcashGetOrchardFVK ───────────────────────────────────────────────── */

void fsm_msgZcashGetOrchardFVK(const ZcashGetOrchardFVK *msg) {
    CHECK_INITIALIZED
    CHECK_PIN

    uint32_t account = msg->has_account ? msg->account : 0;

    uint8_t ak[32], nk[32], rivk[32];
    if (!zcash_derive_orchard_fvk(msg->address_n, msg->address_n_count,
                                   account, ak, nk, rivk)) {
        fsm_sendFailure(FailureType_Failure_FirmwareError,
                        _("Failed to derive Orchard FVK"));
        layoutHome();
        return;
    }

    if (msg->has_show_display && msg->show_display) {
        /* TODO: display the Orchard address on screen */
    }

    RESP_INIT(ZcashOrchardFVK);
    resp->has_ak = true;
    resp->ak.size = 32;
    memcpy(resp->ak.bytes, ak, 32);
    resp->has_nk = true;
    resp->nk.size = 32;
    memcpy(resp->nk.bytes, nk, 32);
    resp->has_rivk = true;
    resp->rivk.size = 32;
    memcpy(resp->rivk.bytes, rivk, 32);

    memzero(ak, 32);
    memzero(nk, 32);
    memzero(rivk, 32);

    msg_write(MessageType_MessageType_ZcashOrchardFVK, resp);
    layoutHome();
}
