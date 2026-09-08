/* Runtime provider handlers, included by fsm.c through fsm_msg_ethereum.h. */
void fsm_msgEthereumTxMetadata(const EthereumTxMetadata* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  /* Metadata must arrive before signing starts. signed_metadata_process()
   * clears the binding on entry, so accepting metadata mid-signing would
   * drop the tx<->metadata binding without aborting: a host could approve a
   * benign decode (suppressing the blind-sign gate), then inject metadata to
   * clear the binding and stream attacker-chosen calldata for the rest.
   * Refuse and abort any in-progress signing session. */
  if (ethereum_signing_isInProgress()) {
    ethereum_signing_abort();
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Metadata not allowed during signing"));
    layoutHome();
    return;
  }

  CHECK_PARAM(storage_isPolicyEnabled("AdvancedMode"),
              _("AdvancedMode required for clearsign metadata"));

  RESP_INIT(EthereumMetadataAck);

  MetadataClassification result = signed_metadata_process(
      msg->signed_payload.bytes, msg->signed_payload.size,
      msg->has_key_id ? msg->key_id : 0);

  resp->classification = (uint32_t)result;
  resp->has_display_summary = true;

  switch (result) {
    case METADATA_VERIFIED:
      strlcpy(resp->display_summary, "Verified", sizeof(resp->display_summary));
      break;
    case METADATA_OPAQUE:
      strlcpy(resp->display_summary, "Unverified",
              sizeof(resp->display_summary));
      break;
    case METADATA_MALFORMED:
    default:
      strlcpy(resp->display_summary, "Invalid", sizeof(resp->display_summary));
      break;
  }

  msg_write(MessageType_MessageType_EthereumMetadataAck, resp);
}

void fsm_msgLoadClearsignSigner(const LoadClearsignSigner* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  /* Same reasoning as fsm_msgEthereumTxMetadata above, and the same fix.
   * Storing a signer ends in signed_metadata_clear(), which drops the
   * tx<->metadata binding along with relied_on_metadata -- so loading a
   * signer mid-signing let a host approve a benign decode and then stream
   * different calldata, with signed_metadata_enforce() seeing relied=false
   * and passing. The guard was on the metadata message but not on its
   * sibling. */
  if (ethereum_signing_isInProgress()) {
    ethereum_signing_abort();
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Signer load not allowed during signing"));
    layoutHome();
    return;
  }

  CHECK_PARAM(storage_isPolicyEnabled("AdvancedMode"),
              _("AdvancedMode required for clearsign signers"));

  CHECK_PARAM(msg->has_key_id && msg->has_pubkey && msg->has_alias,
              _("key_id, pubkey and alias required"));
  /* Range-check as uint32 BEFORE narrowing: (uint8_t)256 would alias slot 0 */
  CHECK_PARAM(msg->key_id < METADATA_MAX_KEYS, _("key_id out of range"));
  CHECK_PARAM(
      signed_metadata_signer_valid((uint8_t)msg->key_id, msg->pubkey.bytes,
                                   msg->pubkey.size, msg->alias),
      _("Invalid clearsign signer"));

  /* Optional identity icon (1bpp mono RLE). The proto caps icon at 384 bytes;
   * bound the dims too so the render path never scans a bogus geometry. An icon
   * with zero/oversized dims is rejected rather than silently dropped so a
   * malformed upload is visible, not a mystery text-only identity. */
  const uint8_t* icon = NULL;
  uint16_t icon_len = 0;
  uint8_t icon_w = 0, icon_h = 0;
  if (msg->has_icon && msg->icon.size > 0) {
    CHECK_PARAM(msg->icon.size <= METADATA_ICON_MAX, _("icon too large"));
    /* Width is capped at the confirm screen's icon column
     * (LEFT_MARGIN_WITH_ICON = 40), NOT at the 64px height. Title/body text
     * begins at x=40 and the icon is drawn AFTER the text, so a wider
     * host-supplied icon would paint over the alias, fingerprint and the
     * "NOT verified by KeepKey" warning — on the very screen that exists to
     * carry that warning. This is the trust boundary for icons arriving on the
     * wire; signed_metadata_signer_icon() rechecks the session copy at use. */
    CHECK_PARAM(msg->has_icon_width && msg->has_icon_height &&
                    msg->icon_width > 0 &&
                    msg->icon_width <= LEFT_MARGIN_WITH_ICON &&
                    msg->icon_height > 0 && msg->icon_height <= 64,
                _("icon dimensions out of range"));
    /* Reject a malformed RLE stream HERE rather than discovering it at draw
     * time. The render path returns a bool that layout_add_icon() discards, so
     * an undecodable icon would otherwise show no logo while still returning
     * Success — the user would consent to an identity
     * whose logo silently does not exist. Validation is exact (every packet
     * well-formed, no run straddling the image, whole input consumed) and
     * side-effect-free.
     */
    CHECK_PARAM(draw_bitmap_mono_rle_valid(
                    msg->icon.bytes, (uint32_t)msg->icon.size,
                    (uint16_t)msg->icon_width, (uint16_t)msg->icon_height),
                _("invalid icon encoding"));
    icon = msg->icon.bytes;
    icon_len = (uint16_t)msg->icon.size;
    icon_w = (uint8_t)msg->icon_width;
    icon_h = (uint8_t)msg->icon_height;
  }
  bool persist = msg->has_persist && msg->persist;
  CHECK_PARAM(!persist, _("Persistent clearsign signers are disabled"));

  /* Mandatory on-device consent — leads with the identity's logo (if any) +
   * alias + fingerprint. The whole trust model hangs on this confirm; the same
   * fingerprint reappears on every per-tx identity screen. */
  char fingerprint[METADATA_FINGERPRINT_LEN];
  signed_metadata_pubkey_fingerprint(msg->pubkey.bytes, fingerprint);
  if (!signed_metadata_confirm_load(msg->alias, fingerprint, icon, icon_w,
                                    icon_h, icon_len)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Load clearsign signer cancelled"));
    layoutHome();
    return;
  }

  if (!signed_metadata_store_signer((uint8_t)msg->key_id, msg->pubkey.bytes,
                                    msg->alias, icon, icon_w, icon_h, icon_len,
                                    persist)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Clearsign signer could not be loaded"));
    layoutHome();
    return;
  }
  fsm_sendSuccess(_("Clearsign signer loaded"));
  layoutHome();
}
