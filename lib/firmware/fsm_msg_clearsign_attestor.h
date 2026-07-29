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

/* Clearsign attestor: turn a KeepKey (today the emulator, tomorrow a device in
 * a rack) into the signing enclave for clear-sign schemas.
 *
 * This replaces the rejected "persist signers to public flash" design: the
 * VERIFYING devices get a production key baked into signature-protected
 * firmware, and the ISSUING KeepKey holds the private key in its seed, where a
 * hardware wallet's keys already belong. No trust anchors in writable flash,
 * no per-boot signer prompts.
 *
 * The attestor NEVER signs arbitrary bytes. It parses the submitted payload
 * with the same validator verifying devices run (solana_parseInstrSchema for
 * KKSOLSC1) and refuses anything malformed. A fully compromised host can
 * therefore only obtain attestations over well-formed, user-confirmed
 * descriptors — never a general secp256k1 signing oracle. That is the single
 * most important property of this design; do not add a "raw" mode.
 *
 * Key custody: the attestation key is derived from the device seed at
 * ATTESTOR_PATH (a dedicated hardened path outside every coin space), so PIN
 * unlock gates its availability, seed backup is key backup, and wipe destroys
 * it.
 *
 * Build-gated: CLEARSIGN_ATTESTOR is OFF for device firmware (the 7.15 line
 * has no ROM headroom) and opt-in for emulator/rack builds. Wire IDs 1700-1703
 * are reserved regardless, so promoting the physical-device tier later is a
 * flag flip rather than a protocol change.
 *
 * ponytail: KKSOLSC1 only. EVM v2 metadata blobs are attestable in principle
 * but sign a different range (payload minus the 65-byte signature trailer, see
 * signed_metadata_process) and their parser is static in signed_metadata.c;
 * add a second branch here plus an exported pure parser when EVM schemas need
 * device-issued signatures.
 */

/* The attestation key path: purpose 0x4B4B ("KK"), then 0x4353 ("CS") for
 * clearsign, then account 0. All hardened, and far outside any SLIP-44 coin
 * range, so an attestation key can never collide with a funds key. */
#define ATTESTOR_PATH_LEN 3
static const uint32_t ATTESTOR_PATH[ATTESTOR_PATH_LEN] = {
    0x80000000 | 0x4B4B,
    0x80000000 | 0x4353,
    0x80000000 | 0,
};

/* Derive the attestation node. Returns NULL and sends the failure itself. */
static HDNode *attestor_getNode(void) {
  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, ATTESTOR_PATH,
                                    ATTESTOR_PATH_LEN, NULL);
  if (!node) return NULL;
  hdnode_fill_public_key(node);
  return node;
}

void fsm_msgClearsignAttestorGetPublicKey(
    const ClearsignAttestorGetPublicKey *msg) {
  (void)msg;
  RESP_INIT(ClearsignAttestorPublicKey);

  CHECK_INITIALIZED
  CHECK_PIN

  HDNode *node = attestor_getNode();
  if (!node) return;

  resp->has_public_key = true;
  resp->public_key.size = 33;
  memcpy(resp->public_key.bytes, node->public_key, 33);
  memzero(node, sizeof(*node));

  msg_write(MessageType_MessageType_ClearsignAttestorPublicKey, resp);
  layoutHome();
}

void fsm_msgClearsignAttestorSign(const ClearsignAttestorSign *msg) {
  RESP_INIT(ClearsignAttestorSignature);

  CHECK_INITIALIZED
  CHECK_PIN

  CHECK_PARAM(msg->has_payload && msg->payload.size > 0, "Missing payload");

  /* Validate before attesting. The payload must be a descriptor this firmware
   * can itself parse — the same code path fsm_msgSolanaSignTx runs — so a
   * compromised host cannot use the attestor as a raw signing oracle. */
  SolanaInstrSchema schema;
  if (msg->payload.size < 8 || memcmp(msg->payload.bytes, "KKSOLSC1", 8) != 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, "Unsupported descriptor");
    layoutHome();
    return;
  }
  if (!solana_parseInstrSchema(msg->payload.bytes, msg->payload.size,
                               &schema)) {
    memzero(&schema, sizeof(schema));
    fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid schema");
    layoutHome();
    return;
  }

  char program_id[45];
  char disc_hex[2 * SOL_SCHEMA_DISC_MAX + 1];
  solana_pubkeyToStr(schema.program_id, program_id, sizeof(program_id));
  for (uint8_t i = 0; i < schema.disc_len; i++) {
    snprintf(disc_hex + 2 * i, sizeof(disc_hex) - 2 * i, "%02x",
             schema.disc[i]);
  }

  /* The base58 program id alone wraps to two of the three rows, so it gets no
   * "Program" prefix — with one the discriminator renders off the screen. */
  bool confirmed =
      confirm(ButtonRequestType_ButtonRequest_SignTx, "Attest Schema", "%s\n%s",
              schema.program_name, schema.instruction_name) &&
      confirm(ButtonRequestType_ButtonRequest_SignTx, "Attest Schema",
              "%s\nDisc %s", program_id, disc_hex);

  /* One label per screen. A structurally valid schema can still lie by
   * labelling the wrong offset ("Amount" over the order id), so the operator
   * has to read every label — and confirm()'s body is three rendered rows with
   * no pagination, so a batched list of max-length labels scrolls off. A label
   * nobody saw is a label nobody checked. */
  for (uint8_t i = 0; confirmed && i < schema.num_args; i++) {
    confirmed = confirm(ButtonRequestType_ButtonRequest_SignTx, "Attest Schema",
                        "Arg %u shows\n%s", (unsigned)(i + 1),
                        schema.args[i].label);
  }
  for (uint8_t i = 0; confirmed && i < schema.num_accounts; i++) {
    confirmed = confirm(ButtonRequestType_ButtonRequest_SignTx, "Attest Schema",
                        "Account #%u shows\n%s",
                        (unsigned)schema.accounts[i].index,
                        schema.accounts[i].label);
  }
  memzero(&schema, sizeof(schema));
  if (!confirmed) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  HDNode *node = attestor_getNode();
  if (!node) return;

  /* Plain ECDSA over SHA256(payload): exactly what
   * signed_metadata_verify_attestation() checks on the verifying device. */
  uint8_t digest[32];
  sha256_Raw(msg->payload.bytes, msg->payload.size, digest);

  uint8_t sig[64];
  int ret =
      ecdsa_sign_digest(&secp256k1, node->private_key, digest, sig, NULL, NULL);
  memzero(digest, sizeof(digest));
  if (ret != 0) {
    memzero(node, sizeof(*node));
    memzero(sig, sizeof(sig));
    fsm_sendFailure(FailureType_Failure_Other, "Attestation failed");
    layoutHome();
    return;
  }

  resp->has_signature = true;
  resp->signature.size = sizeof(sig);
  memcpy(resp->signature.bytes, sig, sizeof(sig));
  resp->has_public_key = true;
  resp->public_key.size = 33;
  memcpy(resp->public_key.bytes, node->public_key, 33);

  memzero(sig, sizeof(sig));
  memzero(node, sizeof(*node));

  msg_write(MessageType_MessageType_ClearsignAttestorSignature, resp);
  layoutHome();
}
