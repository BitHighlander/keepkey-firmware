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

/* Clearsign attestor: seed-derived schema attestations, AdvancedMode-gated.
 * Runtime tier (SRS R-1.3): annotates, never suppresses the raw review.
 * NEVER signs arbitrary bytes: only payloads the verifier's own parser accepts
 * and the user confirmed, so a compromised host gets no signing oracle. Do not
 * add a "raw" mode. ponytail: KKSOLSC1 only; EVM v2 needs its own branch.
 */

/* m/'KK'/'CS'/0', all hardened and outside SLIP-44 space: never a funds key. */
#define ATTESTOR_PATH_LEN 3
static const uint32_t ATTESTOR_PATH[ATTESTOR_PATH_LEN] = {
    0x80000000 | 0x4B4B,
    0x80000000 | 0x4353,
    0x80000000u,
};

/* Derive the attestation node. Returns NULL and sends the failure itself. */
static HDNode* attestor_getNode(void) {
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, ATTESTOR_PATH,
                                    ATTESTOR_PATH_LEN, NULL);
  if (!node) return NULL;
  hdnode_fill_public_key(node);
  return node;
}

/* Types are security-relevant (equal total widths can shift label offsets):
 * never attest a label without showing its type. */
static const char* attestor_schemaArgTypeName(SolanaSchemaArgType type) {
  switch (type) {
    case SOL_SCHEMA_ARG_U64:
      return "u64 LE";
    case SOL_SCHEMA_ARG_U8:
      return "u8";
    case SOL_SCHEMA_ARG_PUBKEY:
      return "public key";
    case SOL_SCHEMA_ARG_OPAQUE32:
      return "bytes32 hex";
    case SOL_SCHEMA_ARG_LAMPORTS:
      return "lamports (u64 LE)";
    case SOL_SCHEMA_ARG_TOKEN_AMOUNT:
      return "token amount (u64 LE)";
    case SOL_SCHEMA_ARG_DURATION:
      return "seconds (u64 LE)";
  }
  return "invalid"; /* Parser rejects unknown values; defense in depth. */
}

void fsm_msgClearsignAttestorGetPublicKey(
    const ClearsignAttestorGetPublicKey* msg) {
  (void)msg;
  RESP_INIT(ClearsignAttestorPublicKey);

  CHECK_INITIALIZED
  CHECK_PIN
  CHECK_PARAM(storage_isPolicyEnabled("AdvancedMode"),
              _("AdvancedMode required for clearsign attestation"));

  HDNode* node = attestor_getNode();
  if (!node) return;

  resp->has_public_key = true;
  resp->public_key.size = 33;
  memcpy(resp->public_key.bytes, node->public_key, 33);
  memzero(node, sizeof(*node));

  msg_write(MessageType_MessageType_ClearsignAttestorPublicKey, resp);
  layoutHome();
}

void fsm_msgClearsignAttestorSign(const ClearsignAttestorSign* msg) {
  RESP_INIT(ClearsignAttestorSignature);

  CHECK_INITIALIZED
  CHECK_PIN

  CHECK_PARAM(msg->has_payload && msg->payload.size > 0, "Missing payload");

  /* Validate with the verifier's own parser: no raw signing oracle. */
  SolanaInstrSchema schema;
  CHECK_PARAM(storage_isPolicyEnabled("AdvancedMode"),
              _("AdvancedMode required for schema attestation"));
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

  char program_id[45] = {0};
  char disc_hex[2 * SOL_SCHEMA_DISC_MAX + 1] = {0};
  solana_pubkeyToStr(schema.program_id, program_id, sizeof(program_id));
  for (uint8_t i = 0; i < schema.disc_len; i++) {
    snprintf(disc_hex + 2 * i, sizeof(disc_hex) - 2 * i, "%02x",
             schema.disc[i]);
  }

  /* Separate screens: combined, the discriminator could be clipped. */
  bool confirmed =
      (confirm(ButtonRequestType_ButtonRequest_SignTx, "Attest Schema",
               "%s\n%s", schema.program_name, schema.instruction_name) &&
       confirm(ButtonRequestType_ButtonRequest_SignTx, "Program ID", "%s",
               program_id) &&
       confirm(ButtonRequestType_ButtonRequest_SignTx, "Discriminator", "%s",
               disc_hex));

  /* One label per screen (confirm() does not paginate): a valid schema can
   * still mislabel an offset, so every label must be seen. */
  for (uint8_t i = 0; confirmed && i < schema.num_args; i++) {
    confirmed = confirm(ButtonRequestType_ButtonRequest_SignTx, "Attest Schema",
                        "Arg %u: %s\n%s", (unsigned)(i + 1),
                        attestor_schemaArgTypeName(schema.args[i].type),
                        schema.args[i].label);
    /* The mint account decides which token definition scales the amount. */
    if (confirmed && schema.args[i].type == SOL_SCHEMA_ARG_TOKEN_AMOUNT) {
      confirmed =
          confirm(ButtonRequestType_ButtonRequest_SignTx, "Attest Schema",
                  "Arg %u token mint is\naccount #%u", (unsigned)(i + 1),
                  (unsigned)schema.args[i].mint_account);
    }
  }
  for (uint8_t i = 0; confirmed && i < schema.num_accounts; i++) {
    confirmed =
        confirm(ButtonRequestType_ButtonRequest_SignTx, "Attest Schema",
                "Account #%u shows\n%s", (unsigned)schema.accounts[i].index,
                schema.accounts[i].label);
  }
  memzero(&schema, sizeof(schema));
  if (!confirmed) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  HDNode* node = attestor_getNode();
  if (!node) return;

  /* ECDSA over SHA256(payload), as signed_metadata_verify_attestation(). */
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
