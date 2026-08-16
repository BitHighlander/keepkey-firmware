extern "C" {
#include "keepkey/firmware/signed_metadata.h"
}

#include <cstring>
#include <gtest/gtest.h>

/* The signer keyring ships empty.
 *
 * Signers are loaded over the wire and the messages that do so are not
 * registered in this release, so no slot can be populated and every query must
 * answer "no signer". These assertions exist so that a partial implementation
 * fails here rather than silently beginning to trust host-supplied token
 * symbols and instruction schemas -- a keyring that quietly starts saying yes
 * looks exactly like a keyring that is working.
 *
 * When the clearsign engine lands it replaces both signed_metadata.c and this
 * file; deleting these tests is part of landing it, not an oversight. */

TEST(SignedMetadata, EveryKeyringSlotIsEmpty) {
  for (uint8_t key_id = 0; key_id < METADATA_MAX_KEYS; key_id++) {
    EXPECT_EQ(signed_metadata_signer_alias(key_id), nullptr)
        << "slot " << (int)key_id << " reported an alias";

    char fingerprint[METADATA_FINGERPRINT_LEN] = {0};
    EXPECT_FALSE(signed_metadata_signer_fingerprint(key_id, fingerprint))
        << "slot " << (int)key_id << " reported a fingerprint";

    EXPECT_FALSE(signed_metadata_signer_is_runtime(key_id))
        << "slot " << (int)key_id << " reported a runtime signer";
  }
}

TEST(SignedMetadata, AttestationAlwaysFails) {
  const uint8_t data[32] = {0};
  const uint8_t sig[64] = {0};

  for (uint8_t key_id = 0; key_id < METADATA_MAX_KEYS; key_id++) {
    EXPECT_FALSE(signed_metadata_verify_attestation(key_id, data, sizeof(data),
                                                    sig, sizeof(sig)))
        << "slot " << (int)key_id << " verified an attestation";
  }
}

/* Out-of-range slots must be refused rather than aliasing a valid one: the
 * wire field is a uint32 and callers narrow it to uint8, so key_id 256 would
 * otherwise land on slot 0. */
TEST(SignedMetadata, OutOfRangeSlotsAreRefused) {
  const uint8_t data[32] = {0};
  const uint8_t sig[64] = {0};
  char fingerprint[METADATA_FINGERPRINT_LEN] = {0};

  EXPECT_EQ(signed_metadata_signer_alias(METADATA_MAX_KEYS), nullptr);
  EXPECT_FALSE(
      signed_metadata_signer_fingerprint(METADATA_MAX_KEYS, fingerprint));
  EXPECT_FALSE(signed_metadata_signer_is_runtime(METADATA_MAX_KEYS));
  EXPECT_FALSE(signed_metadata_verify_attestation(
      METADATA_MAX_KEYS, data, sizeof(data), sig, sizeof(sig)));
}
