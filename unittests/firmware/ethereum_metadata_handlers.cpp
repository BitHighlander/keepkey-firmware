extern "C" {
#define delete delete_field
#include "messages.pb.h"
#undef delete
#include "messages-ethereum.pb.h"
#include "keepkey/board/draw.h"
#include "keepkey/board/layout.h"
#include "keepkey/firmware/signed_metadata.h"
}
#include "gtest/gtest.h"
#include <cstring>

// Compile the production handlers with observable I/O boundaries. Verification
// and icon validation remain the actual provider engine functions.
namespace {
bool initialized, pin, advanced, streaming, consent;
unsigned failures, confirmations, stores, successes, aborts;
static void failure(int, const char*) { ++failures; }
static void home() {}
static bool policy(const char*) { return advanced; }
static bool in_progress() { return streaming; }
static void abort_signing() {
  streaming = false;
  ++aborts;
}
static void success(const char*) { ++successes; }
static void write_response(int, const void*) {}
static bool confirm_load(const char*, const char*, const uint8_t*, uint8_t,
                         uint8_t, uint16_t) {
  ++confirmations;
  return consent;
}
static bool store(uint8_t, const uint8_t*, const char*, const uint8_t*, uint8_t,
                  uint8_t, uint16_t, bool) {
  EXPECT_EQ(1u, confirmations);
  EXPECT_TRUE(consent);
  ++stores;
  return true;
}
#define _(x) (x)
#define CHECK_INITIALIZED \
  if (!initialized) {     \
    ++failures;           \
    return;               \
  }
#define CHECK_PIN \
  if (!pin) {     \
    ++failures;   \
    return;       \
  }
#define CHECK_PARAM(x, message) \
  if (!(x)) {                   \
    ++failures;                 \
    return;                     \
  }
#define RESP_INIT(type) \
  type response = {};   \
  type* resp = &response
#define fsm_sendFailure failure
#define layoutHome home
#define storage_isPolicyEnabled policy
#define ethereum_signing_isInProgress in_progress
#define ethereum_signing_abort abort_signing
#define fsm_sendSuccess success
#define msg_write write_response
#define signed_metadata_confirm_load confirm_load
#define signed_metadata_store_signer store
#include "fsm_msg_ethereum_metadata.h"

class MetadataHandlers : public ::testing::Test {
 protected:
  LoadClearsignSigner msg;
  void SetUp() override {
    initialized = pin = advanced = consent = true;
    streaming = false;
    failures = confirmations = stores = successes = aborts = 0;
    msg = {};
    msg.has_key_id = msg.has_pubkey = msg.has_alias = true;
    msg.key_id = 3;
    msg.pubkey.size = 33;
    const uint8_t generator[] = {
        2,    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
        0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
        0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
    memcpy(msg.pubkey.bytes, generator, sizeof(generator));
    strcpy(msg.alias, "Test provider");
  }
};
TEST_F(MetadataHandlers, ConsentPrecedesStore) {
  fsm_msgLoadClearsignSigner(&msg);
  EXPECT_EQ(1u, confirmations);
  EXPECT_EQ(1u, stores);
  EXPECT_EQ(1u, successes);
  EXPECT_EQ(0u, failures);
}
TEST_F(MetadataHandlers, CancellationDoesNotStore) {
  consent = false;
  fsm_msgLoadClearsignSigner(&msg);
  EXPECT_EQ(1u, confirmations);
  EXPECT_EQ(0u, stores);
  EXPECT_EQ(0u, successes);
  EXPECT_EQ(1u, failures);
}
TEST_F(MetadataHandlers, RejectsPersistenceBeforeConsent) {
  msg.has_persist = msg.persist = true;
  fsm_msgLoadClearsignSigner(&msg);
  EXPECT_EQ(0u, confirmations);
  EXPECT_EQ(0u, stores);
  EXPECT_EQ(1u, failures);
}
TEST_F(MetadataHandlers, DoesNotNarrowOutOfRangeSlot) {
  msg.key_id = 256;
  fsm_msgLoadClearsignSigner(&msg);
  EXPECT_EQ(0u, confirmations);
  EXPECT_EQ(0u, stores);
  EXPECT_EQ(1u, failures);
}
TEST_F(MetadataHandlers, PolicyRequired) {
  advanced = false;
  fsm_msgLoadClearsignSigner(&msg);
  EXPECT_EQ(0u, confirmations);
  EXPECT_EQ(0u, stores);
  EXPECT_EQ(1u, failures);
}
TEST_F(MetadataHandlers, LockedDeviceCannotLoadProvider) {
  pin = false;
  fsm_msgLoadClearsignSigner(&msg);
  EXPECT_EQ(0u, confirmations);
  EXPECT_EQ(0u, stores);
  EXPECT_EQ(1u, failures);
}
TEST_F(MetadataHandlers, UninitializedDeviceCannotLoadProvider) {
  initialized = false;
  fsm_msgLoadClearsignSigner(&msg);
  EXPECT_EQ(0u, confirmations);
  EXPECT_EQ(0u, stores);
  EXPECT_EQ(1u, failures);
}
TEST_F(MetadataHandlers, InvalidIconCannotReachConsent) {
  msg.has_icon = msg.has_icon_width = msg.has_icon_height = true;
  msg.icon_width = msg.icon_height = 2;
  msg.icon.size = 2;
  msg.icon.bytes[0] = 0x80;
  msg.icon.bytes[1] = 0xff;
  fsm_msgLoadClearsignSigner(&msg);
  EXPECT_EQ(0u, confirmations);
  EXPECT_EQ(0u, stores);
  EXPECT_EQ(1u, failures);
}
TEST_F(MetadataHandlers, SignerInjectionAbortsStreaming) {
  streaming = true;
  fsm_msgLoadClearsignSigner(&msg);
  EXPECT_FALSE(streaming);
  EXPECT_EQ(1u, aborts);
  EXPECT_EQ(0u, confirmations);
  EXPECT_EQ(0u, stores);
  EXPECT_EQ(1u, failures);
}
TEST_F(MetadataHandlers, MetadataInjectionAbortsStreaming) {
  streaming = true;
  EthereumTxMetadata metadata = {};
  fsm_msgEthereumTxMetadata(&metadata);
  EXPECT_FALSE(streaming);
  EXPECT_EQ(1u, aborts);
  EXPECT_EQ(1u, failures);
}
}  // namespace
