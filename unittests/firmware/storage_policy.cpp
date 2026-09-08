#include "gtest/gtest.h"
#include <cstring>

extern "C" {
#include "keepkey/firmware/storage.h"
#include "storage.h"
void storage_writeStorageV16Plaintext(char*, size_t, const Storage*);
void storage_readStorageV16Plaintext(Storage*, const char*, size_t);
}

namespace {
class SessionPolicy : public ::testing::Test {
 protected:
  void SetUp() override { storage_reset(); }
  void TearDown() override { storage_reset(); }
};

TEST_F(SessionPolicy, NeitherFlashWriterPersistsAdvancedMode) {
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  ASSERT_TRUE(storage_setPolicy("Experimental", true));
  Storage storage = {};
  char bytes[852] = {};
  storage_writeStorageV11(bytes, sizeof(bytes), &storage);
  EXPECT_EQ(0, bytes[5] & 0x10);
  EXPECT_NE(0, bytes[5] & 0x08);  // Experimental retains its existing policy.
  storage_writeStorageV16Plaintext(bytes, sizeof(bytes), &storage);
  EXPECT_EQ(0, bytes[5] & 0x10);
  EXPECT_NE(0, bytes[5] & 0x08);
}

TEST_F(SessionPolicy, BothFlashReadersIgnoreLegacyAdvancedModeBit) {
  char bytes[852] = {};
  bytes[5] = 0x18;  // Legacy AdvancedMode and Experimental bits.
  Storage storage = {};
  storage_readStorageV11(&storage, bytes, sizeof(bytes));
  EXPECT_FALSE(
      storage_isPolicyEnabled_impl(storage.pub.policies, "AdvancedMode"));
  EXPECT_TRUE(
      storage_isPolicyEnabled_impl(storage.pub.policies, "Experimental"));
  storage_readStorageV16Plaintext(&storage, bytes, sizeof(bytes));
  EXPECT_FALSE(
      storage_isPolicyEnabled_impl(storage.pub.policies, "AdvancedMode"));
  EXPECT_TRUE(
      storage_isPolicyEnabled_impl(storage.pub.policies, "Experimental"));
}

TEST_F(SessionPolicy, LegacyPolicyNameCannotRearmAdvancedMode) {
  char bytes[559] = {};
  bytes[0] = 10;
  bytes[464] = 1;
  std::memcpy(bytes + 465, "AdvancedMode", 13);
  bytes[481] = 1;
  bytes[482] = 1;
  SessionState session = {};
  Storage storage = {};
  storage_readStorageV1(&session, &storage, bytes, sizeof(bytes));
  storage_upgradePolicies(&storage);
  EXPECT_FALSE(
      storage_isPolicyEnabled_impl(storage.pub.policies, "AdvancedMode"));
}

TEST_F(SessionPolicy, SoftInitializePreservesPolicyButLockRevokesIt) {
  SessionState session = {};
  Storage storage = {};
  storage_resetPolicies(&storage);
  storage.pub.has_pin = true;  // Avoid an unlock: this test isolates teardown.
  ASSERT_TRUE(
      storage_setPolicy_impl(storage.pub.policies, "AdvancedMode", true));
  ASSERT_TRUE(
      storage_setPolicy_impl(storage.pub.policies, "Experimental", true));
  session_clear_impl(&session, &storage, false);
  EXPECT_TRUE(
      storage_isPolicyEnabled_impl(storage.pub.policies, "AdvancedMode"));
  session_clear_impl(&session, &storage, true);
  EXPECT_FALSE(
      storage_isPolicyEnabled_impl(storage.pub.policies, "AdvancedMode"));
  EXPECT_TRUE(
      storage_isPolicyEnabled_impl(storage.pub.policies, "Experimental"));
}
}  // namespace
