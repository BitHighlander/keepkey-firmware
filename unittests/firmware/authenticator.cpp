extern "C" {
#include <stdint.h>

#include "trezor/crypto/sha2.h"
#include "keepkey/firmware/authenticator.h"
#include "keepkey/firmware/storage.h"

void setup(void);
}

#include "gtest/gtest.h"

// Shared emulator confirmation driver from thorchain.cpp.
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

static void ensure_auth_storage_initialized(void) {
  static bool initialized = false;
  if (!initialized) {
    setup();
    storage_init();
    initialized = true;
  }
}

TEST(Authenticator, WipeCancellationFailsClosed) {
  ensure_auth_storage_initialized();
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_EQ(AUTH_CANCELLED, wipeAuthData());
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Authenticator, AddAndRemoveCancellationFailsClosed) {
  ensure_auth_storage_initialized();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_EQ(NOERR, wipeAuthData());
  EXPECT_EQ(0, kkconfirm_drain());

  char cancelled_add[] = "example:alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_EQ(AUTH_CANCELLED, addAuthAccount(cancelled_add));
  EXPECT_EQ(0, kkconfirm_drain());

  char account[DOMAIN_SIZE + ACCOUNT_SIZE + 2] = {0};
  EXPECT_EQ(NOACC, getAuthAccount("0", account));

  char accepted_add[] = "example:alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  EXPECT_EQ(NOERR, addAuthAccount(accepted_add));
  EXPECT_EQ(0, kkconfirm_drain());

  char cancelled_remove[] = "example:alice";
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_EQ(AUTH_CANCELLED, removeAuthAccount(cancelled_remove));
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_EQ(NOERR, getAuthAccount("0", account));
  EXPECT_STREQ("example:alice", account);

  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_EQ(NOERR, wipeAuthData());
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Authenticator, RejectsAmbiguousDisplayFieldsBeforeMutation) {
  char long_domain[] = "domain-is-too-long:alice:JBSWY3DPEHPK3PXP";
  EXPECT_EQ(TOKERR, addAuthAccount(long_domain));

  char control_domain[] = "bad\ndomain:alice:JBSWY3DPEHPK3PXP";
  EXPECT_EQ(TOKERR, addAuthAccount(control_domain));

  char long_account[] = "example:account-is-too-long:JBSWY3DPEHPK3PXP";
  EXPECT_EQ(TOKERR, addAuthAccount(long_account));

  char remove_long[] = "example:account-is-too-long";
  EXPECT_EQ(TOKERR, removeAuthAccount(remove_long));

  char remove_control[] = "example:bad\naccount";
  EXPECT_EQ(TOKERR, removeAuthAccount(remove_control));
}

TEST(Authenticator, RejectsWeakAndDuplicateSecrets) {
  ensure_auth_storage_initialized();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_EQ(NOERR, wipeAuthData());
  EXPECT_EQ(0, kkconfirm_drain());

  char weak[] = "example:weak:MY";
  EXPECT_EQ(BADSECRET, addAuthAccount(weak));

  // The final invalid block fails after earlier blocks have decoded; the
  // implementation must still take its cleanup path.
  char partially_decoded[] = "example:invalid:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX!";
  EXPECT_EQ(BADSECRET, addAuthAccount(partially_decoded));

  char first[] = "example:alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  EXPECT_EQ(NOERR, addAuthAccount(first));
  EXPECT_EQ(0, kkconfirm_drain());

  char duplicate[] = "example:alice:KRSXG5DSNFXGOIDBKRSXG5DSNFXGOIDB";
  EXPECT_EQ(DUPLICATE, addAuthAccount(duplicate));

  char account[DOMAIN_SIZE + ACCOUNT_SIZE + 2] = {0};
  EXPECT_EQ(NOACC, getAuthAccount("1", account));

  char remove[] = "example:alice";
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_EQ(NOERR, removeAuthAccount(remove));
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_EQ(NOACC, getAuthAccount("0", account));
}

TEST(Authenticator, CacheClearReloadsPersistentAccounts) {
  ensure_auth_storage_initialized();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_EQ(NOERR, wipeAuthData());
  ASSERT_EQ(0, kkconfirm_drain());

  char account_seed[] = "example:alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  ASSERT_EQ(NOERR, addAuthAccount(account_seed));
  ASSERT_EQ(0, kkconfirm_drain());

  authenticator_clear_cache();

  char account[DOMAIN_SIZE + ACCOUNT_SIZE + 2] = {0};
  EXPECT_EQ(NOERR, getAuthAccount("0", account));
  EXPECT_STREQ("example:alice", account);

  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_EQ(NOERR, wipeAuthData());
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Authenticator, OtpRejectsMalformedOrUnboundedTimes) {
  ensure_auth_storage_initialized();
  const char* requests[] = {"example:missing:1:31",
                            "example:missing:1:4294967295",
                            "example:missing:1:-1",
                            "example:missing:1:30junk",
                            "example:missing:-1:0",
                            "example:missing:1junk:0",
                            "example:missing:18446744073709551616:0",
                            "example:missing:1:18446744073709551616",
                            "example::1:0",
                            ":missing:1:0",
                            "example:missing::0",
                            "example:missing:1:",
                            "example:missing:1:0:extra"};
  for (const char* request : requests) {
    SCOPED_TRACE(request);
    char input[128];
    snprintf(input, sizeof(input), "%s", request);
    char otp[9] = "residue";
    EXPECT_EQ(TOKERR, generateOTP(input, otp));
    EXPECT_STREQ("", otp);
  }
  char account[DOMAIN_SIZE + ACCOUNT_SIZE + 2] = {};
  for (const char* slot : {"-1", "256", "18446744073709551616", "0junk", ""})
    EXPECT_EQ(NOSLOT, getAuthAccount(slot, account));
}

TEST(Authenticator, OtpUsesFull64BitCounter) {
  ensure_auth_storage_initialized();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_EQ(NOERR, wipeAuthData());
  ASSERT_EQ(0, kkconfirm_drain());
  char added[] = "example:alice:GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  ASSERT_EQ(NOERR, addAuthAccount(added));
  ASSERT_EQ(0, kkconfirm_drain());
  // Independent HMAC-SHA1/HOTP vectors for the ASCII key 12345678901234567890.
  const char* counters[] = {"0", "1", "4294967296", "18446744073709551615"};
  const char* expected[] = {"755224", "287082", "999456", "094451"};
  for (size_t i = 0; i < 4; ++i) {
    char input[96], otp[9];
    snprintf(input, sizeof(input), "example:alice:%s:0", counters[i]);
    // A zero time remaining prompts expiry without a blocking countdown.
    ASSERT_TRUE(kkconfirm_preload(2, 0));
    EXPECT_EQ(NOERR, generateOTP(input, otp));
    EXPECT_STREQ(expected[i], otp);
    EXPECT_EQ(0, kkconfirm_drain());
  }
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_EQ(NOERR, wipeAuthData());
  EXPECT_EQ(0, kkconfirm_drain());
}
