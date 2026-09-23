#include "gtest/gtest.h"

extern "C" {
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/otp.h"
}

#include <cstring>

namespace {
enum class Fault {
  None,
  Draw,
  Write,
  Readback,
  Corrupt,
  Lock,
  LockVerify,
  FinalRead,
  PrelockedRead
};
Fault fault;
bool locked;
unsigned reads;
unsigned writes;
unsigned locks;
uint8_t stored[FLASH_OTP_BLOCK_SIZE];

bool is_locked(uint8_t block) {
  EXPECT_EQ(FLASH_OTP_BLOCK_RANDOMNESS, block);
  return locked && !(fault == Fault::LockVerify && locks != 0);
}
bool draw(uint8_t* data, size_t size) {
  EXPECT_EQ(FLASH_OTP_BLOCK_SIZE, size);
  memset(data, 0xa5, size);
  return fault != Fault::Draw;
}
bool write(uint8_t block, uint8_t offset, const uint8_t* data, uint8_t size) {
  EXPECT_EQ(FLASH_OTP_BLOCK_RANDOMNESS, block);
  EXPECT_EQ(0, offset);
  EXPECT_EQ(FLASH_OTP_BLOCK_SIZE, size);
  ++writes;
  if (fault == Fault::Write) return false;
  memcpy(stored, data, size);
  if (fault == Fault::Corrupt) stored[0] ^= 1;
  return true;
}
bool read(uint8_t block, uint8_t offset, uint8_t* data, uint8_t size) {
  EXPECT_EQ(FLASH_OTP_BLOCK_RANDOMNESS, block);
  EXPECT_EQ(0, offset);
  EXPECT_EQ(FLASH_OTP_BLOCK_SIZE, size);
  ++reads;
  if ((reads == 1 &&
       (fault == Fault::Readback || fault == Fault::PrelockedRead)) ||
      (reads == 2 && fault == Fault::FinalRead))
    return false;
  memcpy(data, stored, size);
  return true;
}
bool lock(uint8_t block) {
  EXPECT_EQ(FLASH_OTP_BLOCK_RANDOMNESS, block);
  ++locks;
  if (fault == Fault::Lock) return false;
  locked = true;
  return true;
}
const FlashEntropyOps ops = {is_locked, draw, write, read, lock};
void reset(Fault next) {
  fault = next;
  locked = false;
  reads = writes = locks = 0;
  memset(stored, 0, sizeof(stored));
}
}  // namespace

TEST(OtpEntropy, EveryProvisioningFailureRefusesAndWipesOutput) {
  for (Fault next :
       {Fault::Draw, Fault::Write, Fault::Readback, Fault::Corrupt, Fault::Lock,
        Fault::LockVerify, Fault::FinalRead, Fault::PrelockedRead}) {
    reset(next);
    if (next == Fault::PrelockedRead) locked = true;
    uint8_t output[FLASH_OTP_BLOCK_SIZE];
    memset(output, 0xff, sizeof(output));
    EXPECT_FALSE(flash_collectOtpEntropy(output, &ops)) << int(next);
    for (uint8_t byte : output) EXPECT_EQ(0, byte) << int(next);
    if (next == Fault::Draw) EXPECT_EQ(0u, writes);
    if (next == Fault::Write) EXPECT_EQ(0u, reads);
    if (next == Fault::Draw || next == Fault::Write ||
        next == Fault::Readback || next == Fault::Corrupt)
      EXPECT_EQ(0u, locks);
  }
}

TEST(OtpEntropy, HealthyProvisioningAndExistingLockedBlock) {
  reset(Fault::None);
  uint8_t output[FLASH_OTP_BLOCK_SIZE] = {};
  ASSERT_TRUE(flash_collectOtpEntropy(output, &ops));
  EXPECT_EQ(1u, writes);
  EXPECT_EQ(1u, locks);
  for (uint8_t byte : output) EXPECT_EQ(0xa5, byte);
  ASSERT_TRUE(flash_collectOtpEntropy(output, &ops));
  EXPECT_EQ(1u, writes);
  EXPECT_EQ(1u, locks);
}
