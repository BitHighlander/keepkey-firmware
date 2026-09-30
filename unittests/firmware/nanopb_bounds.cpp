extern "C" {
#include "pb_decode.h"
#include "types.pb.h"
}

#include "gtest/gtest.h"

namespace {

typedef PB_BYTES_ARRAY_T(3) ThreeByteArray;
const uint8_t kDescriptorSentinel = 0xA5;

struct FixedCountBytesFixture {
  ThreeByteArray values[2];
};

const pb_field_t kFixedCountBytesFields[] = {
    PB_REPEATED_FIXED_COUNT(1, BYTES, FIRST, FixedCountBytesFixture, values,
                            values, &kDescriptorSentinel),
    PB_LAST_FIELD};

struct StaticOneofFixture {
  pb_size_t which_choice;
  union {
    ThreeByteArray value;
  } choice;
};

const pb_field_t kStaticOneofFields[] = {
    PB_ONEOF_FIELD(choice, 1, BYTES, ONEOF, STATIC, FIRST, StaticOneofFixture,
                   value, value, &kDescriptorSentinel),
    PB_LAST_FIELD};

struct PointerOneofFixture {
  pb_size_t which_choice;
  union {
    ThreeByteArray *value;
  } choice;
};

const pb_field_t kPointerOneofFields[] = {
    PB_ONEOF_FIELD(choice, 1, BYTES, ONEOF, POINTER, FIRST, PointerOneofFixture,
                   value, value, &kDescriptorSentinel),
    PB_LAST_FIELD};

struct AnonymousStaticOneofFixture {
  pb_size_t which_choice;
  union {
    ThreeByteArray value;
  };
};

const pb_field_t kAnonymousStaticOneofFields[] = {
    PB_ANONYMOUS_ONEOF_FIELD(choice, 1, BYTES, ONEOF, STATIC, FIRST,
                             AnonymousStaticOneofFixture, value, value,
                             &kDescriptorSentinel),
    PB_LAST_FIELD};

struct AnonymousPointerOneofFixture {
  pb_size_t which_choice;
  union {
    ThreeByteArray *value;
  };
};

const pb_field_t kAnonymousPointerOneofFields[] = {
    PB_ANONYMOUS_ONEOF_FIELD(choice, 1, BYTES, ONEOF, POINTER, FIRST,
                             AnonymousPointerOneofFixture, value, value,
                             &kDescriptorSentinel),
    PB_LAST_FIELD};

}  // namespace

typedef PB_BYTES_ARRAY_T(3) OddBytes;

struct FixedBytesDescriptorProbe {
  pb_size_t values_count;
  OddBytes values[2];
};

struct OneofBytesDescriptorProbe {
  pb_size_t which_choice;
  union {
    OddBytes value;
  } choice;
};

struct AnonymousOneofBytesDescriptorProbe {
  pb_size_t which_choice;
  union {
    OddBytes anonymous_value;
  };
};

static const pb_field_t fixed_bytes_probe = PB_REPEATED_FIXED_COUNT(
    1, BYTES, FIRST, FixedBytesDescriptorProbe, values, values, nullptr);
static const pb_field_t oneof_bytes_probe =
    PB_ONEOF_FIELD(choice, 1, BYTES, ONEOF, STATIC, FIRST,
                   OneofBytesDescriptorProbe, value, choice, nullptr);
static const pb_field_t anonymous_oneof_bytes_probe = PB_ANONYMOUS_ONEOF_FIELD(
    choice, 1, BYTES, ONEOF, STATIC, FIRST, AnonymousOneofBytesDescriptorProbe,
    anonymous_value, anonymous_value, nullptr);

TEST(NanopbBounds, OddSizedBytesAcceptsDeclaredMaximum) {
  uint8_t wire[2 + 73] = {0x12, 73};  // signatures field, length-delimited
  memset(wire + 2, 0xA5, sizeof(wire) - 2);

  MultisigRedeemScriptType message = MultisigRedeemScriptType_init_zero;
  pb_istream_t stream = pb_istream_from_buffer(wire, sizeof(wire));
  ASSERT_TRUE(pb_decode(&stream, MultisigRedeemScriptType_fields, &message));
  ASSERT_EQ(1u, message.signatures_count);
  EXPECT_EQ(73u, message.signatures[0].size);
}

TEST(NanopbBounds, OddSizedBytesRejectsAlignmentPaddingByte) {
  uint8_t wire[2 + 74] = {0x12, 74};  // one byte beyond max_size:73
  memset(wire + 2, 0xA5, sizeof(wire) - 2);

  MultisigRedeemScriptType message = MultisigRedeemScriptType_init_zero;
  pb_istream_t stream = pb_istream_from_buffer(wire, sizeof(wire));
  EXPECT_FALSE(pb_decode(&stream, MultisigRedeemScriptType_fields, &message));
}

TEST(NanopbBounds, DescriptorKeepsCapacitySeparateFromAlignedStride) {
  const pb_field_t &signatures = MultisigRedeemScriptType_fields[1];
  EXPECT_EQ(73u, signatures.bytes_capacity);
  EXPECT_EQ(sizeof(MultisigRedeemScriptType_signatures_t),
            signatures.data_size);
  EXPECT_GT(signatures.data_size,
            PB_BYTES_ARRAY_T_ALLOCSIZE(signatures.bytes_capacity));
}

TEST(NanopbBounds, FixedCountDescriptorKeepsCapacityArraySizeAndPointer) {
  EXPECT_EQ(3u, kFixedCountBytesFields[0].bytes_capacity);
  EXPECT_EQ(2u, kFixedCountBytesFields[0].array_size);
  EXPECT_EQ(&kDescriptorSentinel, kFixedCountBytesFields[0].ptr);
}

TEST(NanopbBounds, OneofDescriptorFamiliesKeepCapacityAndPointerSlots) {
  EXPECT_EQ(3u, kStaticOneofFields[0].bytes_capacity);
  EXPECT_EQ(0u, kStaticOneofFields[0].array_size);
  EXPECT_EQ(&kDescriptorSentinel, kStaticOneofFields[0].ptr);

  EXPECT_EQ(0u, kPointerOneofFields[0].bytes_capacity);
  EXPECT_EQ(0u, kPointerOneofFields[0].array_size);
  EXPECT_EQ(&kDescriptorSentinel, kPointerOneofFields[0].ptr);

  EXPECT_EQ(3u, kAnonymousStaticOneofFields[0].bytes_capacity);
  EXPECT_EQ(0u, kAnonymousStaticOneofFields[0].array_size);
  EXPECT_EQ(&kDescriptorSentinel, kAnonymousStaticOneofFields[0].ptr);

  EXPECT_EQ(0u, kAnonymousPointerOneofFields[0].bytes_capacity);
  EXPECT_EQ(0u, kAnonymousPointerOneofFields[0].array_size);
  EXPECT_EQ(&kDescriptorSentinel, kAnonymousPointerOneofFields[0].ptr);
}

TEST(NanopbBounds, AlternateDescriptorMacrosInitializeCapacityAndShape) {
  EXPECT_EQ(3u, fixed_bytes_probe.bytes_capacity);
  EXPECT_EQ(2u, fixed_bytes_probe.array_size);
  EXPECT_EQ(sizeof(OddBytes), fixed_bytes_probe.data_size);
  EXPECT_EQ(nullptr, fixed_bytes_probe.ptr);

  EXPECT_EQ(3u, oneof_bytes_probe.bytes_capacity);
  EXPECT_EQ(0u, oneof_bytes_probe.array_size);
  EXPECT_EQ(sizeof(OddBytes), oneof_bytes_probe.data_size);
  EXPECT_EQ(nullptr, oneof_bytes_probe.ptr);

  EXPECT_EQ(3u, anonymous_oneof_bytes_probe.bytes_capacity);
  EXPECT_EQ(0u, anonymous_oneof_bytes_probe.array_size);
  EXPECT_EQ(sizeof(OddBytes), anonymous_oneof_bytes_probe.data_size);
  EXPECT_EQ(nullptr, anonymous_oneof_bytes_probe.ptr);
}
