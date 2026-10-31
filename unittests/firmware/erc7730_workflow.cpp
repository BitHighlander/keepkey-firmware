#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <vector>

extern "C" {
#include "keepkey/firmware/erc7730_workflow.h"
}

static void prepareTypedUintWorkflow(Erc7730Workflow* workflow) {
  workflow->typed_data = true;
  workflow->phase = ERC7730_WORKFLOW_READY;
  workflow->loader.abi_started = true;
  workflow->loader.index.complete = true;
  workflow->loader.abi.complete = true;
  workflow->loader.abi.node_count = 2;
  workflow->loader.abi.nodes[0].kind = ERC7730_ABI_TUPLE;
  workflow->loader.abi.nodes[0].first_child = 1;
  workflow->loader.abi.nodes[0].child_count = 1;
  workflow->loader.abi.nodes[1].kind = ERC7730_ABI_UINT;
  workflow->loader.abi.nodes[1].size = 256;
}

TEST(Erc7730Workflow, RejectsAStartWithNoPreloadedDefinition) {
  erc7730_catalog_clear_preload();
  Erc7730Workflow workflow{};
  Erc7730CatalogIdentity identity{};
  identity.kind = ERC7730_DEFINITION_CALLDATA;
  EthereumSignTx tx{};
  tx.has_data_length = true;
  tx.data_length = 36;
  tx.has_data_initial_chunk = true;
  tx.data_initial_chunk.size = 4;
  EXPECT_FALSE(erc7730_workflow_begin(&workflow, &identity, &tx));
  EXPECT_EQ(workflow.phase, ERC7730_WORKFLOW_FAILED);
}

TEST(Erc7730Workflow,
     SigningReplayMustMatchReviewedBytesAcrossChunkBoundaries) {
  for (bool change_value : {false, true}) {
    Erc7730Workflow workflow{};
    prepareTypedUintWorkflow(&workflow);
    workflow.typed_data = false;
    EthereumSignTx tx{};
    tx.has_data_length = true;
    tx.data_length = 36;
    tx.has_data_initial_chunk = true;
    tx.data_initial_chunk.size = 4;
    tx.data_initial_chunk.bytes[0] = 0xaa;
    ASSERT_TRUE(erc7730_tx_continuation_capture(&workflow.continuation, &tx));
    ASSERT_TRUE(erc7730_workflow_restore_and_start_calldata(&workflow, &tx));
    uint8_t value[32] = {0};
    value[31] = 42;
    ASSERT_EQ(erc7730_workflow_calldata_feed(&workflow, value, 32),
              ERC7730_ABI_OK);
    ASSERT_EQ(erc7730_workflow_calldata_finish(&workflow), ERC7730_ABI_OK);
    ASSERT_TRUE(erc7730_workflow_start_signing(&workflow, &tx));
    EXPECT_FALSE(erc7730_workflow_complete(&workflow));
    if (change_value) value[31] = 43;
    ASSERT_EQ(erc7730_workflow_calldata_feed(&workflow, value, 7),
              ERC7730_ABI_OK);
    ASSERT_EQ(erc7730_workflow_calldata_feed(&workflow, value + 7, 25),
              ERC7730_ABI_OK);
    EXPECT_EQ(erc7730_workflow_calldata_finish(&workflow),
              change_value ? ERC7730_ABI_NON_CANONICAL : ERC7730_ABI_OK);
    EXPECT_EQ(erc7730_workflow_complete(&workflow), !change_value);
  }
}

TEST(Erc7730Workflow, RefusesDataOutsideAuthenticatedLifecycle) {
  Erc7730Workflow workflow{};
  const uint8_t byte = 0;
  EXPECT_EQ(erc7730_workflow_calldata_feed(&workflow, &byte, 1),
            ERC7730_ABI_BOUNDS);
  EXPECT_EQ(workflow.phase, ERC7730_WORKFLOW_FAILED);
  EXPECT_EQ(erc7730_workflow_calldata_finish(&workflow), ERC7730_ABI_BOUNDS);
  EXPECT_FALSE(erc7730_workflow_active(&workflow));
  EXPECT_FALSE(erc7730_workflow_complete(&workflow));
}

TEST(Erc7730Workflow, StateIsBoundedIndependentlyOfDescriptorSize) {
  // Host (64-bit) layout. Phase E2 added the inner call's context (184 B on
  // ARM, where tools/check_sram_budget.py is the real gate); 7.17 B5c the
  // suffix tail the review shows (ERC7730_SUFFIX_SHOWN_MAX, 128 B); 7.17 the
  // resume state of a second embedded level (136 B on the host); 7.17 the
  // setup() module call SafeToL2Setup is recognised from (64 B); 7.17 the
  // settlement state, which shares the suffix tail's bytes (typed data has
  // no suffix).
  static_assert(sizeof(Erc7730Settle) > ERC7730_SUFFIX_SHOWN_MAX, "union");
  EXPECT_LE(sizeof(Erc7730Workflow),
            4352u + sizeof(Erc7730Settle) + 136u + 64u);
}

TEST(Erc7730Workflow, ReportsOnlyUnvalidatedCalldataAsWaiting) {
  Erc7730Workflow workflow{};
  size_t remaining = 99;
  EXPECT_FALSE(erc7730_workflow_calldata_waiting(&workflow, &remaining));
  workflow.phase = ERC7730_WORKFLOW_CALLDATA;
  // Every pass replays the whole outer calldata, also while an inner call's
  // bytes are the only ones decoded.
  workflow.outer_total = 96;
  workflow.outer_received = 32;
  ASSERT_TRUE(erc7730_workflow_calldata_waiting(&workflow, &remaining));
  EXPECT_EQ(remaining, 64u);
  workflow.outer_received = 96;
  EXPECT_FALSE(erc7730_workflow_calldata_waiting(&workflow, &remaining));
  EXPECT_EQ(remaining, 0u);
  workflow.outer_received = 97;
  EXPECT_FALSE(erc7730_workflow_calldata_waiting(&workflow, &remaining));
}

TEST(Erc7730Workflow, CapturesAndFormatsExactTypedDataLeaf) {
  Erc7730Workflow workflow{};
  prepareTypedUintWorkflow(&workflow);
  Erc7730Path path{};
  path.source = 1;
  path.step_count = 1;
  path.source_index = UINT16_MAX;
  path.steps[0].opcode = 1;
  path.steps[0].first = 0;
  ASSERT_TRUE(erc7730_workflow_start_eip712_capture(&workflow, &path));

  const uint32_t member_path[2] = {1, 0};
  uint8_t value[32] = {0};
  value[31] = 42;
  ASSERT_TRUE(erc7730_workflow_eip712_observe(
      &workflow, member_path, 2, value, sizeof(value), sizeof(value), false));
  EXPECT_FALSE(erc7730_workflow_eip712_observe(
      &workflow, member_path, 2, value, sizeof(value), sizeof(value), false));
  ASSERT_TRUE(erc7730_workflow_eip712_finish(&workflow));
  char formatted[16];
  ASSERT_TRUE(erc7730_workflow_format_captured_raw(&workflow, formatted,
                                                   sizeof(formatted)));
  EXPECT_STREQ(formatted, "42");
}

// A bytes or string value over one ack's limit arrives in chunks under one
// member path. It is observed once, with the whole value's length; the later
// chunks must not be taken for a repeat of the leaf.
TEST(Erc7730Workflow, ChunkedTypedDataLeafIsObservedOnceWithItsWholeLength) {
  Erc7730Workflow workflow{};
  prepareTypedUintWorkflow(&workflow);
  workflow.loader.abi.nodes[1].kind = ERC7730_ABI_BYTES;
  workflow.loader.abi.nodes[1].size = 0;
  Erc7730Path path{};
  path.source = 1;
  path.step_count = 1;
  path.source_index = UINT16_MAX;
  path.steps[0].opcode = 1;
  path.steps[0].first = 0;
  ASSERT_TRUE(erc7730_workflow_start_eip712_capture(&workflow, &path));

  const uint32_t member_path[2] = {1, 0};
  const uint8_t chunk[1024] = {0};
  ASSERT_TRUE(erc7730_workflow_eip712_observe(&workflow, member_path, 2, chunk,
                                              sizeof(chunk), 1500, false));
  EXPECT_TRUE(workflow.calldata.capture_overflow);
  EXPECT_EQ(workflow.calldata.located_length, 1500u);
  EXPECT_TRUE(erc7730_workflow_eip712_observe(&workflow, member_path, 2, chunk,
                                              476, 476, true));
  // A second first-chunk for the same leaf is still a repeat.
  EXPECT_FALSE(erc7730_workflow_eip712_observe(&workflow, member_path, 2, chunk,
                                               sizeof(chunk), 1500, false));
  EXPECT_TRUE(erc7730_workflow_eip712_finish(&workflow));
}

// A continuation can only follow a first chunk that was too long to capture.
TEST(Erc7730Workflow, TypedDataContinuationNeedsALongFirstChunk) {
  Erc7730Workflow workflow{};
  prepareTypedUintWorkflow(&workflow);
  Erc7730Path path{};
  path.source = 1;
  path.step_count = 1;
  path.source_index = UINT16_MAX;
  path.steps[0].opcode = 1;
  path.steps[0].first = 0;
  ASSERT_TRUE(erc7730_workflow_start_eip712_capture(&workflow, &path));
  const uint32_t member_path[2] = {1, 0};
  uint8_t value[32] = {0};
  EXPECT_FALSE(erc7730_workflow_eip712_observe(
      &workflow, member_path, 2, value, sizeof(value), sizeof(value), true));
  // A value that fits one ack never claims more bytes than it carries.
  EXPECT_FALSE(erc7730_workflow_eip712_observe(&workflow, member_path, 2, value,
                                               sizeof(value), 64, false));
  ASSERT_TRUE(erc7730_workflow_eip712_observe(
      &workflow, member_path, 2, value, sizeof(value), sizeof(value), false));
  EXPECT_FALSE(erc7730_workflow_eip712_observe(
      &workflow, member_path, 2, value, sizeof(value), sizeof(value), true));
}

TEST(Erc7730Workflow, TypedDataCaptureFailsClosedOnMissingOrWrongWidthValue) {
  Erc7730Workflow workflow{};
  prepareTypedUintWorkflow(&workflow);
  Erc7730Path path{};
  path.source = 1;
  path.step_count = 1;
  path.source_index = UINT16_MAX;
  path.steps[0].opcode = 1;
  path.steps[0].first = 0;
  ASSERT_TRUE(erc7730_workflow_start_eip712_capture(&workflow, &path));
  const uint32_t other_path[2] = {1, 1};
  uint8_t value[32] = {0};
  EXPECT_TRUE(erc7730_workflow_eip712_observe(
      &workflow, other_path, 2, value, sizeof(value), sizeof(value), false));
  EXPECT_FALSE(erc7730_workflow_eip712_finish(&workflow));
  const uint32_t target_path[2] = {1, 0};
  EXPECT_FALSE(erc7730_workflow_eip712_observe(&workflow, target_path, 2, value,
                                               sizeof(value) - 1,
                                               sizeof(value) - 1, false));
}

TEST(Erc7730Workflow, TypedDataReplayBindsBothDomainAndMessageHashes) {
  for (bool change_domain : {false, true}) {
    Erc7730Workflow workflow{};
    workflow.typed_data = true;
    workflow.phase = ERC7730_WORKFLOW_COMPLETE;
    uint8_t domain[32] = {1};
    uint8_t message[32] = {2};
    ASSERT_TRUE(erc7730_workflow_eip712_commit(&workflow, domain, message));
    EXPECT_TRUE(erc7730_workflow_eip712_commit(&workflow, domain, message));
    if (change_domain)
      domain[31] ^= 1;
    else
      message[31] ^= 1;
    EXPECT_FALSE(erc7730_workflow_eip712_commit(&workflow, domain, message));
    EXPECT_EQ(workflow.phase, ERC7730_WORKFLOW_FAILED);
  }
}

TEST(Erc7730Workflow, ResolvesNegativeTypedArrayIndexFromStreamedLength) {
  Erc7730Workflow workflow{};
  workflow.typed_data = true;
  workflow.phase = ERC7730_WORKFLOW_READY;
  workflow.loader.abi_started = true;
  workflow.loader.index.complete = true;
  workflow.loader.abi.complete = true;
  workflow.loader.abi.node_count = 3;
  workflow.loader.abi.nodes[0].kind = ERC7730_ABI_TUPLE;
  workflow.loader.abi.nodes[0].first_child = 1;
  workflow.loader.abi.nodes[0].child_count = 1;
  workflow.loader.abi.nodes[1].kind = ERC7730_ABI_ARRAY;
  workflow.loader.abi.nodes[1].first_child = 2;
  workflow.loader.abi.nodes[1].child_count = 1;
  workflow.loader.abi.nodes[1].array_length = ERC7730_ABI_DYNAMIC_ARRAY;
  workflow.loader.abi.nodes[2].kind = ERC7730_ABI_UINT;
  workflow.loader.abi.nodes[2].size = 256;

  Erc7730Path path{};
  path.source = 1;
  path.step_count = 2;
  path.source_index = UINT16_MAX;
  path.steps[0].opcode = 1;
  path.steps[0].first = 0;
  path.steps[1].opcode = 1;
  path.steps[1].first = -1;
  ASSERT_TRUE(erc7730_workflow_start_eip712_capture(&workflow, &path));

  const uint32_t array_path[2] = {1, 0};
  const uint8_t length[2] = {0, 3};
  ASSERT_TRUE(erc7730_workflow_eip712_observe(
      &workflow, array_path, 2, length, sizeof(length), sizeof(length), false));
  const uint32_t last_element_path[3] = {1, 0, 2};
  uint8_t value[32] = {0};
  value[31] = 7;
  ASSERT_TRUE(erc7730_workflow_eip712_observe(&workflow, last_element_path, 3,
                                              value, sizeof(value),
                                              sizeof(value), false));
  EXPECT_TRUE(erc7730_workflow_eip712_finish(&workflow));
}

// Seaport's shape: OrderComponents(Item[] offer), Item(address token,
// uint256 amount). Paths offer.[] and offer.[].amount.
static void prepareTypedItemsWorkflow(Erc7730Workflow* workflow) {
  *workflow = Erc7730Workflow{};
  workflow->typed_data = true;
  workflow->phase = ERC7730_WORKFLOW_READY;
  workflow->loader.abi_started = true;
  workflow->loader.index.complete = true;
  workflow->loader.abi.complete = true;
  workflow->loader.abi.node_count = 5;
  Erc7730AbiNode* n = workflow->loader.abi.nodes;
  n[0].kind = ERC7730_ABI_TUPLE;
  n[0].first_child = 1;
  n[0].child_count = 1;
  n[1].kind = ERC7730_ABI_ARRAY;
  n[1].first_child = 2;
  n[1].child_count = 1;
  n[1].array_length = ERC7730_ABI_DYNAMIC_ARRAY;
  n[2].kind = ERC7730_ABI_TUPLE;
  n[2].first_child = 3;
  n[2].child_count = 2;
  n[3].kind = ERC7730_ABI_ADDRESS;
  n[3].size = 160;
  n[4].kind = ERC7730_ABI_UINT;
  n[4].size = 256;
}

static Erc7730Path itemsPath(bool amount) {
  Erc7730Path path{};
  path.source = 1;
  path.source_index = UINT16_MAX;
  path.step_count = amount ? 3 : 2;
  path.steps[0].opcode = 1;
  path.steps[0].first = 0;
  path.steps[1].opcode = 2; /* every element */
  path.steps[2].opcode = 1;
  path.steps[2].first = 1;
  return path;
}

// 7.17: a typed-data iteration counts its array from the length the stream
// sends at the array's path, then each element's field captures that element.
TEST(Erc7730Workflow, TypedDataIterationCountsThenCapturesEachElement) {
  Erc7730Workflow workflow;
  prepareTypedItemsWorkflow(&workflow);
  const Erc7730Path items = itemsPath(false);
  const Erc7730Path amount = itemsPath(true);
  // An "every element" step outside an iteration names no element.
  EXPECT_FALSE(erc7730_workflow_start_eip712_capture(&workflow, &amount));
  // A count is of an array, never of a leaf.
  EXPECT_FALSE(erc7730_workflow_start_eip712_length(&workflow, &amount));
  ASSERT_TRUE(erc7730_workflow_start_eip712_length(&workflow, &items));
  const uint32_t array_path[2] = {1, 0};
  const uint8_t three[3] = {0, 0, 2};
  EXPECT_FALSE(erc7730_workflow_eip712_observe(&workflow, array_path, 2, three,
                                               3, 3, false));
  prepareTypedItemsWorkflow(&workflow);
  ASSERT_TRUE(erc7730_workflow_start_eip712_length(&workflow, &items));
  const uint8_t two[2] = {0, 2};
  ASSERT_TRUE(erc7730_workflow_eip712_observe(&workflow, array_path, 2, two, 2,
                                              2, false));
  ASSERT_TRUE(erc7730_workflow_eip712_finish(&workflow));
  Erc7730AbiCapture capture;
  uint8_t cls = 0;
  ASSERT_TRUE(erc7730_workflow_captured(&workflow, &capture, &cls));
  EXPECT_EQ(cls, ERC7730_ABI_ARRAY);
  EXPECT_EQ(capture.length, 32u);
  EXPECT_EQ(capture.data[30], 0);
  EXPECT_EQ(capture.data[31], 2);

  // Element 1's amount: element 0's is not it.
  ASSERT_TRUE(erc7730_workflow_resume_field(&workflow));
  workflow.iterating = true;
  workflow.iteration_index = 1;
  workflow.iteration_count = 2;
  // No count is taken inside an iteration.
  EXPECT_FALSE(erc7730_workflow_start_eip712_length(&workflow, &items));
  ASSERT_TRUE(erc7730_workflow_start_eip712_capture(&workflow, &amount));
  ASSERT_TRUE(erc7730_workflow_eip712_observe(&workflow, array_path, 2, two, 2,
                                              2, false));
  uint8_t value[32] = {0};
  const uint32_t first_amount[4] = {1, 0, 0, 1};
  value[31] = 7;
  ASSERT_TRUE(erc7730_workflow_eip712_observe(&workflow, first_amount, 4, value,
                                              32, 32, false));
  EXPECT_FALSE(workflow.calldata.capture_found);
  const uint32_t second_amount[4] = {1, 0, 1, 1};
  value[31] = 42;
  ASSERT_TRUE(erc7730_workflow_eip712_observe(&workflow, second_amount, 4,
                                              value, 32, 32, false));
  EXPECT_TRUE(workflow.calldata.capture_found);
  ASSERT_TRUE(erc7730_workflow_eip712_finish(&workflow));
  char formatted[16];
  ASSERT_TRUE(erc7730_workflow_format_captured_raw(&workflow, formatted,
                                                   sizeof(formatted)));
  EXPECT_STREQ(formatted, "42");
}

TEST(Erc7730Workflow, InnerDefinitionIsNeverShownAboveItsOuterTier) {
  const struct {
    uint8_t outer, inner, shown;
  } cases[] = {
      {METADATA_TIER_RUNTIME, METADATA_TIER_KEEPKEY, METADATA_TIER_RUNTIME},
      {METADATA_TIER_KEEPKEY, METADATA_TIER_RUNTIME, METADATA_TIER_RUNTIME},
      {METADATA_TIER_KEEPKEY, METADATA_TIER_KEEPKEY, METADATA_TIER_KEEPKEY},
      {METADATA_TIER_RUNTIME, METADATA_TIER_RUNTIME, METADATA_TIER_RUNTIME},
  };
  for (const auto& c : cases) {
    Erc7730Workflow workflow{};
    workflow.phase = ERC7730_WORKFLOW_READY;
    workflow.identity.tier = c.outer;
    workflow.field.kind = 13;
    workflow.field.has_inner = true;
    workflow.field.has_address = true;
    workflow.field.inner_selector_length = 4;
    workflow.field.inner_length = 4;
    EXPECT_EQ(erc7730_workflow_tier(&workflow), c.outer);
    ASSERT_TRUE(erc7730_workflow_begin_fetch(&workflow, 1));
    // What erc7730_workflow_fetch_complete installs for a bound inner
    // definition: its own identity, at depth 1.
    workflow.identity.tier = c.inner;
    workflow.depth = 1;
    EXPECT_EQ(erc7730_workflow_tier(&workflow), c.shown)
        << (int)c.outer << " " << (int)c.inner;
  }
}

/* #821: every host-streamed calldata pass must carry the bytes the first pass
 * reviewed, and the signing pass must match them. A hostile host that shows
 * benign arguments and signs different ones of the same length is refused. */
static void prepareCalldataWorkflow(Erc7730Workflow* workflow,
                                    EthereumSignTx* tx) {
  prepareTypedUintWorkflow(workflow);
  workflow->typed_data = false;
  tx->has_data_length = true;
  tx->data_length = 36;
  tx->has_data_initial_chunk = true;
  tx->data_initial_chunk.size = 4;
  tx->data_initial_chunk.bytes[0] = 0xaa;
  ASSERT_TRUE(erc7730_tx_continuation_capture(&workflow->continuation, tx));
}

static Erc7730AbiResult hostPass(Erc7730Workflow* workflow, EthereumSignTx* tx,
                                 uint8_t fill) {
  // A later display pass starts from the field the previous one completed.
  if (workflow->phase == ERC7730_WORKFLOW_COMPLETE &&
      !erc7730_workflow_resume_field(workflow))
    return ERC7730_ABI_BOUNDS;
  if (!erc7730_workflow_restore_and_start_calldata(workflow, tx))
    return ERC7730_ABI_BOUNDS;
  uint8_t word[32] = {0};
  word[31] = fill;
  const Erc7730AbiResult fed =
      erc7730_workflow_calldata_feed(workflow, word, sizeof(word));
  if (fed != ERC7730_ABI_OK) return fed;
  return erc7730_workflow_calldata_finish(workflow);
}

static bool signingPass(Erc7730Workflow* workflow, EthereumSignTx* tx,
                        uint8_t fill) {
  if (!erc7730_workflow_start_signing(workflow, tx)) return false;
  uint8_t word[32] = {0};
  word[31] = fill;
  return erc7730_workflow_calldata_feed(workflow, word, 16) == ERC7730_ABI_OK &&
         erc7730_workflow_calldata_feed(workflow, word + 16, 16) ==
             ERC7730_ABI_OK &&
         erc7730_workflow_calldata_finish(workflow) == ERC7730_ABI_OK;
}

TEST(Erc7730Workflow, DisplayPassesMustCarryTheSameCalldata) {
  Erc7730Workflow workflow{};
  EthereumSignTx tx{};
  prepareCalldataWorkflow(&workflow, &tx);
  ASSERT_EQ(hostPass(&workflow, &tx, 1), ERC7730_ABI_OK);  // field capture
  ASSERT_EQ(hostPass(&workflow, &tx, 1), ERC7730_ABI_OK);  // later pass
  EXPECT_NE(hostPass(&workflow, &tx, 2), ERC7730_ABI_OK);  // swapped argument
  EXPECT_EQ(workflow.phase, ERC7730_WORKFLOW_FAILED);
}

TEST(Erc7730Workflow, SigningPassMustMatchReviewedCalldata) {
  Erc7730Workflow workflow{};
  EthereumSignTx tx{};
  prepareCalldataWorkflow(&workflow, &tx);
  ASSERT_EQ(hostPass(&workflow, &tx, 7), ERC7730_ABI_OK);
  EXPECT_TRUE(signingPass(&workflow, &tx, 7));
  EXPECT_FALSE(
      signingPass(&workflow, &tx, 8));  // benign review, malicious sign
  EXPECT_EQ(workflow.phase, ERC7730_WORKFLOW_FAILED);
}

TEST(Erc7730Workflow, NoReviewedCalldataMeansNoneMayBeSigned) {
  Erc7730Workflow workflow{};
  EthereumSignTx tx{};
  prepareCalldataWorkflow(&workflow, &tx);
  EXPECT_FALSE(signingPass(&workflow, &tx, 1));
  EXPECT_EQ(workflow.phase, ERC7730_WORKFLOW_FAILED);
  // Nothing streamed afterwards becomes the reviewed calldata.
  EXPECT_FALSE(erc7730_workflow_restore_and_start_calldata(&workflow, &tx));
}

// f(address to, bytes data) with the embedded call `inner` as data: run the
// pass that locates it, as a calldata formatter's first argument does.
static bool locateEmbedded(Erc7730Workflow* workflow,
                           const std::vector<uint8_t>& inner) {
  *workflow = Erc7730Workflow{};
  workflow->phase = ERC7730_WORKFLOW_READY;
  workflow->loader.abi_started = true;
  workflow->loader.index.complete = true;
  workflow->loader.abi.complete = true;
  workflow->loader.abi.node_count = 3;
  workflow->loader.abi.nodes[0].kind = ERC7730_ABI_TUPLE;
  workflow->loader.abi.nodes[0].first_child = 1;
  workflow->loader.abi.nodes[0].child_count = 2;
  workflow->loader.abi.nodes[1].kind = ERC7730_ABI_ADDRESS;
  workflow->loader.abi.nodes[2].kind = ERC7730_ABI_BYTES;
  workflow->field.kind = 13;
  workflow->field.pending_role = 1;

  std::vector<uint8_t> args(64 + 32, 0);
  args[31] = 0x11;  // to
  args[63] = 64;    // data offset
  args[94] = (uint8_t)(inner.size() >> 8);
  args[95] = (uint8_t)inner.size();
  args.insert(args.end(), inner.begin(), inner.end());
  args.resize(args.size() + (32 - inner.size() % 32) % 32, 0);

  EthereumSignTx tx{};
  tx.has_data_length = true;
  tx.data_length = 4 + args.size();
  tx.has_data_initial_chunk = true;
  tx.data_initial_chunk.size = 4;
  if (!erc7730_tx_continuation_capture(&workflow->continuation, &tx))
    return false;
  Erc7730Path path{};
  path.source = 1;
  path.step_count = 1;
  path.source_index = UINT16_MAX;
  path.steps[0].opcode = 1;
  path.steps[0].first = 1;
  return erc7730_workflow_restore_and_start_capture(workflow, &tx, &path) &&
         erc7730_workflow_calldata_feed(workflow, args.data(), args.size()) ==
             ERC7730_ABI_OK &&
         erc7730_workflow_calldata_finish(workflow) == ERC7730_ABI_OK &&
         erc7730_workflow_field_embedded(workflow);
}

static std::vector<uint8_t> innerApprove(uint8_t amount_byte) {
  std::vector<uint8_t> call = {0x09, 0x5e, 0xa7, 0xb3};
  call.resize(68, 0);
  for (size_t i = 16; i < 36; i++) call[i] = 0x22;  // spender
  for (size_t i = 36; i < 68; i++) call[i] = amount_byte;
  return call;
}

// An embedded approve() gets the top-level policy: an amount of 2^255 or
// more is flagged for the UNLIMITED warning with its full spender, a smaller
// one is not, and a dirty spender word is refused.
TEST(Erc7730Workflow, EmbeddedApproveIsClassifiedLikeATopLevelOne) {
  Erc7730Workflow workflow{};
  ASSERT_TRUE(locateEmbedded(&workflow, innerApprove(0xff)));
  EXPECT_TRUE(workflow.field.unlimited_approve);
  const uint8_t spender[20] = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                               0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                               0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
  EXPECT_EQ(0, memcmp(workflow.field.approve_spender, spender, 20));
  EXPECT_EQ(workflow.field.inner_selector_length, 4u);
  EXPECT_EQ(workflow.field.inner_length, 68u);

  // The threshold is the top-level one: 2^255 exactly is unlimited, and
  // 2^255 - 1 is not.
  auto threshold = innerApprove(0x00);
  threshold[36] = 0x80;
  ASSERT_TRUE(locateEmbedded(&workflow, threshold));
  EXPECT_TRUE(workflow.field.unlimited_approve);
  auto almost = innerApprove(0xff);
  almost[36] = 0x7f;
  ASSERT_TRUE(locateEmbedded(&workflow, almost));
  EXPECT_FALSE(workflow.field.unlimited_approve);
  ASSERT_TRUE(locateEmbedded(&workflow, innerApprove(0x01)));
  EXPECT_FALSE(workflow.field.unlimited_approve);

  // Trailing bytes do not hide it, as they do not at the top level.
  auto longer = innerApprove(0xff);
  longer.resize(100, 0xab);
  ASSERT_TRUE(locateEmbedded(&workflow, longer));
  EXPECT_TRUE(workflow.field.unlimited_approve);
  EXPECT_EQ(workflow.field.inner_length, 100u);

  auto dirty = innerApprove(0xff);
  dirty[15] = 1;  // pre-0.8 tokens mask it and still grant the allowance
  EXPECT_FALSE(locateEmbedded(&workflow, dirty));

  // increaseAllowance grants the same allowance and is classified the same.
  auto increase = innerApprove(0xff);
  const uint8_t selector[4] = {0x39, 0x50, 0x93, 0x51};
  std::copy(selector, selector + 4, increase.begin());
  ASSERT_TRUE(locateEmbedded(&workflow, increase));
  EXPECT_TRUE(workflow.field.unlimited_approve);
  EXPECT_EQ(0, memcmp(workflow.field.approve_spender, spender, 20));

  // Another call keeps only its selector.
  auto transfer = innerApprove(0xff);
  transfer[0] = 0xa9;
  ASSERT_TRUE(locateEmbedded(&workflow, transfer));
  EXPECT_FALSE(workflow.field.unlimited_approve);
  EXPECT_EQ(workflow.field.inner_selector[0], 0xa9);
}

// A Safe exec (to, value, data, operation): one full calldata pass, fed in
// `chunk`-byte pieces, of a 68-byte inner call with `operation` in the
// operation word's byte `operation_at` (argument byte 96..127). A byte above
// the last is read as a uint256 word: a uint8 one would not decode.
static bool safeExecPass(Erc7730Workflow* workflow, const uint8_t selector[4],
                         uint8_t operation, size_t chunk,
                         size_t operation_at = 127) {
  *workflow = Erc7730Workflow{};
  memcpy(workflow->identity.selector_or_type_hash, selector, 4);
  workflow->phase = ERC7730_WORKFLOW_READY;
  workflow->loader.abi_started = true;
  workflow->loader.index.complete = true;
  workflow->loader.abi.complete = true;
  workflow->loader.abi.node_count = 5;
  workflow->loader.abi.nodes[0].kind = ERC7730_ABI_TUPLE;
  workflow->loader.abi.nodes[0].first_child = 1;
  workflow->loader.abi.nodes[0].child_count = 4;
  workflow->loader.abi.nodes[1].kind = ERC7730_ABI_ADDRESS;
  workflow->loader.abi.nodes[2].kind = ERC7730_ABI_UINT;
  workflow->loader.abi.nodes[2].size = 256;
  workflow->loader.abi.nodes[3].kind = ERC7730_ABI_BYTES;
  workflow->loader.abi.nodes[4].kind = ERC7730_ABI_UINT;
  workflow->loader.abi.nodes[4].size = operation_at == 127 ? 8 : 256;

  std::vector<uint8_t> args(5 * 32 + 96, 0);
  args[31] = 0x11;        // to
  args[95] = 128;         // data offset
  args[operation_at] = operation;  // operation
  args[159] = 68;         // data length
  args[160] = 0xa9;       // transfer(...)
  EthereumSignTx tx{};
  tx.has_data_length = true;
  tx.data_length = 4 + args.size();
  tx.has_data_initial_chunk = true;
  tx.data_initial_chunk.size = 4;
  memcpy(tx.data_initial_chunk.bytes, selector, 4);
  if (!erc7730_tx_continuation_capture(&workflow->continuation, &tx) ||
      !erc7730_workflow_restore_and_start_calldata(workflow, &tx))
    return false;
  for (size_t at = 0; at < args.size(); at += chunk) {
    const size_t n = std::min(chunk, args.size() - at);
    if (erc7730_workflow_calldata_feed(workflow, args.data() + at, n) !=
        ERC7730_ABI_OK)
      return false;
  }
  return erc7730_workflow_calldata_finish(workflow) == ERC7730_ABI_OK;
}

// The operation word of a Safe exec is read from the signed calldata itself,
// in any chunking; any value but 0 (CALL) marks the embedded call as a
// delegatecall. Other functions of the same shape are not Safe execs.
TEST(Erc7730Workflow, SafeExecOperationIsReadFromTheCalldata) {
  const uint8_t exec[4] = {0x6a, 0x76, 0x12, 0x02};
  const uint8_t module[4] = {0x46, 0x87, 0x21, 0xa7};
  const uint8_t module_data[4] = {0x52, 0x29, 0x07, 0x3f};
  // Zodiac Roles v1/v2 execTransactionWithRole(ReturnData).
  const uint8_t roles_v1[4] = {0x69, 0x28, 0xe7, 0x4b};
  const uint8_t roles_v2[4] = {0xc6, 0xfe, 0x87, 0x47};
  const uint8_t roles_v1_data[4] = {0xb0, 0xc1, 0x99, 0x12};
  const uint8_t roles_v2_data[4] = {0x2b, 0x99, 0xe5, 0x06};
  const uint8_t other[4] = {0x29, 0x23, 0x8e, 0xe4};
  Erc7730Workflow workflow{};
  for (const uint8_t* selector : {exec, module, module_data, roles_v1, roles_v2,
                                  roles_v1_data, roles_v2_data}) {
    for (size_t chunk : {(size_t)1, (size_t)7, (size_t)100, (size_t)256}) {
      ASSERT_TRUE(safeExecPass(&workflow, selector, 1, chunk));
      EXPECT_TRUE(workflow.safe_delegatecall) << chunk;
      ASSERT_TRUE(safeExecPass(&workflow, selector, 0, chunk));
      EXPECT_FALSE(workflow.safe_delegatecall) << chunk;
    }
    ASSERT_TRUE(safeExecPass(&workflow, selector, 2, 256));
    EXPECT_TRUE(workflow.safe_delegatecall);
    // Any byte of the operation word counts.
    for (size_t at : {(size_t)96, (size_t)120}) {
      ASSERT_TRUE(safeExecPass(&workflow, selector, 1, 7, at));
      EXPECT_TRUE(workflow.safe_delegatecall) << at;
    }
  }
  ASSERT_TRUE(safeExecPass(&workflow, other, 1, 256));
  EXPECT_FALSE(workflow.safe_delegatecall);
}

// An outer approve(address,uint256): the first calldata pass, at any chunking,
// records what the top-level allowance policy reads. Later passes record
// nothing; the signing pass is "checked" only once the policy has run.
static void allowancePass(Erc7730Workflow* workflow,
                          const std::vector<uint8_t>& args, size_t chunk) {
  *workflow = Erc7730Workflow{};
  prepareTypedUintWorkflow(workflow);
  workflow->typed_data = false;
  workflow->loader.abi.node_count = 3;
  workflow->loader.abi.nodes[0].child_count = 2;
  workflow->loader.abi.nodes[1].kind = ERC7730_ABI_ADDRESS;
  workflow->loader.abi.nodes[1].size = 0;
  workflow->loader.abi.nodes[2].kind = ERC7730_ABI_UINT;
  workflow->loader.abi.nodes[2].size = 256;
  workflow->allowance = ERC7730_ALLOWANCE_CALL;
  EthereumSignTx tx{};
  tx.has_data_length = true;
  tx.data_length = 68;
  tx.has_data_initial_chunk = true;
  tx.data_initial_chunk.size = 4;
  memcpy(tx.data_initial_chunk.bytes, "\x09\x5e\xa7\xb3", 4);
  ASSERT_TRUE(erc7730_tx_continuation_capture(&workflow->continuation, &tx));
  ASSERT_TRUE(erc7730_workflow_restore_and_start_calldata(workflow, &tx));
  for (size_t at = 0; at < args.size(); at += chunk) {
    const size_t n = std::min(chunk, args.size() - at);
    erc7730_workflow_calldata_feed(workflow, args.data() + at, n);
  }
}

TEST(Erc7730Workflow, FirstPassRecordsTheAllowanceFacts) {
  std::vector<uint8_t> args(64, 0);
  for (size_t i = 12; i < 32; i++) args[i] = (uint8_t)i;  // spender
  for (size_t chunk : {size_t{1}, size_t{7}, size_t{64}}) {
    SCOPED_TRACE(chunk);
    Erc7730Workflow workflow{};
    args[32] = 0x7f;  // 2^255 - 1 and below: finite
    allowancePass(&workflow, args, chunk);
    EXPECT_EQ((unsigned)workflow.allowance, ERC7730_ALLOWANCE_CALL);
    EXPECT_EQ(0, memcmp(workflow.allowance_spender, args.data() + 12, 20));

    args[32] = 0x80;  // 2^255: unlimited
    allowancePass(&workflow, args, chunk);
    EXPECT_EQ((unsigned)workflow.allowance,
              ERC7730_ALLOWANCE_CALL | ERC7730_ALLOWANCE_UNLIMITED);

    std::vector<uint8_t> dirty = args;
    dirty[11] = 1;
    allowancePass(&workflow, dirty, chunk);
    EXPECT_TRUE(workflow.allowance & ERC7730_ALLOWANCE_DIRTY);
  }

  // A later pass records nothing: the first one fixed the facts.
  Erc7730Workflow workflow{};
  args[32] = 0;
  allowancePass(&workflow, args, 64);
  ASSERT_EQ(erc7730_workflow_calldata_finish(&workflow), ERC7730_ABI_OK);
  workflow.calldata_validated = true;
  EXPECT_FALSE(erc7730_workflow_allowance_checked(&workflow));
  workflow.allowance |= ERC7730_ALLOWANCE_CHECKED;
  EthereumSignTx tx{};
  ASSERT_TRUE(erc7730_workflow_start_signing(&workflow, &tx));
  EXPECT_TRUE(erc7730_workflow_allowance_checked(&workflow));
  std::vector<uint8_t> unlimited = args;
  unlimited[32] = 0xff;
  ASSERT_EQ(erc7730_workflow_calldata_feed(&workflow, unlimited.data(), 64),
            ERC7730_ABI_OK);
  EXPECT_FALSE(workflow.allowance & ERC7730_ALLOWANCE_UNLIMITED);
  // ...and the signing pass must still match the reviewed digest.
  EXPECT_NE(erc7730_workflow_calldata_finish(&workflow), ERC7730_ABI_OK);
  EXPECT_FALSE(erc7730_workflow_allowance_checked(&workflow));
}

// 7.17 B5c: the review shows a suffix byte for byte, from the pass that just
// matched the reviewed digest, up to ERC7730_SUFFIX_SHOWN_MAX; a longer one
// is stated by its length alone. Chunks of 5 split words and the suffix.
TEST(Erc7730Workflow, ShowsTheSuffixTheLastPassCarried) {
  for (size_t n :
       {size_t{1}, size_t{24}, size_t{33}, size_t{127},
        size_t{ERC7730_SUFFIX_SHOWN_MAX}, size_t{129}, size_t{300}}) {
    SCOPED_TRACE(n);
    Erc7730Workflow workflow{};
    prepareTypedUintWorkflow(&workflow);
    workflow.typed_data = false;
    workflow.identity.trailing_data = true;
    EthereumSignTx tx{};
    tx.has_data_length = true;
    tx.data_length = (uint32_t)(36 + n);
    tx.has_data_initial_chunk = true;
    tx.data_initial_chunk.size = 4;
    tx.data_initial_chunk.bytes[0] = 0xaa;
    ASSERT_TRUE(erc7730_tx_continuation_capture(&workflow.continuation, &tx));
    std::vector<uint8_t> data(32 + n, 0);
    data[31] = 42;
    for (size_t i = 0; i < n; i++) data[32 + i] = (uint8_t)(7 * i + 1);
    for (int pass = 0; pass < 2; pass++) {
      if (workflow.phase == ERC7730_WORKFLOW_COMPLETE)
        ASSERT_TRUE(erc7730_workflow_resume_field(&workflow));
      ASSERT_TRUE(erc7730_workflow_restore_and_start_calldata(&workflow, &tx));
      for (size_t at = 0; at < data.size(); at += 5) {
        const size_t len = std::min<size_t>(5, data.size() - at);
        ASSERT_EQ(
            erc7730_workflow_calldata_feed(&workflow, data.data() + at, len),
            ERC7730_ABI_OK);
      }
      ASSERT_EQ(erc7730_workflow_calldata_finish(&workflow), ERC7730_ABI_OK);
    }
    EXPECT_EQ(workflow.suffix_length, n);
    uint8_t shown[ERC7730_SUFFIX_SHOWN_MAX];
    const size_t length = erc7730_workflow_suffix(&workflow, shown);
    if (n > ERC7730_SUFFIX_SHOWN_MAX) {
      EXPECT_EQ(length, 0u);
    } else {
      ASSERT_EQ(length, n);
      EXPECT_EQ(0, memcmp(shown, data.data() + 32, n));
    }
  }
  Erc7730Workflow none{};
  uint8_t shown[ERC7730_SUFFIX_SHOWN_MAX];
  EXPECT_EQ(erc7730_workflow_suffix(&none, shown), 0u);
  EXPECT_EQ(erc7730_workflow_suffix(nullptr, shown), 0u);
}
