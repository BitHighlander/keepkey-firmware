#!/usr/bin/env python3
"""Writes unittests/firmware/erc7730_embedded_vectors.h.

Real transactions (embedded_transactions.json: mainnet transactions by hash
and Desktop request captures) and the ERC-7730 programs that describe them,
compiled by python-keepkey's erc7730_compiler (deps/python-keepkey). The
firmware unit tests sign each program with test keys and run the device's
review over the real calldata.

The Safe formats are copied from the official registry
(ethereum/clear-signing-erc7730-registry 9f37816a, registry/safe/
common-Safe.json and common-SafeProxyFactory.json). The others are
KeepKey-authored test descriptors.

Usage: scripts/erc7730/gen_embedded_vectors.py > unittests/firmware/erc7730_embedded_vectors.h
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "deps", "python-keepkey"))

from keepkeylib.erc7730_compiler import compile_calldata  # noqa: E402

FACTORY = "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67"
SAFE_L2 = "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762"
SAFE_141 = "0x41675C099F32341bf84BFc5382aF534df5C7461a"
SAFE_TO_L2_SETUP = "0xBD89A1CE4DDe368FFAB0eC35506eEcE0b1fFdc54"
SAFE_A = "0xe9619c0450fd890e28a5baa09ab2e83e6a02c3fd"  # executes the transfer
SAFE_B = "0x0da96062099823ae487aeb33da6331b8b5001c48"  # sends ETH
SAFE_C = "0x7ef04d8026b553d7ab16c6d4f91878f5345e142b"  # adds an owner
TOKEN = "0x8292bb45bf1ee4d140127049757c2e0ff06317ed"   # the transfer's token
ROUTER02 = "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45"
ALLOWANCE_HOLDER = "0x0000000000001ff3684f28c67538d4d072c22734"
SETTLER = "0x0cef320d0c5793ade37964e2661a033771e53cd5"
ETH_FLOW = "0xba3cb449bd2b4adddbc894d8697f5170800eadec"

SAFE_METADATA = {
    "enums": {"operation": {"0": "Call", "1": "Delegate Call"}},
    "constants": {
        "addressAsNull": "0x0000000000000000000000000000000000000000"},
}

CREATE_PROXY = ("createProxyWithNonce(address _singleton, bytes initializer, "
                "uint256 saltNonce)")
SETUP = ("setup(address[] _owners, uint256 _threshold, address to, bytes data, "
         "address fallbackHandler, address paymentToken, uint256 payment, "
         "address paymentReceiver)")
EXEC = ("execTransaction(address to, uint256 value, bytes data, "
        "uint8 operation, uint256 safeTxGas, uint256 baseGas, "
        "uint256 gasPrice, address gasToken, address refundReceiver, "
        "bytes signatures)")

ADD_OWNER = "addOwnerWithThreshold(address owner, uint256 _threshold)"
SETUP_TO_L2 = "setupToL2(address l2Singleton)"

REGISTRY_FORMATS = {
    CREATE_PROXY: {
        "$id": "createProxyWithNonce", "intent": "Create Safe", "fields": [
            {"path": "_singleton", "label": "Safe singleton",
             "format": "addressName", "params": {"types": ["contract"]},
             "visible": "always"},
            {"path": "initializer", "format": "calldata",
             "label": "Account setup", "params": {"calleePath": "_singleton"}},
            {"label": "Salt Nonce", "path": "saltNonce", "visible": "never"}]},
    SETUP: {
        "$id": "setup", "intent": "Setup Safe", "fields": [
            {"path": "_owners.[]", "label": "Signer", "format": "addressName",
             "params": {"types": ["eoa", "wallet"]}},
            {"path": "_threshold", "label": "Threshold", "format": "raw",
             "visible": "always"},
            {"path": "fallbackHandler", "label": "Fallback handler",
             "format": "addressName", "params": {"types": ["contract"]},
             "visible": "always"},
            {"path": "payment", "label": "Payment", "format": "tokenAmount",
             "params": {"tokenPath": "paymentToken",
                        "nativeCurrencyAddress":
                            "$.metadata.constants.addressAsNull"},
             "visible": "always"},
            {"path": "paymentReceiver", "label": "Payment receiver",
             "format": "addressName",
             "params": {"types": ["eoa", "wallet", "contract"]},
             "visible": "always"},
            {"path": "data", "label": "Module", "format": "calldata",
             "params": {"calleePath": "to"}, "visible": "always"}]},
    EXEC: {
        "$id": "execTransaction", "intent": "sign multisig operation",
        "fields": [
            {"path": "operation", "label": "Operation type", "format": "enum",
             "params": {"$ref": "$.metadata.enums.operation"},
             "visible": "always"},
            {"path": "@.to", "label": "From Safe", "format": "addressName",
             "params": {"types": ["contract"]}},
            {"path": "@.from", "label": "Execution signer",
             "format": "addressName", "params": {"types": ["eoa"]}},
            {"path": "data", "label": "Transaction", "format": "calldata",
             "params": {"calleePath": "to", "amountPath": "value",
                        "spenderPath": "@.to"}, "visible": "always"},
            {"path": "baseGas", "label": "Gas amount", "format": "raw",
             "visible": "always"},
            {"path": "gasPrice", "label": "Gas price", "format": "tokenAmount",
             "params": {"tokenPath": "gasToken",
                        "nativeCurrencyAddress":
                            "$.metadata.constants.addressAsNull"},
             "visible": "always"},
            {"path": "refundReceiver", "label": "Gas receiver",
             "format": "addressName",
             "params": {"types": ["eoa", "wallet", "contract"]},
             "visible": "always"},
            {"label": "Safe Tx Gas", "path": "safeTxGas", "visible": "never"},
            {"label": "Signatures", "path": "signatures",
             "visible": "never"}]},
    ADD_OWNER: {
        "$id": "addOwnerWithThreshold", "intent": "Add signer", "fields": [
            {"path": "owner", "label": "Signer", "format": "addressName",
             "params": {"types": ["eoa"]}, "visible": "always"},
            {"path": "_threshold", "label": "New threshold", "format": "raw",
             "visible": "always"}]},
}


def safe(signature):
    return {"metadata": SAFE_METADATA,
            "display": {"formats": {signature: REGISTRY_FORMATS[signature]}}}


def without_amount(descriptor):
    """The same descriptor with no amountPath on its calldata field."""
    descriptor = json.loads(json.dumps(descriptor))
    for formats in descriptor["display"]["formats"].values():
        for field in formats["fields"]:
            field.get("params", {}).pop("amountPath", None)
    return descriptor


def one(signature, intent, fields):
    return {"display": {"formats": {signature: {
        "intent": intent, "fields": fields}}}}


TRANSFER = "transfer(address to, uint256 amount)"
MULTICALL = "multicall(uint256 deadline, bytes[] data)"
EXACT_INPUT = ("exactInput((bytes path, address recipient, uint256 amountIn, "
               "uint256 amountOutMinimum) params)")
UNWRAP = "unwrapWETH9(uint256 amountMinimum, address recipient)"
ZEROEX_EXEC = ("exec(address operator, address token, uint256 amount, "
               "address target, bytes data)")
SETTLER_EXECUTE = ("execute((address recipient, address buyToken, "
                   "uint256 minAmountOut) slippage, bytes[] actions, "
                   "bytes32 zid)")
CREATE_ORDER = ("createOrder((address buyToken, address receiver, "
                "uint256 sellAmount, uint256 buyAmount, bytes32 appData, "
                "uint256 feeAmount, uint32 validTo, bool partiallyFillable, "
                "int64 quoteId) order)")

PROGRAMS = [
    # G14: the factory, and the singleton's setup() it embeds.
    ("safe_factory", safe(CREATE_PROXY), CREATE_PROXY, FACTORY),
    ("safe_setup", safe(SETUP), SETUP, SAFE_L2),
    # Safe{Wallet}'s 1.4.1 creation: setup() at the Safe singleton, whose
    # module call DELEGATECALLs SafeToL2Setup.setupToL2 (certified here only
    # to show the device refuses it anyway).
    ("safe_setup_141", safe(SETUP), SETUP, SAFE_141),
    ("safe_to_l2_setup", one(SETUP_TO_L2, "Use L2 singleton", [
        {"path": "l2Singleton", "label": "L2 singleton",
         "format": "addressName"}]), SETUP_TO_L2, SAFE_TO_L2_SETUP),
    # G13: execTransaction at each Safe (exact address), and the token.
    ("safe_exec_a", safe(EXEC), EXEC, SAFE_A),
    ("safe_exec_b", safe(EXEC), EXEC, SAFE_B),
    # The same format without amountPath: the value moved is not shown.
    ("safe_exec_b_no_value", without_amount(safe(EXEC)), EXEC, SAFE_B),
    # A Safe calling itself: the inner definition is bound to the same
    # address as the outer one (the transaction's `to`).
    ("safe_exec_c", safe(EXEC), EXEC, SAFE_C),
    ("safe_add_owner", safe(ADD_OWNER), ADD_OWNER, SAFE_C),
    ("token_transfer", one(TRANSFER, "Send", [
        {"path": "to", "label": "To", "format": "addressName",
         "params": {"recipient": True}},
        {"path": "amount", "label": "Amount", "format": "tokenAmount",
         "params": {"tokenPath": "@.to"}}]), TRANSFER, TOKEN),
    # G02: SwapRouter02 multicall, each element a call to the router itself.
    ("router02_multicall", one(MULTICALL, "Swap", [
        {"path": "deadline", "label": "Deadline", "format": "date",
         "params": {"encoding": "timestamp"}},
        {"path": "data.[]", "label": "Step", "format": "calldata",
         "params": {"calleePath": "@.to", "amountPath": "@.value",
                    "spenderPath": "@.from"}}]), MULTICALL, ROUTER02),
    ("router02_exact_input", one(EXACT_INPUT, "Swap exact input", [
        {"path": "params.path", "label": "Path", "format": "raw"},
        {"path": "params.recipient", "label": "Recipient",
         "format": "addressName"},
        {"path": "params.amountIn", "label": "Amount in", "format": "raw"},
        {"path": "params.amountOutMinimum", "label": "Minimum out",
         "format": "raw"}]), EXACT_INPUT, ROUTER02),
    ("router02_unwrap", one(UNWRAP, "Unwrap WETH", [
        {"path": "amountMinimum", "label": "Minimum", "format": "amount"},
        {"path": "recipient", "label": "Recipient", "format": "addressName",
         "params": {"recipient": True}}]), UNWRAP, ROUTER02),
    # G06: 0x AllowanceHolder.exec, then Settler.execute's slippage struct.
    ("zeroex_exec", one(ZEROEX_EXEC, "Swap", [
        {"path": "operator", "label": "Operator", "format": "addressName"},
        {"path": "data", "label": "Route", "format": "calldata",
         "params": {"calleePath": "target", "amountPath": "@.value"}}]),
     ZEROEX_EXEC, ALLOWANCE_HOLDER),
    ("zeroex_settler", one(SETTLER_EXECUTE, "Swap", [
        {"path": "@.value", "label": "Sell", "format": "amount"},
        {"path": "slippage.minAmountOut", "label": "Receive at least",
         "format": "tokenAmount",
         "params": {"tokenPath": "slippage.buyToken"}},
        {"path": "slippage.recipient", "label": "Recipient",
         "format": "addressName", "params": {"recipient": True}},
        {"path": "actions", "label": "Actions", "visible": "never"},
        {"path": "zid", "label": "Id", "visible": "never"}]),
     SETTLER_EXECUTE, SETTLER),
    # G07: CoW EthFlow: the order sells exactly the transaction's ETH.
    ("cow_ethflow", one(CREATE_ORDER, "Sell ETH", [
        {"path": "order.sellAmount", "label": "Sell", "format": "amount",
         "params": {"equalsTxValue": True}},
        {"path": "order.buyAmount", "label": "Receive at least",
         "format": "tokenAmount", "params": {"tokenPath": "order.buyToken"}},
        {"path": "order.receiver", "label": "Receiver",
         "format": "addressName", "params": {"recipient": True}},
        {"path": "order.validTo", "label": "Valid until", "format": "date",
         "params": {"encoding": "timestamp"}},
        {"path": "order.feeAmount", "label": "Fee", "format": "amount"},
        {"path": "order.appData", "label": "App data", "visible": "never"},
        {"path": "order.partiallyFillable", "label": "Partial",
         "visible": "never"},
        {"path": "order.quoteId", "label": "Quote", "visible": "never"}]),
     CREATE_ORDER, ETH_FLOW),
]


def word(value):
    return value.to_bytes(32, "big")


def address_word(address):
    return bytes(12) + bytes.fromhex(address[2:])


def safe_exec(to, data, value=0, operation=0):
    """execTransaction(to, value, data, operation, 0, 0, 0, 0, 0, 65-byte
    signatures): a synthesized wrapper around real inner bytes."""
    padded = data + bytes(-len(data) % 32)
    signatures = bytes(65) + bytes(-65 % 32)
    head = (address_word(to) + word(value) + word(320) + word(operation) +
            word(0) * 3 + bytes(32) * 2 +
            word(320 + 32 + len(padded)))
    selector = bytes.fromhex("6a761202")
    return (selector + head + word(len(data)) + padded + word(65) +
            signatures)


def main():
    with open(os.path.join(HERE, "embedded_transactions.json")) as source:
        transactions = json.load(source)
    by_name = dict((tx["name"], tx) for tx in transactions)
    multicall = bytes.fromhex(by_name["router02_multicall"]["data"][2:])
    # Depth 2: Safe A executes the real multicall (whose steps are depth 2).
    transactions.append({
        "name": "safe_exec_multicall",
        "source": "Safe A execTransaction wrapping the real calldata of tx "
                  "0x27ee4abb...",
        "chain_id": 1, "to": SAFE_A, "value": "0x0",
        "data": "0x" + safe_exec(ROUTER02, multicall).hex()})
    # Depth 3: Safe A executes Safe B's exec of the multicall: refused.
    transactions.append({
        "name": "safe_exec_safe_multicall",
        "source": "Safe A executing Safe B executing the real calldata of tx "
                  "0x27ee4abb...",
        "chain_id": 1, "to": SAFE_A, "value": "0x0",
        "data": "0x" + safe_exec(SAFE_B, safe_exec(ROUTER02, multicall)).hex()})

    # Safe A executes Safe B's DELEGATECALL of the real token transfer: the
    # inner Safe's operation is read at its own level.
    transfer = bytes.fromhex(by_name["safe_exec_transfer"]["data"][2:])
    inner_transfer = transfer[4 + 352:4 + 352 + 68]
    transactions.append({
        "name": "safe_exec_safe_delegatecall",
        "source": "Safe A executing Safe B's DELEGATECALL of the transfer in "
                  "tx 0x1084535e...",
        "chain_id": 1, "to": SAFE_A, "value": "0x0",
        "data": "0x" + safe_exec(SAFE_B, safe_exec(
            TOKEN, inner_transfer, operation=1)).hex()})

    out = ["// Generated by scripts/erc7730/gen_embedded_vectors.py. Do not edit.",
           "// Real calldata (scripts/erc7730/embedded_transactions.json) and",
           "// the ERC-7730 programs that describe it.",
           "#include <cstdint>",
           "",
           "namespace e7730v {",
           "struct Program { const char* name; const char* contract; "
           "const char* hex; };",
           "struct Tx { const char* name; const char* source; uint64_t chain; "
           "const char* to; const char* value; const char* data; };",
           "static const Program kPrograms[] = {"]
    for name, descriptor, signature, address in PROGRAMS:
        program = compile_calldata(descriptor, signature, 1, address)
        out.append('  {"%s", "%s",\n   "%s"},' % (
            name, address.lower()[2:], program.hex()))
    out.append("};")
    out.append("static const Tx kTxs[] = {")
    for tx in transactions:
        out.append('  {"%s", "%s", %d, "%s", "%s",\n   "%s"},' % (
            tx["name"], tx["source"], tx["chain_id"], tx["to"].lower()[2:],
            tx["value"], tx["data"][2:]))
    out.append("};")
    out.append("}  // namespace e7730v")
    print("\n".join(out))


if __name__ == "__main__":
    main()
