# Safe typed-call review on alpha

Generic EIP-712 review renders `SafeTx.data` as bytes. A desktop decoder cannot
authenticate a different interpretation on the hardware. Capability 28 enables
the firmware to interpret the inner call using authenticated ERC-7730 programs
while signing the original Safe EIP-712 digest.

The outer definition must bind the exact chain, Safe deployment, and canonical
SafeTx type hash. Its embedded formatter selects the actual `data` member.
Inner definitions bind the target contract and function selector. Every inner
ABI pass comes from a device-requested Safe message replay; its complete message
digest must match the reviewed request. Domain facts remain device-owned across
replays. Failure or cancellation ends the signature.

The device suppresses raw `data` only when that signed embedded formatter is
selected. Other Safe fields and device warnings remain visible. This change does
not promise a fixed number of screens or certify a Safe's owner configuration.

MultiSend expansion accepts only the firmware's pinned deployments on the
current chain. Every packed entry must be CALL, including entries after the
currently displayed one. The bounded streaming parser checks canonical offsets,
lengths, padding, truncation, trailing bytes, and a 64-call limit. Arbitrary
delegatecalls cannot acquire the callee's ordinary transfer description.

## Incident regression

The Python dependency contains the public Base request for Safe
`0x6717d97655d8fc9d05c2dd3f28b54f574309b473`: transfer 8 USDC from contract
`0x833589fcd6edb6e08f4c7c32d4f71b54bda02913` to
`0x4efb11f884a2ead4c1f4e4f4d2841f207dba14dd`, Safe nonce 0.

It asserts the full recipient, amount, Safe, and network in the device review,
absence of the full raw calldata, and a signature over the independently recorded
digest `def9a33d36e2dca79d9e67460e4c5e038b73b868b5fec35888774294010a096d`.
Only the public emulator seed signs. The test also refuses changed token,
recipient, amount, and nonce during replay, missing inner metadata, and metadata
bound to another chain or Safe.

Run against a built full-feature debug emulator:

```sh
python3 scripts/emulator/test_safe_clearsign.py \
  --emulator /absolute/path/to/bin/kkemu \
  --python-keepkey deps/python-keepkey \
  --junit /tmp/safe-incident.xml
```

The runner owns a temporary emulator with a deterministic public TEST root,
forces UDP to avoid connected hardware, and rejects skipped incident evidence.
The ordinary alpha-root suite keeps its separate emulator. Firmware integration
CI invokes this runner for the full product.

## Release readiness

This firmware capability does not make an existing 7.16 device clear-sign Safe
inner calls. It needs an installed firmware that advertises capability 28,
host-side catalog delivery, and issuer-signed outer and inner definitions for
the exact deployment. The actual Base Safe and token were absent from the signed
catalog during the incident audit. Production metadata review, signing,
publication, and physical-device acceptance are separate release steps.

The SDK's short signing timeout is a separate transport issue. Extending that
timeout does not supply a hardware-authenticated transfer interpretation.
