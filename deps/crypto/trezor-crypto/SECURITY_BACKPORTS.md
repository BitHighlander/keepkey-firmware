# RC18 crypto security triage

This file records the security-relevant delta applied after baseline
`56f404e452bc7738cd3b3e14454dfecb25c083bf`.

## Applied upstream changes

| Upstream commit | KeepKey disposition |
| --- | --- |
| `15bb085509263a2586b914363b095e1e62255816` | Propagate invalid public-child derivation failures. |
| `5d03110a4287d2cdb0820d07d04e71a79d445014` | Handle invalid ECDSA private-key and zero-digest edge cases. |
| `34621a6b6d340a42e917cad346ec527c94066712` | Tighten private-key validity checks. |
| `307d166383614a8fa6ebee90ee10c469dfa697d1` | Clean Ed25519 stack intermediates. |
| `f96e737ef540665ff8df0e5d46a3ad0e2d7f67f9` | Remove alignment-dependent SHA3 undefined behavior. |
| `4882648dad1e29b635568abe52251285fb56bdb1` | Reject a recovered ECDSA point at infinity. |
| `8baf1ca79f107da2c25348df7f429e2f147dd939` | Prevent an out-of-bounds read in `ecdsa_sig_to_der`. |
| `10bc747dc6dae3620dce73df37a55009bbfc87ed` | Correct Ed25519 argument types. |
| `4827969cc8411f38d4b10916658d2aa665ca555d` | Harden SHA function declarations. |
| `d1d3558d02732979c00c96c5e7b91e6560149e61` | Correct constant-time assertions and casts. |
| `d6fdadf6730727c26d0644d84faaa562cf75f4d3` | Remove zero-length Groestl/SHA3 undefined behavior. |
| `f4d0dd9807ec3d50483dd589455235569a1a63c6` | Initialize Ed25519 locals; adapted for KeepKey Cardano APIs. |
| `8e8f1afa8566cd5c7f89e4154163e6b9f6c9bee4` | Enforce strict DER signature decoding. |
| `1e53a84cfc22405d2a67295954cbb33ca0c336ca` | Zero-initialize AES stack contexts. |
| `3b49e5400db4c92490a259c363f257617cb017ff` | Remove secret-dependent Ed25519 memory access. |
| `ecc38f267f91dffdb8afaaea8d5e5853be72df21` | Use constant-time Ed25519 conditional moves. |
| `2ce1e6ba7dbe5bbaeeb336fff0a038e59cb40ef8` | Add BIP32/BIP39 cache clearing APIs. |
| `477cbb365a29c23df766fd8f128cc5b73ed04bb6` | Wipe HDNode deserialization scratch data. |
| `09e55d8c9cb255eaa0463a8aa58f5dca1ed17644` | Clean NEM AES contexts. |
| `26914ff4962812695a2abf49f06e268606a7a7e2` | Prevent fixed-size BIP32 cache-path overflow. |
| `ea542943fced278c3563f068c2aa63dda0d1705e` | Reject BIP32 depth overflow. |
| `865ca5f0a9534ca64f41a1d508983029b55c9b7b` | Correct SLIP-10/25519 fingerprints. |
| `3da9c6bbb9910ce7f8fc29f9c5da758dbb50cb9c` | Reject public CKD for 25519 curves. |
| `bddd38b47d920559e50aa50c82eab62a8f6510ca` | Wipe ECDSA signing intermediates. |
| `9b1c06205c41811abe7de81d9e50abd22613f0b3` | Make BIP39 word processing constant-time. |
| `13e6c4f55d3a54678d140ecd9b06205d5115881d` | Bound CashAddr HRP and output writes. |
| `ea5886026fac93f2a7544f425fa0480d6e896220` | Pass the curve into RFC6979 initialization. |
| `53d522a1fd6f391fe48de8accecae308e9754f09` | Reduce RFC6979 digests modulo the curve order. |
| `fa5e7feda66f2b64d8d2976f9110456a1f86989b` | Remove CoSi nonce bias. |
| `48db49fa67eb4b51a30dff394e27cbea6803dbf1` | Wipe CoSi secrets on early returns. |
| `892f3e348dacb6c7b9880bc697234a78aaf6d80a` | Remove caller-supplied Ed25519 public keys from signing APIs. |

## KeepKey-specific corrections

- Preserve the existing `mnemonic_find_word` API while using a fixed-size,
  constant-time word lookup and wiping checksum intermediates.
- Reject an invalid/null-curve node in `hdnode_private_ckd_cached`; the legacy
  implementation incorrectly returned success.
- Deserialize into a fresh output `HDNode` without first requiring that
  uninitialized output to be valid, and reject an unknown curve safely.
- Calculate 25519 fingerprints without mutating a cached public key.
- Apply the hardened Ed25519 signing API to the KeepKey Nano/Blake2b variant
  and all firmware call sites.
- Clear BIP32 and BIP39 global caches on session clear and storage reset.

## Reviewed but not applied

- `a5f7c19` insecure platform-independent LCG: not active in production.
  KeepKey defines `RAND_PLATFORM_INDEPENDENT=0` and supplies hardware
  `random32`; host tests use their own platform source.
- `b1bee00` BIP39 word-boundary read: the KeepKey word list already carried a
  sentinel, and the constant-time BIP39 rewrite above supersedes this path.
- `dfb7295` migration of crypto globals to stack: deferred because the legacy
  embedded target has strict stack limits. Existing static secret
  intermediates are explicitly wiped, and the new cache-clear APIs are called
  at the firmware session boundary.
- Broad feature, architecture, generated-file, Rust/Python/Core, and toolchain
  changes outside the compiled KeepKey crypto surface were not backported.

## Regression coverage

The standalone suite includes focused tests for:

- zero-valued DER signature components;
- recovered point-at-infinity rejection;
- BIP32 cache paths deeper than `BIP32_CACHE_MAXDEPTH`;
- private and public BIP32 depth overflow;
- RFC6979 digest reduction/deterministic signatures;
- the hardened Ed25519, Cardano, and CoSi APIs;
- the complete pre-existing crypto vector suite.

Result: 158/158 checks pass under the optimized build and under ASan+UBSan.
