# P06-002: Ripple displayed-address response (7.14.3 full variant)

Base: 47eae604e183ab1c6c69be7dae43eee60b58326c.

The full variant reproduces the empty RippleGetAddress response when debug
screenshot capture overwrites the response arena during confirmation. Keep the
address in a local MAX_ADDR_SIZE buffer and populate the response afterward.
Bitcoin-only does not expose Ripple; its compiled behavior is unchanged.

Full screenshot regression fails before and passes after. All 190 full and
90 Bitcoin-only native firmware tests pass. Full native build is in
build-native-full, using the same local compiler/nanopb settings as the
Bitcoin-only build except KK_BITCOIN_ONLY=OFF. The P00
ripple_display_response.py rehearsal was run with its executable path adjusted
to build-native-full/bin/kkemu, using the release's own pinned host suite.

ARM/host integration and the permanent older-host assertion remain pending.
Production DEBUG_LINK-off failure was not established. Full audit remains open.
