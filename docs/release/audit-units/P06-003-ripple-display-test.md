# P06-003: permanent displayed-address regression (7.14.3)

Pin host 8e5eaaaa10787a64f5d54780bb2b5f72d3d82700, fork PR
https://github.com/BitHighlander/python-keepkey/pull/79, above firmware
1ce4d3961 (response lifetime fix).

The existing screenshot-selected Ripple address test now checks the known
returned address for 7.14.3 and later. All three address host tests pass with
screenshot capture against this release's fixed full emulator. The assertion
was reproduced failing before the firmware fix. Tests use isolated temporary
storage and forced UDP, without physical hardware.

The exact host commit is fetchable through the configured submodule URL.
Combined CI remains pending. This unit changes no firmware source. Full
release audit and physical display validation remain open.
