# Monero emulator evidence in firmware reports

Render the focused report with the checked-in helper and the pinned Python
report writer. No additional Python PDF package is needed.

```sh
python3 scripts/monero-report.py \
  --evidence /path/to/public-evidence/manifest.json \
  --output /path/to/monero-firmware-report.pdf
```

The result includes a PDF, `.pdf.sha256` checksum, and `.pdf.monero.json`
receipt binding the public manifest, renderer, helper and final PDF hashes.
The input must be the **public evidence bundle**, never a wallet directory or
the raw host-run directory. The helper rejects private-key, seed and credential
fields, verifies every referenced file hash and checks every PNG/PGM against
its retained 2048-byte OLED framebuffer. It includes every referenced receive,
approval and refusal screen at 512 by 128 points; it does not synthesize screens.

To append the same evidence to the canonical firmware report, provide the
optional environment variable when running the existing wrapper:

```sh
KK_MONERO_EVIDENCE=/path/to/public-evidence/manifest.json \
  python3 scripts/generate-test-report.py
```

All existing baseline JUnit, OLED and ARM gates still apply. The Monero input
must record the exact checked-out firmware commit and match every recorded
source-file hash against the checkout. The wrapper copies only
the validated public manifest and referenced files into a hash-named directory
inside `test-report/`, includes the appendix in `test-report.pdf`, and records
its evidence/helper/receipt hashes in `test-report-manifest.json`. A missing,
tampered or inconsistent Monero bundle fails report generation.

The report distinguishes public transaction parsing from fixture-view-key
output recovery, and Monero Core proof verification from the separate parser,
hash/output binding and recipient-wallet observations. Its scope is a bounded
native emulator and isolated local Monero chain. MCU signing and physical-device
readiness are explicitly unproven. Passing this report does not change those
boundaries or make the experimental firmware suitable for funds.

Run the report-input and adapter tests with:

```sh
python3 -m unittest discover -s scripts -p 'test_monero_report.py'
python3 -m unittest discover -s scripts -p 'test_generate_test_report.py'
```

The tests use visibly labeled synthetic fixtures to exercise tampering and PDF
plumbing. Final report screenshots must come from the real emulator run.
