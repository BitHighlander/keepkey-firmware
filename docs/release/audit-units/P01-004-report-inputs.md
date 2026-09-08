# P01-004: Require native report evidence (7.14.2)

Status: bounded fix validated locally; phase integration and complete release audit pending.

The report discovered native XMLs with a glob, which silently omitted missing
suites. Require each product's emitted native suite by name, nonempty content,
parseable XML and at least one test case before merging report evidence.

Validation: actual native XML artifacts from CI run 34277705965 are accepted;
12 missing, empty, malformed and no-case mutations are rejected.
The repeatable rehearsal is `docs/release/rehearsals/native_report_inputs.py`
on the phase-scope branch (PR #668). Python syntax and whitespace checks pass.
