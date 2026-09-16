# 7.15 external-review prediction

Candidate `d77d75647b05db4b8f2e150ef2a525339b534d41` is ready for external
challenge. The machine receipt validates against tree
`9436897e6792179a6331ba6744539413c4204140` and the live GitHub state.

No known actionable release defect remains. The independent falsification pass
reproduced the timer reinitialization guard and its failing mutation, verified
all four projection manifests and their disjoint 262-file union, sampled prior
finding closures, and traced stalled-signing auto-lock behavior end to end.

Residual risks:

- Physical power-cut atomicity remains limited by the released bootloader. Its
  coordinated bootloader redesign is deferred to 7.17.
- Physical-device QA remains required after external review.

Evidence:

- `715-d77d7564-prediction.json` — complete machine receipt
- `715-d77d7564-evidence/timer-reinit.json` — isolated fixture and mutation
- `715-d77d7564-evidence/shuffled.log` — 62 stateful tests, three shuffled runs
