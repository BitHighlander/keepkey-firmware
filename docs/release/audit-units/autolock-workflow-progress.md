# Refresh auto-lock only for accepted workflow progress

A stalled signing session remained unlocked indefinitely while a host polled
GetFeatures: the firmware RX wrapper reset idle time before validating any USB
frame. Remove that wrapper and renew the deadline only at accepted workflow
stages that request another message. This covers Bitcoin, Ethereum, Binance,
Cosmos/Tendermint, Osmosis, THORChain, MAYAChain, and EOS streams. Accepted
recovery edits and reset entropy preserve the setup ceremony deadline too.

EOS chunks carrying zero bytes while data remains, empty recovery backspaces,
unrelated polls, and incomplete frames do not count as progress. Empty recovery
characters are rejected instead of matching the cipher's terminating NUL.
Progress can renew a deadline at home because some signing handlers wait there;
it cannot wake a completed screensaver lock.

Native USB-callback regressions reproduce the old GetFeatures/incomplete-frame
bypass and verify real Bitcoin, Ethereum, EOS, and recovery progress across
multiple idle periods, followed by lock when progress stalls. Invalid Bitcoin
ACKs still terminate signing. The tests exercise completed protocol stages;
individual fragments of a very slow message do not extend its deadline. Existing
on-device confirmation and layout-transition timer behavior is unchanged.
