# Wipe after consecutive wrong device PINs

The owner can configure a limit of 1 through 16 verified wrong device PIN
entries. The default is off. This setting and the duress PIN can each be used
alone or together. A limit of 1 means a single mistyped PIN erases the wallet.

A compatible host sends SetPinFailureLimit with the requested number, or zero
to clear it. Firmware displays the requested action and exact positive limit
on the device and requires physical confirmation and fresh ordinary PIN
authentication. Clearing an already-clear limit uses the same flow. Removing
the ordinary PIN also clears the limit. A correct ordinary PIN resets the
failure streak. A wrong PIN submitted during reauthentication counts too.

After a nonfinal wrong PIN, the device displays how many more wrong entries
will wipe the wallet. With one try remaining, the PIN matrix warns that a
wrong entry wipes, including after reboot or when the configured limit is one.
Anyone watching the display can see the warning. USB discovery omits the
policy and count, and the failure reply stays generic. The display pause can
also reveal policy use through response timing. The usual backoff still applies. A cancelled or malformed entry does not count. Existing anti-brute-force
backoff precharges a submission before verification. The wipe streak advances
only after verification fails. Interrupted verification can therefore increase
backoff without consuming a verified failure. Nonfinal failures commit flash
before replying in both policy states, at the cost of one additional flash
rotation per verified wrong PIN.

On the threshold failure, the firmware commits the same durable wipe intent
as the duress PIN before issuing the usual failure response. A cut before the
intent is durable can leave the earlier wallet. Normal boots after commitment
finish erasure before selecting a wallet record. Earlier firmware does not
enforce this policy and can discard it on a storage write.

## Hardware acceptance

On disposable devices, compare the locked USB transcript, OLED, latency and
reboot behavior at equal failure counts with the feature off and on. Check both
firmware variants. Cut power at the final verification and during each flash
erase, including during recovery, and verify the countdown and final-entry warning. Verify that the
threshold failure response follows durable commitment. The emulator covers logical behavior. Hardware timing,
power analysis and stock bootloader behavior require separate validation.
