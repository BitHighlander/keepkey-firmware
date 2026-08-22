/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2021 KeepKey LLC
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef INTERFACE_H
#define INTERFACE_H

// Allow this file to be used from C++ by renaming an unfortunately named field:
#define delete del
#include "messages.pb.h"
#include "messages-nano.pb.h"
#undef delete

#include "messages-ethereum.pb.h"
#include "messages-binance.pb.h"
#include "messages-cosmos.pb.h"
#include "messages-osmosis.pb.h"
#include "messages-eos.pb.h"
#include "messages-ripple.pb.h"
#include "messages-tendermint.pb.h"
#include "messages-thorchain.pb.h"
#include "messages-mayachain.pb.h"
#include "messages-tron.pb.h"
#include "messages-ton.pb.h"
#include "messages-solana.pb.h"
#include "messages-zcash.pb.h"
#include "messages-hive.pb.h"

#include "types.pb.h"
#include "trezor_transport.h"

#ifndef EMULATOR
/* The max size of a decoded protobuf.
 *
 * 12 KB, reduced from 13 KB to buy the SRAM structured EIP-712's array walk
 * needs. Not a guess: fsm.c static-asserts sizeof() of EVERY registered
 * inbound message against this value, so a message that outgrows it fails the
 * BUILD rather than overflowing at runtime. 10 KB does not compile -- the real
 * floor is between 10 and 12 KB -- so this is the last kilobyte available
 * without shrinking a message.
 *
 * Measured, structured EIP-712 only: 13 KB gives a 16,180 B reserve, which
 * FAILS the linker's 16,384 B gate; 12 KB gives 17,204 B.
 *
 * Then passkeys landed and took 1,248 B of static allocation -- a passkey
 * credential is 212 B and the storage struct is held TWICE in RAM, live in
 * shadow_config and staged in flash_temp -- which spent that margin and left
 * the reserve at 15,956 B, 428 B under the gate.
 *
 * 11 KB restores it to 16,980 B, a 596 B margin, with both ARM variants
 * linking. Chosen over cutting PASSKEY_MAX_DISCOVERABLE_CREDENTIALS from 4
 * because that is a permanent, user-visible product limit (4 is already low
 * against a YubiKey's 25+) while this is protocol headroom nobody sees, and
 * every registered message is static-asserted against it -- outgrowing it
 * fails the BUILD, not the field. */
#define MAX_DECODE_SIZE (11 * 1024)
#else
#define MAX_DECODE_SIZE (26 * 1024)
#endif

#endif
