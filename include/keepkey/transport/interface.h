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
 * Measured: with arrays and a 13 KB buffer the runtime reserve is 16,180 B,
 * which FAILS the linker's 16,384 B gate. At 12 KB it is 17,204 B, a margin of
 * 820 B. */
#define MAX_DECODE_SIZE (12 * 1024)
#else
#define MAX_DECODE_SIZE (26 * 1024)
#endif

#endif
