/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2025 KeepKey
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

/* Helper: Raw base58 encode (no checksum) for Solana pubkeys/addresses.
 * Uses b58enc() from trezor-crypto, which is the raw base58 encoder.
 * Solana addresses are raw base58-encoded 32-byte Ed25519 public keys. */
static bool solana_base58_encode(const uint8_t* data, size_t data_len,
                                 char* out, size_t* out_len) {
  return b58enc(out, out_len, data, data_len);
}

/* Helper: Base58-encode a 32-byte pubkey for display (full address).
 * Solana base58 addresses are 32-44 chars; out must be >= 45 bytes.
 * Never truncate — truncation is a spoofing vector. */
static void solana_pubkeyToStr(const uint8_t key[SOL_PUBKEY_SIZE], char* out,
                               size_t out_len) {
  size_t enc_len = out_len;
  if (solana_base58_encode(key, SOL_PUBKEY_SIZE, out, &enc_len)) {
    /* b58enc null-terminates and sets enc_len including the NUL */
    return;
  }
  /* Fallback to hex if base58 fails (middle-ellipsis OK for raw hex) */
  snprintf(out, out_len, "%02x%02x...%02x%02x", key[0], key[1], key[30],
           key[31]);
}

static bool solana_confirm_account(const char* title, const char* label,
                                   const uint8_t key[SOL_PUBKEY_SIZE]) {
  char s[45];
  solana_pubkeyToStr(key, s, sizeof(s));
  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title, "%s\n%s",
                 label, s);
}

/* Host symbol is untrusted: printable ASCII only, so newlines or control bytes
 * cannot push the mint or recipient off the confirm screen. */
static bool solana_symbol_is_safe(const char* sym) {
  if (!sym || sym[0] == '\0') return false;
  for (const char* p = sym; *p; p++) {
    if ((uint8_t)*p < 0x20 || (uint8_t)*p > 0x7e) return false;
  }
  return true;
}

static bool solana_confirm_memo(const char* title, const uint8_t* s,
                                uint16_t len) {
  return confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmMemo, title, s,
                       len);
}

/* Priority fee (ceil(cu_price * cu_limit / 1e6) lamports) is charged even on
 * failure, and CU fields show no units, so disclose the MAXIMUM fee in SOL
 * (1.4M-CU cap when no limit is set; never an understatement). */
static bool solana_confirm_priority_fee(const SolanaParsedTx* tx,
                                        const uint8_t* fee_payer) {
  uint64_t price = 0;
  bool have_price = false;
  uint64_t cu_limit = 0;
  bool have_limit = false;
  for (uint8_t i = 0; i < tx->num_instructions; i++) {
    const SolanaParsedInstruction* pi = &tx->instructions[i];
    if (pi->type == SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE) {
      price = pi->extra_value;
      have_price = true;
    } else if (pi->type == SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT) {
      cu_limit = pi->extra_value;
      have_limit = true;
    }
  }
  if (!have_price || price == 0) {
    return true; /* no priority fee to disclose */
  }
  const uint64_t kMaxCuLimit = 1400000u; /* Solana per-tx CU cap */
  uint64_t limit = have_limit ? cu_limit : kMaxCuLimit;
  if (limit > kMaxCuLimit) limit = kMaxCuLimit;

  /* false => fee exceeds u64 lamports: refuse, never show a wrapped value */
  uint64_t lamports = 0;
  if (!solana_priority_fee_lamports(price, limit, &lamports)) {
    (void)confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Fee",
                  "Priority fee too large to display. Refusing to sign.");
    return false;
  }
  char fee_str[40];
  solana_formatAmount(fee_str, sizeof(fee_str), lamports);
  if (fee_payer) {
    char payer_str[45];
    solana_pubkeyToStr(fee_payer, payer_str, sizeof(payer_str));
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Fee",
                 "Fee payer\n%s", payer_str)) {
      return false;
    }
  }
  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Fee",
                 "Max priority fee\n%s", fee_str);
}

static bool solana_confirmInstruction(const SolanaParsedInstruction* pi,
                                      const SolanaSignTx* msg, uint8_t idx,
                                      uint8_t total) {
  char title[32];
  snprintf(title, sizeof(title), "Instr %d/%d", idx + 1, total);

  switch (pi->type) {
    case SOL_INSTR_SYSTEM_TRANSFER: {
      if (!solana_confirm_account(title, "Transfer from", pi->from)) {
        return false;
      }
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Send %s to %s?", amount_str, to_str);
    }

    case SOL_INSTR_SYSTEM_CREATE_ACCOUNT: {
      if (!solana_confirm_account(title, "Fund from", pi->from)) return false;
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char account_str[45];
      solana_pubkeyToStr(pi->to, account_str, sizeof(account_str));
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                   "Create %s with %s?", account_str, amount_str)) {
        return false;
      }
      char owner_str[45];
      solana_pubkeyToStr(pi->extra, owner_str, sizeof(owner_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Owner %s\nSpace %llu bytes?", owner_str,
                     (unsigned long long)pi->extra_value);
    }

    case SOL_INSTR_SYSTEM_ADVANCE_NONCE:
      return solana_confirm_account(title, "Advance nonce account", pi->from);

    case SOL_INSTR_SYSTEM_WITHDRAW_NONCE: {
      /* Withdrawing the full balance can destroy the nonce account. */
      if (!solana_confirm_account(title, "Nonce account", pi->from)) {
        return false;
      }
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Withdraw nonce %s to %s?", amount_str, to_str);
    }

    case SOL_INSTR_SYSTEM_INITIALIZE_NONCE: {
      if (!solana_confirm_account(title, "Initialize nonce account",
                                  pi->from)) {
        return false;
      }
      char auth_str[45];
      solana_pubkeyToStr(pi->authority, auth_str, sizeof(auth_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Nonce authority %s?", auth_str);
    }

    case SOL_INSTR_SYSTEM_AUTHORIZE_NONCE: {
      if (!solana_confirm_account(title, "Nonce account", pi->from)) {
        return false;
      }
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Authorize nonce to %s?", auth_str);
    }

    case SOL_INSTR_SYSTEM_ASSIGN: {
      if (!solana_confirm_account(title, "Assign account", pi->from)) {
        return false;
      }
      return solana_confirm_account(title, "to owner program", pi->extra);
    }

    case SOL_INSTR_SYSTEM_ALLOCATE: {
      if (!solana_confirm_account(title, "Allocate for account", pi->from)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Allocate %llu bytes?",
                     (unsigned long long)pi->extra_value);
    }

    case SOL_INSTR_TOKEN_TRANSFER: {
      if (!solana_confirm_account(title, "Transfer from token account",
                                  pi->from)) {
        return false;
      }
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));

      const SolanaTokenInfo* ti = NULL;
      if (pi->has_mint && msg) {
        ti = solana_findTokenInfo(msg, pi->mint);
      }

      /* The mint is the only authenticated token identity: own screen, so a
       * host symbol cannot push it off-view. */
      if (pi->has_mint) {
        char mint_str[45];
        solana_pubkeyToStr(pi->mint, mint_str, sizeof(mint_str));
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Token mint\n%s", mint_str)) {
          return false;
        }
      }

      /* Unsafe symbol => raw count; the mint still identifies the token. */
      if (ti && ti->has_symbol && ti->has_decimals &&
          solana_symbol_is_safe(ti->symbol)) {
        char amount_str[48];
        solana_formatTokenAmount(amount_str, sizeof(amount_str), pi->amount,
                                 ti->symbol, (uint8_t)ti->decimals);
        return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                       "Send %s to %s?", amount_str, to_str);
      }
      char amount_str[32];
      snprintf(amount_str, sizeof(amount_str), "%llu tokens",
               (unsigned long long)pi->amount);
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Send %s to %s?", amount_str, to_str);
    }

    case SOL_INSTR_TOKEN_TRANSFER_CHECKED: {
      if (!solana_confirm_account(title, "Transfer from token account",
                                  pi->from)) {
        return false;
      }
      /* Decimals come from the signed bytes (pi->extra_u8), never the host. */
      const SolanaTokenInfo* ti = NULL;
      const SolanaKnownToken* known = NULL;
      if (pi->has_mint && msg) {
        ti = solana_findTokenInfo(msg, pi->mint);
      }
      if (pi->has_mint) {
        known = solana_findKnownToken(pi->mint);
      }

      /* A known mint's decimals are firmware-owned; a mismatched signed scale
       * would misrender the amount (0.002 USDC as 20.00), so refuse. */
      if (known && known->decimals != pi->extra_u8) {
        (void)confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Blocked",
                      "%s decimals mismatch. Refusing to sign.", known->symbol);
        return false;
      }

      /* Symbol trust: attestation verifies -> trusted; present but INVALID ->
       * drop the symbol (never fall back to the claim); absent -> show it
       * beside the authenticated mint. */
      const char* symbol = NULL;
      bool symbol_verified = false;
      if (known) {
        symbol = known->symbol;
      } else if (ti && ti->has_symbol && solana_symbol_is_safe(ti->symbol)) {
        if (ti->has_signature) {
          /* Attested decimals must equal the signed decimals, or the attested
           * tuple does not describe this tx and must not earn "verified". */
          if (solana_token_info_trusted(ti) && ti->decimals == pi->extra_u8) {
            symbol = ti->symbol;
            symbol_verified = true;
          }
        } else {
          symbol = ti->symbol;
        }
      }

      if (pi->has_mint) {
        char mint_str[45];
        solana_pubkeyToStr(pi->mint, mint_str, sizeof(mint_str));
        const bool mint_ok =
            known
                ? confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                          "Known token %s\n%s", known->symbol, mint_str)
                : confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                          "Token mint\n%s", mint_str);
        if (!mint_ok) {
          return false;
        }
      }

      /* Show the x402 owner only after the device derives ATA(owner,
       * token_program, mint) and matches the signed destination. */
      uint8_t recipient_owner[SOL_PUBKEY_SIZE];
      const bool recipient_verified =
          pi->has_mint &&
          solana_findTokenRecipientOwner(msg, pi->program_id, pi->mint, pi->to,
                                         recipient_owner);
      if (recipient_verified) {
        if (!solana_confirm_account(title, "Verified recipient owner",
                                    recipient_owner)) {
          return false;
        }
      } else if (msg && msg->token_recipient_owner_count > 0) {
        /* payTo does not own the signed ATA: warn, show the raw account. */
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Warning",
                     "Recipient owner does not match signed token account.")) {
          return false;
        }
      }

      /* Aliases are host-chosen and not unique; the fingerprint identifies the
       * attesting key. symbol_verified implies the signer is loaded. */
      if (symbol_verified) {
        const char* alias = signed_metadata_signer_alias(ti->signer_key_id);
        char fp[METADATA_FINGERPRINT_LEN] = {0};
        signed_metadata_signer_fingerprint((uint8_t)ti->signer_key_id, fp);
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Token \"%s\"\nby %s %s", symbol, alias ? alias : "",
                     fp)) {
          return false;
        }
      }

      if (symbol) {
        char amount_str[48];
        solana_formatTokenAmount(amount_str, sizeof(amount_str), pi->amount,
                                 symbol, pi->extra_u8);
        if (recipient_verified) {
          return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                         "Send %s?", amount_str);
        }
        char to_str[45];
        solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
        return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                       "Send %s to %s?", amount_str, to_str);
      }
      char amount_str[48];
      solana_formatTokenAmount(amount_str, sizeof(amount_str), pi->amount,
                               "tokens", pi->extra_u8);
      if (recipient_verified) {
        return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                       "Send %s?", amount_str);
      }
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Send %s to %s?", amount_str, to_str);
    }

    case SOL_INSTR_TOKEN_APPROVE: {
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Approve %llu tokens to %s?",
                     (unsigned long long)pi->amount, to_str);
    }

    case SOL_INSTR_TOKEN_REVOKE:
      return solana_confirm_account(title, "Revoke approval on account",
                                    pi->from);

    case SOL_INSTR_TOKEN_SET_AUTHORITY: {
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set token authority to %s?", auth_str);
    }

    case SOL_INSTR_TOKEN_MINT_TO: {
      char mint_str[45];
      char to_str[45];
      solana_pubkeyToStr(pi->mint, mint_str, sizeof(mint_str));
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                   "Mint token\n%s", mint_str)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Mint %llu\nto %s?", (unsigned long long)pi->amount,
                     to_str);
    }

    case SOL_INSTR_TOKEN_BURN: {
      char mint_str[45];
      char from_str[45];
      solana_pubkeyToStr(pi->mint, mint_str, sizeof(mint_str));
      solana_pubkeyToStr(pi->from, from_str, sizeof(from_str));
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                   "Burn token\n%s", mint_str)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Burn %llu\nfrom %s?", (unsigned long long)pi->amount,
                     from_str);
    }

    case SOL_INSTR_TOKEN_CLOSE_ACCOUNT: {
      /* Closing sweeps the ENTIRE lamport balance (invisible to the device). */
      if (!solana_confirm_account(title, "Close token account", pi->from)) {
        return false;
      }
      return solana_confirm_account(title, "send balance to", pi->to);
    }

    case SOL_INSTR_TOKEN_FREEZE_ACCOUNT: {
      /* Freeze authority is per-mint, so show the mint too. */
      if (!solana_confirm_account(title, "Freeze token account", pi->from)) {
        return false;
      }
      return solana_confirm_account(title, "of mint", pi->mint);
    }

    case SOL_INSTR_TOKEN_THAW_ACCOUNT: {
      if (!solana_confirm_account(title, "Thaw token account", pi->from)) {
        return false;
      }
      return solana_confirm_account(title, "of mint", pi->mint);
    }

    case SOL_INSTR_TOKEN_SYNC_NATIVE:
      return solana_confirm_account(title, "Sync wrapped SOL account",
                                    pi->from);

    case SOL_INSTR_STAKE_DELEGATE: {
      /* A host could substitute another stake account of the same authority. */
      if (!solana_confirm_account(title, "Delegate stake account", pi->from)) {
        return false;
      }
      return solana_confirm_account(title, "to vote account", pi->to);
    }

    case SOL_INSTR_STAKE_WITHDRAW: {
      if (!solana_confirm_account(title, "Withdraw from stake", pi->from)) {
        return false;
      }
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Withdraw %s\nto %s?", amount_str, to_str);
    }

    case SOL_INSTR_STAKE_AUTHORIZE: {
      /* Staker vs withdrawer: show which power is handed over. */
      if (!solana_confirm_account(title, "Stake account", pi->from)) {
        return false;
      }
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      const char* role = pi->extra_u8 == 0 ? "staker" : "withdrawer";
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Authorize %s\nto %s?", role, auth_str);
    }

    case SOL_INSTR_STAKE_SPLIT: {
      if (!solana_confirm_account(title, "Split from stake", pi->from)) {
        return false;
      }
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Split %s\nto %s?", amount_str, to_str);
    }

    case SOL_INSTR_STAKE_DEACTIVATE:
      return solana_confirm_account(title, "Deactivate stake account",
                                    pi->from);

    case SOL_INSTR_STAKE_MERGE: {
      char from_str[45];
      char to_str[45];
      solana_pubkeyToStr(pi->from, from_str, sizeof(from_str));
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                   "Merge stake from\n%s", from_str)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Merge stake into\n%s?", to_str);
    }

    case SOL_INSTR_VOTE_AUTHORIZE: {
      /* The withdrawer can move the vote account's SOL. */
      if (!solana_confirm_account(title, "Vote account", pi->from)) {
        return false;
      }
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      const char* role = pi->extra_u8 == 0 ? "voter" : "withdrawer";
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Authorize vote %s\nto %s?", role, auth_str);
    }

    case SOL_INSTR_VOTE_WITHDRAW: {
      if (!solana_confirm_account(title, "Withdraw from vote", pi->from)) {
        return false;
      }
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Withdraw vote %s\nto %s?", amount_str, to_str);
    }

    case SOL_INSTR_VOTE_UPDATE_VALIDATOR: {
      if (!solana_confirm_account(title, "Vote account", pi->from)) {
        return false;
      }
      return solana_confirm_account(title, "New validator identity", pi->extra);
    }

    case SOL_INSTR_VOTE_UPDATE_COMMISSION: {
      if (!solana_confirm_account(title, "Vote account", pi->from)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set vote commission to %u%%?", pi->extra_u8);
    }

    case SOL_INSTR_ATA_CREATE: {
      if (!solana_confirm_account(title, "Create token account", pi->to) ||
          !solana_confirm_account(title, "For wallet owner", pi->authority)) {
        return false;
      }
      return solana_confirm_account(title, "Token mint", pi->mint);
    }

    case SOL_INSTR_COMPUTE_BUDGET_HEAP_FRAME:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set heap frame to %llu bytes?",
                     (unsigned long long)pi->extra_value);

    case SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set compute unit limit to %llu?",
                     (unsigned long long)pi->extra_value);

    case SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set compute unit price to %llu?",
                     (unsigned long long)pi->extra_value);

    case SOL_INSTR_COMPUTE_BUDGET_LOADED_ACCOUNTS_SIZE:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set loaded account data to %llu bytes?",
                     (unsigned long long)pi->extra_value);

    case SOL_INSTR_MEMO:
      /* Page the FULL memo: swap intents (THORChain '=:ETH.ETH:...') ride in
       * it, so a byte-count summary would hide where funds go. */
      return solana_confirm_memo(title, pi->data, pi->data_len);

    case SOL_INSTR_UNKNOWN:
    default: {
      char prog_str[45];
      solana_pubkeyToStr(pi->program_id, prog_str, sizeof(prog_str));
      return confirm(ButtonRequestType_ButtonRequest_SignTx, title,
                     "Unknown instruction to program %s. "
                     "Cannot verify contents.",
                     prog_str);
    }
  }
}

static bool solana_offchain_payload_is_ascii(const uint8_t* data, size_t size) {
  for (size_t i = 0; i < size; i++) {
    if (data[i] < 0x20 || data[i] > 0x7e) return false;
  }
  return true;
}

static bool solana_offchain_payload_is_utf8(const uint8_t* data, size_t size) {
  size_t i = 0;
  while (i < size) {
    const uint8_t c = data[i];
    size_t extra;
    uint32_t cp;
    if (c < 0x80) {
      i++;
      continue;
    } else if ((c & 0xe0) == 0xc0) {
      extra = 1;
      cp = c & 0x1fu;
    } else if ((c & 0xf0) == 0xe0) {
      extra = 2;
      cp = c & 0x0fu;
    } else if ((c & 0xf8) == 0xf0) {
      extra = 3;
      cp = c & 0x07u;
    } else {
      return false;
    }
    if (i + extra >= size) return false;
    for (size_t k = 1; k <= extra; k++) {
      const uint8_t cc = data[i + k];
      if ((cc & 0xc0) != 0x80) return false;
      cp = (cp << 6) | (cc & 0x3fu);
    }
    if ((extra == 1 && cp < 0x80u) || (extra == 2 && cp < 0x800u) ||
        (extra == 3 && cp < 0x10000u) || cp > 0x10ffffu ||
        (cp >= 0xd800u && cp <= 0xdfffu)) {
      return false;
    }
    i += extra + 1;
  }
  return true;
}

/* Validate Solana derivation path: m/44'/501'/account'[/change'] */
static bool solana_pathIsStandard(const uint32_t* path, size_t count) {
  if (count < 3 || count > 4) return false;
  if (path[0] != (0x80000000 | 44)) return false;  /* 44' */
  if (path[1] != (0x80000000 | 501)) return false; /* 501' */
  for (size_t i = 2; i < count; i++) {
    if (!(path[i] & 0x80000000)) return false; /* must be hardened */
  }
  return true;
}

/* Verify derived pubkey appears in tx accounts[0..num_required_sigs) */
static bool solana_signerInTx(const uint8_t* pubkey, const SolanaParsedTx* tx) {
  for (uint8_t i = 0; i < tx->num_required_sigs && i < tx->num_accounts; i++) {
    if (memcmp(pubkey, tx->accounts[i], SOL_PUBKEY_SIZE) == 0) return true;
  }
  return false;
}

/* Render a schema-decoded instruction: who attested the schema, then the
 * program/instruction it describes, then every labelled arg and account with
 * values read from the transaction being signed. */
static bool solana_confirm_schema(const SolanaSignTx* msg, bool certified,
                                  const char* alias, const char* fp,
                                  const SolanaInstrSchema* schema,
                                  const SolanaParsedTx* parsed,
                                  uint8_t ix_index) {
  const SolanaParsedInstruction* ix = &parsed->instructions[ix_index];
  SolanaSchemaTokenCache token_cache = {NULL, NULL};

  /* Certified: disclose every instruction in transaction order. */
  for (uint8_t i = 0; certified && i < ix_index; i++) {
    if (!solana_confirmInstruction(&parsed->instructions[i], msg, i,
                                   parsed->num_instructions)) {
      return false;
    }
  }

  /* Aliases are host-chosen and not unique; the fingerprint identifies the
   * key that actually vouched for this decode. */
  if (!(certified ? confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                            "KeepKey ClearSign", "%s\nSigner %s", alias, fp)
                  : confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                            "Schema Signer", "%s\n%s", alias, fp))) {
    return false;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
               schema->program_name, "%s", schema->instruction_name)) {
    return false;
  }

  /* Args sit sequentially after the discriminator, in declaration order. */
  uint16_t off = schema->disc_len;
  for (uint8_t a = 0; a < schema->num_args; a++) {
    const SolanaSchemaArg* arg = &schema->args[a];
    if (arg->type == SOL_SCHEMA_ARG_OPAQUE32) {
      if (!confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         arg->label, ix->data + off, 32)) {
        return false;
      }
    } else {
      char value[96] = {0};
      if (!solana_schemaArgValue(msg, certified, parsed, ix, arg,
                                 ix->data + off, &token_cache, value,
                                 sizeof(value)) ||
          !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, arg->label,
                   "%s", value)) {
        return false;
      }
    }
    off += solana_schemaArgWidth(arg->type);
  }

  for (uint8_t a = 0; a < schema->num_accounts; a++) {
    const SolanaSchemaAccount* sa = &schema->accounts[a];
    const uint8_t pubkey_index = ix->acct_indices[sa->index];
    char addr[64];
    size_t enc = sizeof(addr);
    if (pubkey_index >= parsed->num_accounts ||
        !solana_base58_encode(parsed->accounts[pubkey_index], SOL_PUBKEY_SIZE,
                              addr, &enc) ||
        !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, sa->label, "%s",
                 addr)) {
      return false;
    }
  }

  for (uint8_t i = ix_index + 1; certified && i < parsed->num_instructions;
       i++) {
    if (!solana_confirmInstruction(&parsed->instructions[i], msg, i,
                                   parsed->num_instructions)) {
      return false;
    }
  }

  return solana_confirm_priority_fee(
      parsed, parsed->num_accounts > 0 ? parsed->accounts[0] : NULL);
}

/* Shared by SignTx and SignMessage so their security screens cannot drift.
 * msg is NULL on the SignMessage path. */
static bool solana_confirm_verified_tx(const SolanaParsedTx* parsed,
                                       const SolanaSignTx* msg) {
  for (uint8_t i = 0; i < parsed->num_instructions; i++) {
    if (!solana_confirmInstruction(&parsed->instructions[i], msg, i,
                                   parsed->num_instructions)) {
      return false;
    }
  }
  return solana_confirm_priority_fee(
      parsed, parsed->num_accounts > 0 ? parsed->accounts[0] : NULL);
}

void fsm_msgSolanaGetAddress(const SolanaGetAddress* msg) {
  RESP_INIT(SolanaAddress);

  CHECK_INITIALIZED
  CHECK_PIN

  /* Path validation: warn on non-standard derivation */
  if (!solana_pathIsStandard(msg->address_n, msg->address_n_count)) {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "WARNING",
                 "Non-standard Solana derivation path. Continue?")) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  /* Solana address = raw Base58 of the 32-byte Ed25519 public key.
   * node->public_key is 33 bytes (0x00 prefix + 32 bytes for Ed25519).
   * Use b58enc() for raw base58 encoding (no checksum). */
  char address[45];
  size_t addr_len = sizeof(address);
  if (solana_base58_encode(node->public_key + 1, SOL_PUBKEY_SIZE, address,
                           &addr_len)) {
    resp->has_address = true;
    strncpy(resp->address, address, sizeof(resp->address) - 1);
  } else {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Address encoding failed"));
    layoutHome();
    return;
  }

  if (msg->has_show_display && msg->show_display) {
    if (!confirm_ethereum_address("Solana", resp->address)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Show address cancelled"));
      layoutHome();
      return;
    }
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_SolanaAddress, resp);
  layoutHome();
}

void fsm_msgSolanaSignTx(const SolanaSignTx* msg) {
  RESP_INIT(SolanaSignedTx);

  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_raw_tx || msg->raw_tx.size == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Missing raw_tx"));
    layoutHome();
    return;
  }

  /* Classify before any consent screen so malformed bytes cannot trigger a
   * derivation-path warning before the request is rejected. */
  SolanaParsedTx parsed;
  SolanaTxReview tx_review =
      solana_inspectTx(msg->raw_tx.bytes, msg->raw_tx.size, &parsed);

  /* A failed parse may leave instructions populated; never sign it. */
  if (tx_review == SOL_TX_REVIEW_MALFORMED) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Malformed Solana transaction"));
    layoutHome();
    return;
  }

  /* Any certificate material: honoured fully or refused, never downgraded
   * (SRS R-1.4). */
  const bool certified_request =
      msg->has_clearsign_certificate ||
      (msg->has_lut_signer_key_id &&
       msg->lut_signer_key_id == METADATA_KEYID_DELEGATE) ||
      (msg->has_schema_signer_key_id &&
       msg->schema_signer_key_id == METADATA_KEYID_DELEGATE);
  /* Token definitions must come from the request's own tier. */
  for (pb_size_t t = 0; t < msg->token_info_count; t++) {
    const SolanaTokenInfo* ti = &msg->token_info[t];
    if (ti->has_signer_key_id &&
        (ti->signer_key_id == METADATA_KEYID_DELEGATE) != certified_request) {
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Solana token definition from another tier"));
      layoutHome();
      return;
    }
  }

  /* Path validation: warn on non-standard derivation */
  if (!solana_pathIsStandard(msg->address_n, msg->address_n_count)) {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "WARNING",
                 "Non-standard Solana derivation path. Continue?")) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  SolanaInstrSchema schema;
  memset(&schema, 0, sizeof(schema));
  uint8_t schema_ix = 0;
  char signer_alias[CLEARSIGN_ALIAS_LEN + 1] = {0};
  char signer_fp[METADATA_FINGERPRINT_LEN] = {0};
  uint8_t lut_keys[SOL_MAX_LUT_ACCOUNTS][SOL_PUBKEY_SIZE];
  size_t lut_n = 0;
  /* Flatten, requiring full 32-byte keys. */
  bool lut_well_formed = msg->lut_account_count <= SOL_MAX_LUT_ACCOUNTS;
  for (size_t i = 0; lut_well_formed && i < msg->lut_account_count; i++) {
    lut_well_formed = msg->lut_account[i].size == SOL_PUBKEY_SIZE;
    if (lut_well_formed) {
      memcpy(lut_keys[lut_n++], msg->lut_account[i].bytes, SOL_PUBKEY_SIZE);
    }
  }

  if (certified_request) {
    /* Requires a certified schema, plus a tx-bound LUT proof iff the message
     * has lookups. Anything partial or invalid is a hard failure. */
    const bool has_lut_material = msg->lut_account_count > 0 ||
                                  msg->has_lut_signature ||
                                  msg->has_lut_signer_key_id;
    uint8_t delegate_pub[CLEARSIGN_PUBKEY_LEN];
    const char* err = NULL;
    if (!msg->has_clearsign_certificate ||
        msg->clearsign_certificate.size != CLEARSIGN_CERT_LEN ||
        !msg->has_schema_payload || !msg->has_schema_signature ||
        !msg->has_schema_signer_key_id ||
        msg->schema_signer_key_id != METADATA_KEYID_DELEGATE) {
      err = _("Incomplete certified Solana ClearSign proof");
    } else if (!clearsign_root_cert_delegate(msg->clearsign_certificate.bytes,
                                             msg->clearsign_certificate.size,
                                             CLEARSIGN_SCOPE_SOLANA,
                                             delegate_pub, signer_alias)) {
      err = _("Invalid certified Solana certificate");
    } else {
      signed_metadata_pubkey_fingerprint(delegate_pub, signer_fp);
      signer_fp[8] = '\0'; /* root-authenticated: short id suffices */
      if (has_lut_material &&
          (!lut_well_formed || lut_n == 0 || !msg->has_lut_signature ||
           !msg->has_lut_signer_key_id ||
           msg->lut_signer_key_id != METADATA_KEYID_DELEGATE ||
           !solana_lut_accounts_certified(
               msg->raw_tx.bytes, msg->raw_tx.size,
               (const uint8_t (*)[32])lut_keys, lut_n,
               msg->clearsign_certificate.bytes,
               msg->clearsign_certificate.size, msg->lut_signature.bytes,
               msg->lut_signature.size))) {
        err = _("Invalid certified Solana LUT proof");
      } else {
        tx_review = has_lut_material
                        ? solana_inspectTxWithTrustedLut(
                              msg->raw_tx.bytes, msg->raw_tx.size,
                              (const uint8_t (*)[SOL_PUBKEY_SIZE])lut_keys,
                              lut_n, &parsed)
                        : solana_inspectTx(msg->raw_tx.bytes, msg->raw_tx.size,
                                           &parsed);
        if (tx_review == SOL_TX_REVIEW_MALFORMED ||
            /* A lookup section needs a proof. */
            (lut_n == 0 && parsed.has_address_lookups) ||
            !solana_parseInstrSchema(msg->schema_payload.bytes,
                                     msg->schema_payload.size, &schema) ||
            !clearsign_root_verify_delegate_attestation(
                msg->clearsign_certificate.bytes,
                msg->clearsign_certificate.size, CLEARSIGN_SCOPE_SOLANA,
                msg->schema_payload.bytes, msg->schema_payload.size,
                msg->schema_signature.bytes, msg->schema_signature.size) ||
            !solana_schemaAppliesCertified(&schema, &parsed, &schema_ix)) {
          err = _("Certified Solana schema does not match transaction");
        }
      }
    }
    memzero(delegate_pub, sizeof(delegate_pub));
    if (err) {
      memzero(node, sizeof(*node));
      memzero(&schema, sizeof(schema));
      fsm_sendFailure(FailureType_Failure_SyntaxError, err);
      layoutHome();
      return;
    }
  }

  /* Signer verification: derived key must be a required signer.
   * For verified txs this is mandatory. For opaque txs we still check
   * when we were able to parse the header (num_accounts > 0). */
  if (tx_review == SOL_TX_REVIEW_VERIFIED ||
      (tx_review == SOL_TX_REVIEW_OPAQUE && parsed.num_accounts > 0)) {
    if (!solana_signerInTx(node->public_key + 1, &parsed)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_Other,
                      _("Derived key is not a signer for this tx"));
      layoutHome();
      return;
    }
  }

  /* KKSOLSC1: a signed reusable schema names no amounts; the device reads
   * values from the signed bytes. Present-but-invalid schema fails the
   * request; it never degrades to blind signing. */
  bool schema_verified = false;
  bool has_any_schema = msg->has_schema_payload || msg->has_schema_signature ||
                        msg->has_schema_signer_key_id;
  if (!certified_request && has_any_schema) {
    if (!storage_isPolicyEnabled("AdvancedMode") || !msg->has_schema_payload ||
        !msg->has_schema_signature || !msg->has_schema_signer_key_id ||
        msg->schema_signer_key_id >= METADATA_MAX_KEYS ||
        !signed_metadata_signer_is_runtime(
            (uint8_t)msg->schema_signer_key_id) ||
        !solana_parseInstrSchema(msg->schema_payload.bytes,
                                 msg->schema_payload.size, &schema) ||
        !signed_metadata_verify_attestation(
            (uint8_t)msg->schema_signer_key_id, msg->schema_payload.bytes,
            msg->schema_payload.size, msg->schema_signature.bytes,
            msg->schema_signature.size) ||
        !solana_schemaApplies(&schema, &parsed, &schema_ix)) {
      memzero(node, sizeof(*node));
      memzero(&schema, sizeof(schema));
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Invalid Solana instruction schema"));
      layoutHome();
      return;
    }
    schema_verified = true;
  }

  if (certified_request) {
    /* Root-certified describer: its decode replaces the blind-sign warning. */
    if (!solana_confirm_schema(msg, true, signer_alias, signer_fp, &schema,
                               &parsed, schema_ix)) {
      memzero(node, sizeof(*node));
      memzero(&schema, sizeof(schema));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else if (tx_review == SOL_TX_REVIEW_VERIFIED) {
    /* Per-instruction disclosure + priority fee, shared with SignMessage. */
    if (!solana_confirm_verified_tx(&parsed, msg)) {
      memzero(node, sizeof(*node));
      memzero(&schema, sizeof(schema));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else if (schema_verified) {
    /* Runtime signers are annotation-only: blind-sign warning follows. */
    const char* alias =
        signed_metadata_signer_alias((uint8_t)msg->schema_signer_key_id);
    if (!signed_metadata_signer_fingerprint((uint8_t)msg->schema_signer_key_id,
                                            signer_fp) ||
        !solana_confirm_schema(msg, false, alias ? alias : "", signer_fp,
                               &schema, &parsed, schema_ix)) {
      memzero(node, sizeof(*node));
      memzero(&schema, sizeof(schema));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
    if (signed_metadata_signer_is_runtime((uint8_t)msg->schema_signer_key_id) &&
        !confirm(ButtonRequestType_ButtonRequest_SignTx, "Blind Sign",
                 "Sign unverified Solana transaction? "
                 "The device cannot fully verify the contents.")) {
      memzero(node, sizeof(*node));
      memzero(&schema, sizeof(schema));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else if (tx_review == SOL_TX_REVIEW_OPAQUE) {
    /* Unsupported or opaque message: allow explicit blind-sign only. */
    if (!storage_isPolicyEnabled("AdvancedMode")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_Other,
                      _("Enable AdvancedMode to blind-sign"));
      layoutHome();
      return;
    }

    /* KKSOLSW1 runtime LUT description: annotation only (SRS R-1.3); the
     * blind-sign warning still follows. */
    if (lut_well_formed && lut_n > 0 && msg->has_lut_signature &&
        msg->has_lut_signer_key_id &&
        solana_lut_accounts_trusted(
            msg->raw_tx.bytes, msg->raw_tx.size,
            (const uint8_t (*)[32])lut_keys, lut_n, msg->lut_signer_key_id,
            msg->lut_signature.bytes, msg->lut_signature.size)) {
      const char* alias =
          signed_metadata_signer_alias((uint8_t)msg->lut_signer_key_id);
      if (!signed_metadata_signer_fingerprint((uint8_t)msg->lut_signer_key_id,
                                              signer_fp)) {
        signer_fp[0] = '\0';
      }
      bool ok = confirm(
          ButtonRequestType_ButtonRequest_ConfirmOutput, "Lookup Accounts",
          "%s (%s) describes %u account(s).\nNOT verified by KeepKey.",
          alias ? alias : "Unknown signer", signer_fp, (unsigned)lut_n);
      for (size_t li = 0; ok && li < lut_n; li++) {
        char b58[64];
        size_t b58_len = sizeof(b58);
        ok = solana_base58_encode(lut_keys[li], SOL_PUBKEY_SIZE, b58,
                                  &b58_len) &&
             confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                     "Lookup Account", "%u/%u\n%s", (unsigned)(li + 1),
                     (unsigned)lut_n, b58);
      }
      if (!ok) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
      }
    }

    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Blind Sign",
                 "Sign unverified Solana transaction? "
                 "The device cannot fully verify the contents.")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Malformed Solana transaction"));
    layoutHome();
    return;
  }

  /* Final confirmation */
  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Solana",
               "Sign this Solana transaction?")) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Signing cancelled"));
    layoutHome();
    return;
  }

  if (!solana_signTx(node, msg, resp)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Signing failed"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_SolanaSignedTx, resp);
  layoutHome();
}

void fsm_msgSolanaSignMessage(const SolanaSignMessage* msg) {
  RESP_INIT(SolanaMessageSignature);

  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_message || msg->message.size == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Missing message"));
    layoutHome();
    return;
  }

  /* No domain separation: a payload that parses as a verified tx from byte 0
   * is clear-signed as one (wallets sign v0 swaps this way). */
  SolanaParsedTx parsed;
  bool is_verified_tx = msg->message.bytes[0] != 0 &&
                        solana_inspectTx(msg->message.bytes, msg->message.size,
                                         &parsed) == SOL_TX_REVIEW_VERIFIED;

  /* Path validation: warn on non-standard derivation */
  if (!solana_pathIsStandard(msg->address_n, msg->address_n_count)) {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "WARNING",
                 "Non-standard Solana derivation path. Continue?")) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  if (is_verified_tx) {
    if (!solana_signerInTx(node->public_key + 1, &parsed)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_Other,
                      _("Derived key is not a signer for this tx"));
      layoutHome();
      return;
    }
    if (!solana_confirm_verified_tx(&parsed, NULL)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Solana",
                 "Sign this Solana transaction?")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else {
    /* Printable text without this key cannot be a tx (Solana verifies only
     * static-account keys); all else keeps the AdvancedMode gate. */
    const bool plain_text = solana_rawMessageIsPlainText(
        msg->message.bytes, msg->message.size, node->public_key + 1);
    if (!plain_text && !storage_isPolicyEnabled("AdvancedMode")) {
      memzero(node, sizeof(*node));
      (void)review(ButtonRequestType_ButtonRequest_Other, "Blocked",
                   "This Solana message is not plain text. "
                   "Enable AdvancedMode in device settings to sign it.");
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Message signing disabled by policy"));
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, "Solana Message",
                 plain_text
                     ? "Plain text. It cannot authorize a transaction."
                     : "Format: raw Ed25519. Version: none. Domain: none.") ||
        !confirm_bytes(ButtonRequestType_ButtonRequest_ProtectCall,
                       plain_text ? "Message" : "Raw Message",
                       msg->message.bytes, msg->message.size)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  }

  /* Ed25519 sign */
  uint8_t sig[SOL_SIG_SIZE];
  ed25519_sign(msg->message.bytes, msg->message.size, node->private_key, sig);

  resp->has_signature = true;
  resp->signature.size = SOL_SIG_SIZE;
  memcpy(resp->signature.bytes, sig, SOL_SIG_SIZE);

  resp->has_public_key = true;
  resp->public_key.size = SOL_PUBKEY_SIZE;
  memcpy(resp->public_key.bytes, node->public_key + 1, SOL_PUBKEY_SIZE);

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_SolanaMessageSignature, resp);
  layoutHome();
}

void fsm_msgSolanaSignOffchainMessage(const SolanaSignOffchainMessage* msg) {
  RESP_INIT(SolanaOffchainMessageSignature);

  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_message || msg->message.size == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Missing message"));
    layoutHome();
    return;
  }

  /* Validate format upfront so the user sees a meaningful error rather
   * than a generic signing failure. The envelope's 0xFF prefix provides
   * the domain separation that bare SolanaSignMessage lacks, so NO
   * AdvancedMode gate is required here — that fence was a band-aid for
   * the missing envelope. */
  uint32_t format = msg->has_message_format ? msg->message_format : 0;
  if (format != 0 && format != 1) {
    fsm_sendFailure(
        FailureType_Failure_Other,
        _("Off-chain format 2 (extended UTF-8) not supported on device"));
    layoutHome();
    return;
  }

  uint32_t version = msg->has_version ? msg->version : 0;
  if (version != 0) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Unsupported off-chain message version"));
    layoutHome();
    return;
  }

  if (msg->message.size > 1212) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Off-chain message exceeds 1212-byte limit"));
    layoutHome();
    return;
  }

  const bool payload_matches_format =
      format == 0 ? solana_offchain_payload_is_ascii(msg->message.bytes,
                                                     msg->message.size)
                  : solana_offchain_payload_is_utf8(msg->message.bytes,
                                                    msg->message.size);
  if (!payload_matches_format) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Message does not match declared off-chain format"));
    layoutHome();
    return;
  }

  /* Path validation: warn on non-standard derivation, mirroring the
   * existing SolanaSignMessage handler. */
  if (!solana_pathIsStandard(msg->address_n, msg->address_n_count)) {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "WARNING",
                 "Non-standard Solana derivation path. Continue?")) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  const char* format_label = format == 0 ? "ASCII" : "UTF-8 limited";
  if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, "Solana Off-chain",
               "Version: 0. Format: %s.", format_label) ||
      !confirm_bytes(ButtonRequestType_ButtonRequest_ProtectCall,
                     "Off-chain Message", msg->message.bytes,
                     msg->message.size)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Signing cancelled"));
    layoutHome();
    return;
  }

  if (!solana_offchain_message_sign(node, msg, resp)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Off-chain message signing failed"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_SolanaOffchainMessageSignature, resp);
  layoutHome();
}
