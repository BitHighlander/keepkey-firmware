void fsm_msgInitialize(Initialize *msg)
{
    (void)msg;
    recovery_abort(false);
    signing_abort();
    session_clear(false); // do not clear PIN
    go_home();
    fsm_msgGetFeatures(0);
}

static const char *model(void) {
    const char *ret = flash_getModel();
    if (ret)
        return ret;
    return "Unknown";
}

void fsm_msgGetFeatures(GetFeatures *msg)
{
    (void)msg;
    RESP_INIT(Features);

    /* Vendor */
    resp->has_vendor = true;
    strlcpy(resp->vendor, "keepkey.com", sizeof(resp->vendor));

    /* Version */
    resp->has_major_version = true;  resp->major_version = MAJOR_VERSION;
    resp->has_minor_version = true;  resp->minor_version = MINOR_VERSION;
    resp->has_patch_version = true;  resp->patch_version = PATCH_VERSION;

    /* Device ID */
    resp->has_device_id = true;
    strlcpy(resp->device_id, storage_get_uuid_str(), sizeof(resp->device_id));

    /* Model */
    resp->has_model = true;
    strlcpy(resp->model, model(), sizeof(resp->model));

    /* Variant Name */
    resp->has_firmware_variant = true;
    strlcpy(resp->firmware_variant, variant_getName(), sizeof(resp->firmware_variant));

    /* Security settings */
    resp->has_pin_protection = true; resp->pin_protection = storage_has_pin();
    resp->has_passphrase_protection = true;
    resp->passphrase_protection = storage_get_passphrase_protected();

#ifdef SCM_REVISION
    int len = sizeof(SCM_REVISION) - 1;
    resp->has_revision = true; memcpy(resp->revision.bytes, SCM_REVISION, len);
    resp->revision.size = len;
#endif

    /* Bootloader hash */
#ifndef EMULATOR
    resp->has_bootloader_hash = true;
    resp->bootloader_hash.size = memory_bootloader_hash(
                                     resp->bootloader_hash.bytes, false);
#else
    resp->has_bootloader_hash = false;
#endif

    /* Firmware hash */
#ifndef EMULATOR
    resp->has_firmware_hash = true;
    resp->firmware_hash.size = memory_firmware_hash(resp->firmware_hash.bytes);
#else
    resp->has_firmware_hash = false;
#endif

    /* Settings for device */
    if(storage_get_language())
    {
        resp->has_language = true;
        strlcpy(resp->language, storage_get_language(), sizeof(resp->language));
    }

    if(storage_get_label())
    {
        resp->has_label = true;
        strlcpy(resp->label, storage_get_label(), sizeof(resp->label));
    }

    /* Is device initialized? */
    resp->has_initialized = true;
    resp->initialized = storage_is_initialized();

    /* Are private keys imported */
    resp->has_imported = true; resp->imported = storage_get_imported();

    /* Cached pin and passphrase status */
    resp->has_pin_cached = true; resp->pin_cached = session_is_pin_cached();
    resp->has_passphrase_cached = true;
    resp->passphrase_cached = session_is_passphrase_cached();

    /* Policies */
    resp->policies_count = POLICY_COUNT;
    storage_get_policies(resp->policies);

    msg_write(MessageType_MessageType_Features, resp);
}

void fsm_msgGetCoinTable(GetCoinTable *msg)
{
    RESP_INIT(CoinTable);

    if (msg->has_start != msg->has_end) {
        fsm_sendFailure(FailureType_Failure_Other,
                        "Incorrect GetCoinTable parameters");
        go_home();
        return;
    }

    resp->has_chunk_size = true;
    resp->chunk_size = sizeof(resp->table) / sizeof(resp->table[0]);

    if (msg->has_start && msg->has_end) {
        if (COINS_COUNT <= msg->start ||
            COINS_COUNT < msg->end ||
            msg->end < msg->start ||
            resp->chunk_size < msg->end - msg->start) {
            fsm_sendFailure(FailureType_Failure_Other,
                            "Incorrect GetCoinTable parameters");
            go_home();
            return;
        }
    }

    resp->has_num_coins = true;
    resp->num_coins = COINS_COUNT;

    if (msg->has_start && msg->has_end) {
        resp->table_count = msg->end - msg->start;
        memcpy(&resp->table[0], &coins[msg->start],
               resp->table_count * sizeof(resp->table[0]));
    }

    msg_write(MessageType_MessageType_CoinTable, resp);
}

static bool isValidModelNumber(const char *model) {
#define MODEL_ENTRY(STRING, ENUM) \
    if (!strcmp(model, STRING)) \
        return true;
#include "keepkey/board/models.def"
    return false;
}

void fsm_msgPing(Ping *msg)
{
    RESP_INIT(Success);

    // If device is in manufacture mode, turn if off, lock it, and program the
    // model number into OTP flash.
    if (is_mfg_mode() && msg->has_message && isValidModelNumber(msg->message)) {
        set_mfg_mode_off();
        char message[32];
        strncpy(message, msg->message, sizeof(message));
        message[31] = 0;
        flash_setModel(&message);
    }

    if(msg->has_button_protection && msg->button_protection)
        if(!confirm(ButtonRequestType_ButtonRequest_Ping, "Ping", "%s", msg->message))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Ping cancelled");
            go_home();
            return;
        }

    if(msg->has_pin_protection && msg->pin_protection)
    {
        if(!pin_protect_cached())
        {
            go_home();
            return;
        }
    }

    if(msg->has_passphrase_protection && msg->passphrase_protection)
    {
        if(!passphrase_protect())
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Ping cancelled");
            go_home();
            return;
        }
    }

    if(msg->has_message)
    {
        resp->has_message = true;
        memcpy(&(resp->message), &(msg->message), sizeof(resp->message));
    }

    msg_write(MessageType_MessageType_Success, resp);
    go_home();
}

void fsm_msgChangePin(ChangePin *msg)
{
    bool removal = msg->has_remove && msg->remove;
    bool confirmed = false;

    if(removal)
    {
        if(storage_has_pin())
        {
            confirmed = confirm(ButtonRequestType_ButtonRequest_RemovePin,
                                "Remove PIN", "Do you want to remove PIN protection?");
        }
        else
        {
            fsm_sendSuccess("PIN removed");
            return;
        }
    }
    else
    {
        if(storage_has_pin())
            confirmed = confirm(ButtonRequestType_ButtonRequest_ChangePin,
                                "Change PIN", "Do you want to change your PIN?");
        else
            confirmed = confirm(ButtonRequestType_ButtonRequest_CreatePin,
                                "Create PIN", "Do you want to add PIN protection?");
    }

    if(!confirmed)
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        removal ? "PIN removal cancelled" : "PIN change cancelled");
        go_home();
        return;
    }

    if(!pin_protect("Enter Current PIN"))
    {
        go_home();
        return;
    }

    if(removal)
    {
        storage_set_pin(0);
        storage_commit();
        fsm_sendSuccess("PIN removed");
    }
    else
    {
        if(change_pin())
        {
            storage_commit();
            fsm_sendSuccess("PIN changed");
        }
    }

    go_home();
}

void fsm_msgWipeDevice(WipeDevice *msg)
{
    (void)msg;

    if(!confirm(ButtonRequestType_ButtonRequest_WipeDevice, "Wipe Device",
                "Do you want to erase your private keys and settings?"))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Wipe cancelled");
        go_home();
        return;
    }

    /* Wipe device */
    storage_reset();
    storage_reset_uuid();
    storage_commit();

    fsm_sendSuccess("Device wiped");
    go_home();
}

void fsm_msgFirmwareErase(FirmwareErase *msg)
{
    (void)msg;
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in bootloader mode");
}

void fsm_msgFirmwareUpload(FirmwareUpload *msg)
{
    (void)msg;
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in bootloader mode");
}

void fsm_msgGetEntropy(GetEntropy *msg)
{
    if(!confirm(ButtonRequestType_ButtonRequest_GetEntropy,
                "Generate Entropy",
                "Do you want to generate and return entropy using the hardware RNG?"))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Entropy cancelled");
        go_home();
        return;
    }

    RESP_INIT(Entropy);
    uint32_t len = msg->size;

    if(len > ENTROPY_BUF)
    {
        len = ENTROPY_BUF;
    }

    resp->entropy.size = len;
    random_buffer(resp->entropy.bytes, len);
    msg_write(MessageType_MessageType_Entropy, resp);
    go_home();
}

void fsm_msgLoadDevice(LoadDevice *msg)
{
    if(storage_is_initialized())
    {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                        "Device is already initialized. Use Wipe first.");
        return;
    }

    if(!confirm_load_device(msg->has_node))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Load cancelled");
        go_home();
        return;
    }

    if(msg->has_mnemonic && !(msg->has_skip_checksum && msg->skip_checksum))
    {
        if(!mnemonic_check(msg->mnemonic))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            "Mnemonic with wrong checksum provided");
            go_home();
            return;
        }
    }

    storage_load_device(msg);

    storage_commit();
    fsm_sendSuccess("Device loaded");
    go_home();
}

void fsm_msgResetDevice(ResetDevice *msg)
{
    if(storage_is_initialized())
    {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                        "Device is already initialized. Use Wipe first.");
        return;
    }

    reset_init(
        msg->has_display_random && msg->display_random,
        msg->has_strength ? msg->strength : 128,
        msg->has_passphrase_protection && msg->passphrase_protection,
        msg->has_pin_protection && msg->pin_protection,
        msg->has_language ? msg->language : 0,
        msg->has_label ? msg->label : 0
    );
}

void fsm_msgEntropyAck(EntropyAck *msg)
{
    if(msg->has_entropy)
    {
        reset_entropy(msg->entropy.bytes, msg->entropy.size);
    }
    else
    {
        reset_entropy(0, 0);
    }
}

void fsm_msgCancel(Cancel *msg)
{
    (void)msg;
    recovery_abort(true);
    signing_abort();
    ethereum_signing_abort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Aborted");
}

void fsm_msgApplySettings(ApplySettings *msg)
{
    if(msg->has_label)
    {
        if(!confirm(ButtonRequestType_ButtonRequest_ChangeLabel,
                    "Change Label", "Do you want to change the label to \"%s\"?", msg->label))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            "Apply settings cancelled");
            go_home();
            return;
        }
    }

    if(msg->has_language)
    {
        if(!confirm(ButtonRequestType_ButtonRequest_ChangeLanguage,
                    "Change Language", "Do you want to change the language to %s?", msg->language))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            "Apply settings cancelled");
            go_home();
            return;
        }
    }

    if(msg->has_use_passphrase)
    {
        if(msg->use_passphrase)
        {
            if(!confirm(ButtonRequestType_ButtonRequest_EnablePassphrase,
                        "Enable Passphrase", "Do you want to enable passphrase encryption?"))
            {
                fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                "Apply settings cancelled");
                go_home();
                return;
            }
        }
        else
        {
            if(!confirm(ButtonRequestType_ButtonRequest_DisablePassphrase,
                        "Disable Passphrase", "Do you want to disable passphrase encryption?"))
            {
                fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                "Apply settings cancelled");
                go_home();
                return;
            }
        }
    }

    if(!msg->has_label && !msg->has_language && !msg->has_use_passphrase)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No setting provided");
        return;
    }

    if(!pin_protect_cached())
    {
        go_home();
        return;
    }

    if(msg->has_label)
    {
        storage_set_label(msg->label);
    }

    if(msg->has_language)
    {
        storage_set_language(msg->language);
    }

    if(msg->has_use_passphrase)
    {
        storage_set_passphrase_protected(msg->use_passphrase);
    }

    storage_commit();

    fsm_sendSuccess("Settings applied");
    go_home();
}

void fsm_msgCipherKeyValue(CipherKeyValue *msg)
{

    if (!storage_is_initialized())
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
        return;
    }

    if(!msg->has_key)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No key provided");
        return;
    }

    if(!msg->has_value)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No value provided");
        return;
    }

    if(msg->value.size % 16)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        "Value length must be a multiple of 16");
        return;
    }

    if(!pin_protect_cached())
    {
        go_home();
        return;
    }

    const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count);

    if(!node) { return; }

    bool encrypt = msg->has_encrypt && msg->encrypt;
    bool ask_on_encrypt = msg->has_ask_on_encrypt && msg->ask_on_encrypt;
    bool ask_on_decrypt = msg->has_ask_on_decrypt && msg->ask_on_decrypt;

    if((encrypt && ask_on_encrypt) || (!encrypt && ask_on_decrypt))
    {
        if(!confirm_cipher(encrypt, msg->key))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            "CipherKeyValue cancelled");
            go_home();
            return;
        }
    }

    uint8_t data[256 + 4];
    strlcpy((char *)data, msg->key, sizeof(data));
    strlcat((char *)data, ask_on_encrypt ? "E1" : "E0", sizeof(data));
    strlcat((char *)data, ask_on_decrypt ? "D1" : "D0", sizeof(data));

    hmac_sha512(node->private_key, 32, data, strlen((char *)data), data);

    RESP_INIT(CipheredKeyValue);

    if(encrypt)
    {
        aes_encrypt_ctx ctx;
        aes_encrypt_key256(data, &ctx);
        aes_cbc_encrypt(msg->value.bytes, resp->value.bytes, msg->value.size,
                        ((msg->iv.size == 16) ? (msg->iv.bytes) : (data + 32)), &ctx);
    }
    else
    {
        aes_decrypt_ctx ctx;
        aes_decrypt_key256(data, &ctx);
        aes_cbc_decrypt(msg->value.bytes, resp->value.bytes, msg->value.size,
                        ((msg->iv.size == 16) ? (msg->iv.bytes) : (data + 32)), &ctx);
    }

    resp->has_value = true;
    resp->value.size = msg->value.size;
    msg_write(MessageType_MessageType_CipheredKeyValue, resp);
    go_home();
}

void fsm_msgRecoveryDevice(RecoveryDevice *msg)
{
    if(storage_is_initialized())
    {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                        "Device is already initialized. Use Wipe first.");
        return;
    }

    if(msg->has_use_character_cipher &&
            msg->use_character_cipher == true)   // recovery via character cipher
    {
        recovery_cipher_init(
            msg->has_passphrase_protection && msg->passphrase_protection,
            msg->has_pin_protection && msg->pin_protection,
            msg->has_language ? msg->language : 0,
            msg->has_label ? msg->label : 0,
            msg->has_enforce_wordlist ? msg->enforce_wordlist : false
        );
    }
    else                                                                     // legacy way of recovery
    {
        recovery_init(
            msg->has_word_count ? msg->word_count : 12,
            msg->has_passphrase_protection && msg->passphrase_protection,
            msg->has_pin_protection && msg->pin_protection,
            msg->has_language ? msg->language : 0,
            msg->has_label ? msg->label : 0,
            msg->has_enforce_wordlist ? msg->enforce_wordlist : false
        );
    }
}

void fsm_msgWordAck(WordAck *msg)
{
    recovery_word(msg->word);
}

void fsm_msgCharacterAck(CharacterAck *msg)
{
    if(msg->has_delete && msg->del)
    {
        recovery_delete_character();
    }
    else if(msg->has_done && msg->done)
    {
        recovery_cipher_finalize();
    }
    else
    {
        recovery_character(msg->character);
    }
}

void fsm_msgApplyPolicies(ApplyPolicies *msg)
{
    RESP_INIT(ButtonRequest);
    resp->has_code = true;
    resp->code = ButtonRequestType_ButtonRequest_ApplyPolicies;
    resp->has_data = true;

    if(msg->policy_count == 0)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No policy provided");
        go_home();
        return;
    }

    strlcpy(resp->data, msg->policy[0].policy_name, sizeof(resp->data));

    if(msg->policy[0].enabled)
    {
        strlcat(resp->data, ":Enable", sizeof(resp->data));

        if(!confirm_with_custom_button_request(resp,
                                               "Enable Policy", "Do you want to enable %s policy?", msg->policy[0].policy_name))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            "Apply policy cancelled");
            go_home();
            return;
        }
    }
    else
    {
        strlcat(resp->data, ":Disable", sizeof(resp->data));

        if(!confirm_with_custom_button_request(resp,
                                               "Disable Policy", "Do you want to disable %s policy?", msg->policy[0].policy_name))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            "Apply policy cancelled");
            go_home();
            return;
        }
    }

    if(!pin_protect_cached())
    {
        go_home();
        return;
    }

    if(!storage_set_policy(&msg->policy[0]))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Policy could not be applied");
        go_home();
        return;
    }

    storage_commit();

    fsm_sendSuccess("Policies applied");
    go_home();
}

