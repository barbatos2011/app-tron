/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2022 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
#include "ui_globals.h"
#include "helpers.h"
#include "io.h"
#include "os.h"
#include "ux.h"
#include "crypto_helpers.h"
#include "ui_idle_menu.h"
#include "app_errors.h"

#ifdef HAVE_NBGL
#include "nbgl_use_case.h"
#include "ui_logic.h"
#endif

volatile uint8_t customContractField;
char fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];  // 5 extra bytes used to inform MultSign ID
char toAddress[BASE58CHECK_ADDRESS_SIZE + 1];
char addressSummary[40];
char fullContract[MAX_TOKEN_LENGTH];
char TRC20Action[9];
char TRC20ActionSendAllow[8];
char fullHash[HASH_SIZE * 2 + 1];
int8_t votes_count;
tmpCtx_t global_ctx;
cx_sha3_t global_sha3;
strings_t strings;

extern void reset_app_context();

/**
 * Reset the UI buffer
 *
 * Simply sets its first byte to a NULL character
 */
void reset_ui_191_buffer(void) {
    UI_191_BUFFER[0] = '\0';
}

/**
 * Get used space from UI buffer
 *
 * @return size in bytes
 */
size_t ui_191_buffer_length(void) {
    return strlen(UI_191_BUFFER);
}

/**
 * Get remaining space from UI buffer
 *
 * @return size in bytes
 */
size_t remaining_ui_191_buffer_length(void) {
    // -1 for the ending NULL byte
    return (sizeof(UI_191_BUFFER) - 1) - ui_191_buffer_length();
}

/**
 * Get free space from UI buffer
 *
 * @return pointer to the free space
 */
char *remaining_ui_191_buffer(void) {
    return &UI_191_BUFFER[ui_191_buffer_length()];
}

bool ui_callback_address_ok(bool display_menu) {
    helper_send_response_pubkey(&global_ctx.publicKeyContext);

    reset_app_context();
    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return true;
}

bool ui_callback_signMessage_ok(bool display_menu) {
    bool ret = true;

    if (signTransaction(&global_ctx.transactionContext) != 0) {
        io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
        ret = false;
    } else {
        io_send_response_pointer(global_ctx.transactionContext.signature,
                                 global_ctx.transactionContext.signatureLength,
                                 E_OK);
    }

    reset_app_context();
    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return ret;
}

bool ui_callback_tx_cancel(bool display_menu) {
    reset_app_context();
    io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);

    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return true;
}

bool ui_callback_tx_ok(bool display_menu) {
    bool ret = true;

    if (signTransaction(&global_ctx.transactionContext) != 0) {
        io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
        ret = false;
    } else {
        io_send_response_pointer(global_ctx.transactionContext.signature,
                                 global_ctx.transactionContext.signatureLength,
                                 E_OK);
    }

    reset_app_context();
    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return ret;
}

bool ui_callback_ecdh_ok(bool display_menu) {
    cx_err_t err;
    cx_ecfp_private_key_t privateKey;
    uint32_t tx = 0;

    // Get private key
    err = bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                        global_ctx.transactionContext.bip32_path.indices,
                                        global_ctx.transactionContext.bip32_path.length,
                                        &privateKey,
                                        NULL);
    if (err != CX_OK) {
        goto end;
    }

    err = cx_ecdh_no_throw(&privateKey,
                           CX_ECDH_POINT,
                           global_ctx.transactionContext.signature,
                           65,
                           G_io_apdu_buffer,
                           sizeof(G_io_apdu_buffer));
    if (err != CX_OK) {
        goto end;
    }

    size_t size;
    err = cx_ecdomain_parameters_length(CX_CURVE_256K1, &size);
    tx = 1 + 2 * size;

end:
    // Clear tmp buffer data
    explicit_bzero(&privateKey, sizeof(privateKey));

    reset_app_context();
    if (err == CX_OK) {
        io_send_response_pointer(G_io_apdu_buffer, tx, E_OK);
    } else {
        io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }

    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    if (err == CX_OK) {
        return true;
    } else {
        return false;
    }
}

static const uint8_t TIP_712_MAGIC[] = {0x19, 0x01};

void format_signature_out(const uint8_t *signature) {
    memset(G_io_apdu_buffer, 0x00, 64);
    uint8_t offset = 0;
    uint8_t xoffset = 4;  // point to r value
    // copy r
    uint8_t xlength = signature[xoffset - 1];
    if (xlength == 33) {
        xlength = 32;
        xoffset++;
    }
    memmove(G_io_apdu_buffer + offset + 32 - xlength, signature + xoffset, xlength);
    offset += 32;
    xoffset += xlength + 2;  // move over rvalue and TagLEn
    // copy s value
    xlength = signature[xoffset - 1];
    if (xlength == 33) {
        xlength = 32;
        xoffset++;
    }
    memmove(G_io_apdu_buffer + offset + 32 - xlength, signature + xoffset, xlength);
}

bool ui_callback_signMessage712_v0_ok(bool display_menu) {
    uint32_t tx = 0;
    cx_err_t err;

    cx_ecfp_private_key_t privateKey;
    uint8_t signature[100];
    unsigned int info = 0;

    cx_sha3_t sha3;
    uint8_t hash[32];
    io_seproxyhal_io_heartbeat();

    if (cx_keccak_init_no_throw(&sha3, 256) != CX_OK) {
        return false;
    }

    if (cx_hash_no_throw((cx_hash_t *) &sha3,
                         0,
                         (uint8_t *) TIP_712_MAGIC,
                         sizeof(TIP_712_MAGIC),
                         NULL,
                         0) != CX_OK) {
        return false;
    }

    if (cx_hash_no_throw((cx_hash_t *) &sha3,
                         0,
                         global_ctx.messageSigningContext712.domainHash,
                         sizeof(global_ctx.messageSigningContext712.domainHash),
                         NULL,
                         0) != CX_OK) {
        return false;
    }

    if (cx_hash_no_throw((cx_hash_t *) &sha3,
                         CX_LAST,
                         global_ctx.messageSigningContext712.messageHash,
                         sizeof(global_ctx.messageSigningContext712.messageHash),
                         hash,
                         sizeof(hash)) != CX_OK) {
        return false;
    }

    PRINTF("TIP712 hash to sign %.*H\n", 32, hash);

    io_seproxyhal_io_heartbeat();
    // Get private key
    err = bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                        global_ctx.messageSigningContext712.bip32Path,
                                        global_ctx.messageSigningContext712.pathLength,
                                        &privateKey,
                                        NULL);
    if (err != CX_OK) {
        goto end;
    }

    io_seproxyhal_io_heartbeat();
    unsigned int signatureLength = sizeof(signature);
    if (cx_ecdsa_sign_no_throw(&privateKey,
                               CX_RND_RFC6979 | CX_LAST,
                               CX_SHA256,
                               hash,
                               sizeof(hash),
                               signature,
                               &signatureLength,
                               &info) != CX_OK) {
        return false;
    }

    format_signature_out(signature);
    G_io_apdu_buffer[64] = 0;
    if (info & CX_ECCINFO_PARITY_ODD) {
        G_io_apdu_buffer[64]++;
    }
    tx = 65;
end:
    // Clear tmp buffer data
    explicit_bzero(&privateKey, sizeof(privateKey));

    reset_app_context();
    if (err == CX_OK) {
        // Send back the response, do not restart the event loop
        io_send_response_pointer(G_io_apdu_buffer, tx, E_OK);
    } else {
        io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }

    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    if (err == CX_OK) {
        return true;
    } else {
        return false;
    }
}

bool ui_callback_signMessage712_v0_cancel(bool display_menu) {
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    reset_app_context();
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return true;
}