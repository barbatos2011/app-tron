/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2023 Ledger
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
#include <string.h>
#include <stdint.h>

#include "cx.h"
#include "io.h"

#include "format.h"

#include "helpers.h"
#include "ui_review_menu.h"
#include "app_errors.h"
#include "handlers.h"
#include "parse.h"
#include "ui_globals.h"

static const char SIGN_MAGIC[] = "\x19TRON Signed Message:\n";

states191_t states191;
uint8_t processed_size_191;

cx_sha3_t global_sha3;

int handleSignPersonalMessageV2(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    processed_size_191 = 0;

    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        reset_app_context();
        if (appState != APP_STATE_IDLE) {
            return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
        }
        appState = APP_STATE_SIGNING_MESSAGE_V2;

        off_t ret = read_bip32_path(workBuffer, dataLength, &transactionContext.bip32_path);
        if (ret < 0) {
            return io_send_sw(E_INCORRECT_BIP32_PATH);
        }
        if (initPublicKeyContext(&transactionContext.bip32_path, fromAddress) != 0) {
            return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
        }
        workBuffer += ret;
        dataLength -= ret;
        processed_size_191 += ret;

        // Message Length
        txContent.dataBytes = U4BE(workBuffer, 0);
        workBuffer += 4;
        dataLength -= 4;
        processed_size_191 += 4;

        // Initialize message header + length
        CX_ASSERT(cx_keccak_init_no_throw(&global_sha3, 256));
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &global_sha3,
                                   0,
                                   (const uint8_t *) SIGN_MAGIC,
                                   sizeof(SIGN_MAGIC) - 1,
                                   NULL,
                                   0));

        char tmp[11];
        snprintf((char *) tmp, 11, "%d", (uint32_t) txContent.dataBytes);
        CX_ASSERT(
            cx_hash_no_throw((cx_hash_t *) &global_sha3, 0, (const uint8_t *) tmp, strlen(tmp), NULL, 0));

        reset_ui_191_buffer();
        states191.sign_state = STATE_191_HASH_DISPLAY;
        states191.ui_started = false;
    } else if (p1 != P1_MORE) {
        return io_send_sw(E_INCORRECT_P1_P2);
    } else if (appState != APP_STATE_SIGNING_MESSAGE_V2) {
        PRINTF("Error: App not already in signing state!\n");
        return io_send_sw(E_INCORRECT_DATA);
    }

    if (p2 != 0) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }
    if (dataLength > txContent.dataBytes) {
        return io_send_sw(E_INCORRECT_LENGTH);
    }

    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &global_sha3, 0, workBuffer, dataLength, NULL, 0));
    txContent.dataBytes -= dataLength;
    if (txContent.dataBytes == 0) {
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &global_sha3,
                                   CX_LAST,
                                   workBuffer,
                                   0,
                                   transactionContext.hash,
                                   32));
    }

    if (states191.sign_state == STATE_191_HASH_DISPLAY) {
        if (feed_display()==1){
            return io_send_sw(E_OK);
        }
    } else  // hash only
    {
        if (txContent.dataBytes == 0) {
            ui_191_switch_to_sign();
        } else {
            return io_send_sw(E_OK);
        }
    }

    return 0;
}

