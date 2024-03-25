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

#include "io.h"

#include "format.h"

#include "helpers.h"
#include "handlers.h"
#include "ui_review_menu.h"
#include "ui_globals.h"
#include "uint256.h"
#include "app_errors.h"
#include "parse.h"
#include "settings.h"
#include "tron_plugin_interface.h"
#include "tron_plugin_helper.h"
#include "plugin_utils.h"
#include "tron_plugin_helper.h"

#ifdef HAVE_SWAP
#include "swap.h"
#include "handle_swap_sign_transaction.h"
#endif  // HAVE_SWAP

void reset_app_context() {
    // PRINTF("!!RESET_APP_CONTEXT\n");
#ifdef HAVE_SWAP
    G_called_from_swap = false;
    G_swap_response_ready = false;
#endif  // HAVE_SWAP

    memset(&txContext, 0, sizeof(txContext_t));
    memset(&txContent, 0, sizeof(txContent_t));
}

void io_seproxyhal_send_status(uint32_t sw) {
    G_io_apdu_buffer[0] = ((sw >> 8) & 0xff);
    G_io_apdu_buffer[1] = (sw & 0xff);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

void reportFinalizeError(bool direct) {
    reset_app_context();
    io_send_sw(E_INCORRECT_DATA);
}

__attribute__((noinline)) static uint8_t finalize_parsing_helper(bool direct) {
    tronPluginFinalize_t pluginFinalize;

    // Finalize the plugin handling
    if (dataContext.tokenContext.pluginStatus >= TRON_PLUGIN_RESULT_SUCCESSFUL) {
        tron_plugin_prepare_finalize(&pluginFinalize);
        pluginFinalize.address = txContent.account;

        if (!tron_plugin_call(TRON_PLUGIN_FINALIZE, (void *) &pluginFinalize)) {
            PRINTF("Plugin finalize call failed\n");
            reportFinalizeError(direct);
            if (!direct) {
                return 7;
            }
        }
        // Lookup tokens if requested
        tronPluginProvideInfo_t pluginProvideInfo;
        tron_plugin_prepare_provide_info(&pluginProvideInfo);
        if ((pluginFinalize.tokenLookup1 != NULL) || (pluginFinalize.tokenLookup2 != NULL)) {
            if (pluginFinalize.tokenLookup1 != NULL) {
                PRINTF("Lookup1: %.*H\n", ADDRESS_SIZE, pluginFinalize.tokenLookup1);
                pluginProvideInfo.item1 =
                    getKnownExtraToken(pluginFinalize.tokenLookup1, &transactionContext);
                if (pluginProvideInfo.item1 != NULL) {
                    PRINTF("Token1 ticker: %s\n", pluginProvideInfo.item1->token.ticker);
                }
            }
            if (pluginFinalize.tokenLookup2 != NULL) {
                PRINTF("Lookup2: %.*H\n", ADDRESS_SIZE, pluginFinalize.tokenLookup2);
                pluginProvideInfo.item2 =
                    getKnownExtraToken(pluginFinalize.tokenLookup2, &transactionContext);
                if (pluginProvideInfo.item2 != NULL) {
                    PRINTF("Token2 ticker: %s\n", pluginProvideInfo.item2->token.ticker);
                }
            }
            if (tron_plugin_call(TRON_PLUGIN_PROVIDE_INFO, (void *) &pluginProvideInfo) <=
                TRON_PLUGIN_RESULT_UNSUCCESSFUL) {
                PRINTF("Plugin provide token call failed\n");
                reportFinalizeError(direct);
                if (!direct) {
                    return 8;
                }
            }
            pluginFinalize.result = pluginProvideInfo.result;
        }
        if (pluginFinalize.result != TRON_PLUGIN_RESULT_FALLBACK) {
            // Handle the right interface
            switch (pluginFinalize.uiType) {
                case TRON_UI_TYPE_GENERIC:
                    // Add the number of screens + the number of additional screens to get the total
                    // number of screens needed.
                    dataContext.tokenContext.pluginUiMaxItems =
                        pluginFinalize.numScreens + pluginProvideInfo.additionalScreens;
                    break;
                default:
                    PRINTF("ui type %d not supported\n", pluginFinalize.uiType);
                    reportFinalizeError(direct);
                    if (!direct) {
                        return 9;
                    }
            }
        }
    }

    // if (tmpContent.txContent.dataPresent && !N_storage.dataAllowed) {
    //     reportFinalizeError(direct);
    //     ui_warning_contract_data();
    //     if (!direct) {
    //         return false;
    //     }
    // }

    return 0;
}

uint8_t finalizeParsing(bool direct, bool warning) {
    uint8_t txResult = finalize_parsing_helper(direct);
    if (txResult != 0) {
        return txResult;
    }

    dataContext.tokenContext.pluginUiState = PLUGIN_UI_OUTSIDE;
    dataContext.tokenContext.pluginUiCurrentItem = 0;

    ux_flow_display(APPROVAL_CLEAR_SIGN_TRANSFER, warning);
    return 0;
}

int handleClearSign(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    if (p2 != 0x00) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        PRINTF("Not support clear-signing now in SWAP mode\n");
        return io_send_sw(E_SWAP_CHECKING_FAIL);
    }
#endif

    // initialize context
    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        off_t ret = read_bip32_path(workBuffer, dataLength, &transactionContext.bip32_path);
        if (ret < 0) {
            return io_send_sw(E_INCORRECT_BIP32_PATH);
        }
        workBuffer += ret;
        dataLength -= ret;

        initTx(&txContext, &txContent);
        customContractField = 0;

    } else if ((p1 != P1_MORE) && (p1 != P1_LAST)) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    // Context must be initialized first
    if (!txContext.initialized) {
        PRINTF("Context not initialized\n");
        // NOTE: if txContext is not initialized, then there must be seq errors in P1/P2.
        return io_send_sw(E_INCORRECT_P1_P2);
    }
    // hash data
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &txContext.sha2, 0, workBuffer, dataLength, NULL, 32));

    uint16_t txResult;
    // process buffer
    if (p1 == P1_SIGN) {
        txResult = processTxForClearSign(workBuffer, dataLength, &txContent);
    } else {
        // txResult = processTxForCSMultiParts(workBuffer, dataLength, &txContent, p1);
        uint32_t ret = processTxForCSMultiParts(workBuffer, dataLength, &txContent, p1);
        // if (ret != 0 && ret != 1)
        // {
        //     return io_send_sw(ret);
        // }
        // return io_send_sw(ret);
        txResult = ret;
        // return io_send_sw(txContent.exchangeID);
        // if (p1 == P1_LAST)
        // {
        // return io_send_sw(txContent.permission_id+10);
        // }
        // if (ret == 0 || ret == 1)
        // {
        //     return io_send_sw(E_OK);
        // }
        // return io_send_sw(ret);
    }
    // return io_send_sw(txResult);

    PRINTF("txResult: %04x\n", txResult);
    switch (txResult) {
        case USTREAM_PROCESSING:
            // Last data should not return
            if (p1 == P1_LAST || p1 == P1_SIGN) {
                break;
            }
            return io_send_sw(E_OK);
        case USTREAM_FINISHED:
            // return io_send_sw(txContent.permission_id+10);
            break;
        case USTREAM_FAULT:
            return io_send_sw(E_INCORRECT_DATA);
        case USTREAM_MISSING_SETTING_DATA_ALLOWED:
            return io_send_sw(E_MISSING_SETTING_DATA_ALLOWED);
        default:
            PRINTF("Unexpected parser status\n");
            return io_send_sw(txResult);
    }

    // Last data hash
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &txContext.sha2,
                               CX_LAST,
                               workBuffer,
                               0,
                               transactionContext.hash,
                               32));

    if (txContent.permission_id > 0) {
        PRINTF("Set permission_id...\n");
        snprintf((char *) fromAddress, 5, "P%d - ", txContent.permission_id);
        getBase58FromAddress(txContent.account, fromAddress + 4, HAS_SETTING(S_TRUNCATE_ADDRESS));
    } else {
        PRINTF("Regular transaction...\n");
        getBase58FromAddress(txContent.account, fromAddress, HAS_SETTING(S_TRUNCATE_ADDRESS));
    }

    bool data_warning = ((txContent.dataBytes > 0) ? true : false);

    txResult = finalizeParsing(false, data_warning);
    if (txResult != 0) {
        return io_send_sw(txResult);
    }
    return 0;
}
