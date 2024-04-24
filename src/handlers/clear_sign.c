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
#include "tron_plugin_handler.h"
#include "plugin_utils.h"
#include "plugin_interface.h"

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
    if (direct) {
        THROW(E_INCORRECT_DATA);
    } else {
        io_seproxyhal_send_status(E_INCORRECT_DATA);
        ui_idle();
    }
}


__attribute__((noinline)) static uint16_t finalize_parsing_helper(bool direct, bool *use_standard_UI) {
    char displayBuffer[50];
    uint8_t decimals = WEI_TO_ETHER;
    // uint64_t chain_id = get_tx_chain_id();
    // const char *ticker = get_displayable_ticker(&chain_id, chainConfig);
    const char *ticker = "TRX";
    ethPluginFinalize_t pluginFinalize;
    cx_err_t error = CX_INTERNAL_ERROR;

    // // Store the hash
    // CX_CHECK(cx_hash_no_throw((cx_hash_t *) &global_sha3,
    //                           CX_LAST,
    //                           transactionContext.hash,
    //                           0,
    //                           transactionContext.hash,
    //                           32));

    // Finalize the plugin handling
    if (dataContext.tokenContext.pluginStatus >= ETH_PLUGIN_RESULT_SUCCESSFUL) {
        tron_plugin_prepare_finalize(&pluginFinalize);
        pluginFinalize.address = txContent.account;

        if (!tron_plugin_call(ETH_PLUGIN_FINALIZE, (void *) &pluginFinalize)) {
            PRINTF("Plugin finalize call failed\n");
            reportFinalizeError(direct);
            if (!direct) {
                return 7;
            }
        }
        // Lookup tokens if requested
        ethPluginProvideInfo_t pluginProvideInfo;
        tron_plugin_prepare_provide_info(&pluginProvideInfo);
        if ((pluginFinalize.tokenLookup1 != NULL) || (pluginFinalize.tokenLookup2 != NULL)) {
            if (pluginFinalize.tokenLookup1 != NULL) {
                PRINTF("Lookup1: %.*H\n", ADDRESS_LENGTH, pluginFinalize.tokenLookup1);
                pluginProvideInfo.item1 = getKnownExtraToken(pluginFinalize.tokenLookup1, &transactionContext);
                if (pluginProvideInfo.item1 != NULL) {
                    PRINTF("Token1 ticker: %s\n", pluginProvideInfo.item1->token.ticker);
                }
            }
            if (pluginFinalize.tokenLookup2 != NULL) {
                PRINTF("Lookup2: %.*H\n", ADDRESS_LENGTH, pluginFinalize.tokenLookup2);
                pluginProvideInfo.item2 = getKnownExtraToken(pluginFinalize.tokenLookup2, &transactionContext);
                if (pluginProvideInfo.item2 != NULL) {
                    PRINTF("Token2 ticker: %s\n", pluginProvideInfo.item2->token.ticker);
                }
            }
            if (tron_plugin_call(ETH_PLUGIN_PROVIDE_INFO, (void *) &pluginProvideInfo) <=
                ETH_PLUGIN_RESULT_UNSUCCESSFUL) {
                PRINTF("Plugin provide token call failed\n");
                reportFinalizeError(direct);
                if (!direct) {
                    return 8;
                }
            }
            pluginFinalize.result = pluginProvideInfo.result;
        }
        if (pluginFinalize.result != ETH_PLUGIN_RESULT_FALLBACK) {
            // Handle the right interface
            switch (pluginFinalize.uiType) {
                case ETH_UI_TYPE_GENERIC:
                    // Use the dedicated ETH plugin UI
                    *use_standard_UI = false;
                    // Add the number of screens + the number of additional screens to get the total
                    // number of screens needed.
                    dataContext.tokenContext.pluginUiMaxItems =
                        pluginFinalize.numScreens + pluginProvideInfo.additionalScreens;
                    break;
                // case ETH_UI_TYPE_AMOUNT_ADDRESS:
                //     // Use the standard ETH UI as this plugin uses the amount/address UI
                //     *use_standard_UI = true;
                //     if ((pluginFinalize.amount == NULL) || (pluginFinalize.address == NULL)) {
                //         PRINTF("Incorrect amount/address set by plugin\n");
                //         reportFinalizeError(direct);
                //         if (!direct) {
                //             return false;
                //         }
                //     }
                //     memmove(txContent.value.value, pluginFinalize.amount, 32);
                //     txContent.value.length = 32;
                //     memmove(txContent.destination, pluginFinalize.address, 20);
                //     txContent.destinationLength = 20;
                //     if (pluginProvideInfo.item1 != NULL) {
                //         decimals = pluginProvideInfo.item1->token.decimals;
                //         ticker = pluginProvideInfo.item1->token.ticker;
                //     }
                //     break;
                default:
                    PRINTF("ui type %d not supported\n", pluginFinalize.uiType);
                    reportFinalizeError(direct);
                    if (!direct) {
                        return 9;
                    }
            }
        }
    }

#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if (G_swap_response_ready) {
            // Unreachable given current return to exchange mechanism. Safeguard against regression
            PRINTF("FATAL: safety against double sign triggered\n");
            os_sched_exit(-1);
        }
        G_swap_response_ready = true;
    }

    // // User has just validated a swap but ETH received apdus about a non standard plugin / contract
    // if (G_called_from_swap && !*use_standard_UI) {
    //     PRINTF("ERR_SILENT_MODE_CHECK_FAILED, G_called_from_swap\n");
    //     THROW(ERR_SILENT_MODE_CHECK_FAILED);
    // }
#endif  // HAVE_SWAP

    // if (tmpContent.txContent.dataPresent && !N_storage.dataAllowed) {
    //     reportFinalizeError(direct);
    //     ui_warning_contract_data();
    //     if (!direct) {
    //         return false;
    //     }
    // }

    // // Prepare destination address and amount to display
    // if (*use_standard_UI) {
    //     // Format the address in a temporary buffer, if in swap case compare it with validated
    //     // address, else commit it
    //     address_to_string(tmpContent.txContent.destination,
    //                       tmpContent.txContent.destinationLength,
    //                       displayBuffer,
    //                       sizeof(displayBuffer),
    //                       chainConfig->chainId);
    //     if (G_called_from_swap) {
    //         // Ensure the values are the same that the ones that have been previously validated
    //         if (strcasecmp_workaround(strings.common.fullAddress, displayBuffer) != 0) {
    //             PRINTF("ERR_SILENT_MODE_CHECK_FAILED, address check failed\n");
    //             THROW(ERR_SILENT_MODE_CHECK_FAILED);
    //         }
    //     } else {
    //         strlcpy(strings.common.fullAddress, displayBuffer, sizeof(strings.common.fullAddress));
    //     }
    //     PRINTF("Address displayed: %s\n", strings.common.fullAddress);

    //     // Format the amount in a temporary buffer, if in swap case compare it with validated
    //     // amount, else commit it
    //     if (!amountToString(tmpContent.txContent.value.value,
    //                         tmpContent.txContent.value.length,
    //                         decimals,
    //                         ticker,
    //                         displayBuffer,
    //                         sizeof(displayBuffer))) {
    //         PRINTF("OVERFLOW, amount to string failed\n");
    //         THROW(EXCEPTION_OVERFLOW);
    //     }

    //     if (G_called_from_swap) {
    //         // Ensure the values are the same that the ones that have been previously validated
    //         if (strcmp(strings.common.fullAmount, displayBuffer) != 0) {
    //             PRINTF("ERR_SILENT_MODE_CHECK_FAILED, amount check failed\n");
    //             PRINTF("Expected %s\n", strings.common.fullAmount);
    //             PRINTF("Received %s\n", displayBuffer);
    //             THROW(ERR_SILENT_MODE_CHECK_FAILED);
    //         }
    //     } else {
    //         strlcpy(strings.common.fullAmount, displayBuffer, sizeof(strings.common.fullAmount));
    //     }
    //     PRINTF("Amount displayed: %s\n", strings.common.fullAmount);
    // }

    // // Compute the max fee in a temporary buffer, if in swap case compare it with validated max fee,
    // // else commit it
    // max_transaction_fee_to_string(&tmpContent.txContent.gasprice,
    //                               &tmpContent.txContent.startgas,
    //                               displayBuffer,
    //                               sizeof(displayBuffer));
    // if (G_called_from_swap) {
    //     // Ensure the values are the same that the ones that have been previously validated
    //     if (strcmp(strings.common.maxFee, displayBuffer) != 0) {
    //         PRINTF("ERR_SILENT_MODE_CHECK_FAILED, fees check failed\n");
    //         PRINTF("Expected %s\n", strings.common.maxFee);
    //         PRINTF("Received %s\n", displayBuffer);
    //         THROW(ERR_SILENT_MODE_CHECK_FAILED);
    //     }
    // } else {
    //     strlcpy(strings.common.maxFee, displayBuffer, sizeof(strings.common.maxFee));
    // }

    // PRINTF("Fees displayed: %s\n", strings.common.maxFee);

    // // Prepare nonce to display
    // nonce_to_string(&tmpContent.txContent.nonce,
    //                 strings.common.nonce,
    //                 sizeof(strings.common.nonce));
    // PRINTF("Nonce: %s\n", strings.common.nonce);

    // // Prepare network field
    // get_network_as_string(strings.common.network_name, sizeof(strings.common.network_name));
    // PRINTF("Network: %s\n", strings.common.network_name);
    return 0;
end:
    return 10;
}


uint16_t finalizeParsing(bool direct) {
    bool use_standard_UI = true;
    // bool no_consent_check;
    uint16_t txResult = finalize_parsing_helper(direct, &use_standard_UI);
    if (txResult != 0) {
        return txResult;
    }
    // // If called from swap, the user has already validated a standard transaction
    // // And we have already checked the fields of this transaction above
    // no_consent_check = G_called_from_swap && use_standard_UI;

// #ifdef NO_CONSENT
//     no_consent_check = true;
// #endif  // NO_CONSENT

    // if (no_consent_check) {
    //     io_seproxyhal_touch_tx_ok(NULL);
    // } else {
        // if (use_standard_UI) {
        //     ux_approve_tx(false);
        // } else {
            dataContext.tokenContext.pluginUiState = PLUGIN_UI_OUTSIDE;
            dataContext.tokenContext.pluginUiCurrentItem = 0;
            // ux_approve_tx(true);
            ux_flow_display(APPROVAL_CLEAR_SIGN_TRANSFER, false);
        // }
    // }
}

int handleClearSign(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    if (p2 != 0x00) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

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

#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if (G_swap_response_ready) {
            // Safety against trying to make the app sign multiple TX
            // This code should never be triggered as the app is supposed to exit after
            // sending the signed transaction
            PRINTF("Safety against double signing triggered\n");
            os_sched_exit(-1);
        } else {
            // We will quit the app after this transaction, whether it succeeds or fails
            PRINTF("Swap response is ready, the app will quit after the next send\n");
            G_swap_response_ready = true;
        }
    }
#endif

    // process buffer
    uint16_t txResult = processTxForClearSign(workBuffer, dataLength, &txContent);

    PRINTF("txResult: %04x\n", txResult);
    switch (txResult) {
        case USTREAM_PROCESSING:
            // Last data should not return
            if (p1 == P1_LAST || p1 == P1_SIGN) {
                break;
            }
            return io_send_sw(E_OK);
        case USTREAM_FINISHED:
            break;
        case USTREAM_FAULT:
            return io_send_sw(E_INCORRECT_DATA);
        case USTREAM_MISSING_SETTING_DATA_ALLOWED:
#ifdef HAVE_SWAP
            if (G_called_from_swap) {
                return io_send_sw(E_SWAP_CHECKING_FAIL);
            }
#endif
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

#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if ((txContent.contractType != TRANSFERCONTRACT) &&      // TRX Transfer
            (txContent.contractType != TRIGGERSMARTCONTRACT)) {  // TRC20 Transfer
            PRINTF("Refused contract type when in SWAP mode\n");
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }

        if (txContent.contractType == TRIGGERSMARTCONTRACT) {
            if (txContent.TRC20Method != 1) {
                // Only transfer method allowed for TRC20
                PRINTF("Refused method type when in SWAP mode\n");
                return io_send_sw(E_SWAP_CHECKING_FAIL);
            }
        }

    }
#endif  // HAVE_SWAP

    txResult = finalizeParsing(false);
    if (txResult != 0)
    {
        return io_send_sw(txResult);
    }
    return 0;
}

