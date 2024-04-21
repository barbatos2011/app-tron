#include <string.h>
#include "tron_plugin_handler.h"
#include "tron_plugin_interface.h"
#include "plugin_utils.h"
#include "ui_globals.h"


extraInfo_t *getKnownExtraToken(uint8_t *contractAddress, transactionContext_t *transactionContext) {
    union extraInfo_t *currentItem = NULL;
    // Works for ERC-20 & NFT tokens since both structs in the union have the
    // contract address aligned
    for (uint8_t i = 0; i < MAX_ITEMS; i++) {
        currentItem = (union extraInfo_t *) &transactionContext->extraInfo[i].token;
        if (transactionContext->tokenSet[i] &&
            (memcmp(currentItem->token.address, contractAddress, ADDRESS_LENGTH) == 0)) {
            PRINTF("Token found at index %d\n", i);
            return currentItem;
        }
    }

    return NULL;
}

void tron_plugin_prepare_init(ethPluginInitContract_t *init,
                             const uint8_t *selector,
                             uint32_t dataSize) {
    memset((uint8_t *) init, 0, sizeof(ethPluginInitContract_t));
    init->selector = selector;
    init->dataSize = dataSize;
}

void tron_plugin_prepare_provide_parameter(ethPluginProvideParameter_t *provideParameter,
                                          uint8_t *parameter,
                                          uint32_t parameterOffset) {
    memset((uint8_t *) provideParameter, 0, sizeof(ethPluginProvideParameter_t));
    provideParameter->parameter = parameter;
    provideParameter->parameterOffset = parameterOffset;
}

void tron_plugin_prepare_finalize(ethPluginFinalize_t *finalize) {
    memset((uint8_t *) finalize, 0, sizeof(ethPluginFinalize_t));
}

void tron_plugin_prepare_provide_info(ethPluginProvideInfo_t *provideToken) {
    memset((uint8_t *) provideToken, 0, sizeof(ethPluginProvideInfo_t));
}

void tron_plugin_prepare_query_contract_ID(ethQueryContractID_t *queryContractID,
                                          char *name,
                                          uint32_t nameLength,
                                          char *version,
                                          uint32_t versionLength) {
    memset((uint8_t *) queryContractID, 0, sizeof(ethQueryContractID_t));
    queryContractID->name = name;
    queryContractID->nameLength = nameLength;
    queryContractID->version = version;
    queryContractID->versionLength = versionLength;
}

void tron_plugin_prepare_query_contract_UI(ethQueryContractUI_t *queryContractUI,
                                          uint8_t screenIndex,
                                          char *title,
                                          uint32_t titleLength,
                                          char *msg,
                                          uint32_t msgLength) {
    // uint64_t chain_id;

    memset((uint8_t *) queryContractUI, 0, sizeof(ethQueryContractUI_t));

    // If no extra information was found, set the pointer to NULL
    if (NO_EXTRA_INFO(transactionContext, 1)) {
        queryContractUI->item1 = NULL;
    } else {
        queryContractUI->item1 = &transactionContext.extraInfo[1];
    }

    // If no extra information was found, set the pointer to NULL
    if (NO_EXTRA_INFO(transactionContext, 0)) {
        queryContractUI->item2 = NULL;
    } else {
        queryContractUI->item2 = &transactionContext.extraInfo[0];
    }

    queryContractUI->screenIndex = screenIndex;
    // chain_id = get_tx_chain_id();
    strlcpy(queryContractUI->network_ticker,
            "TRX",
            sizeof(queryContractUI->network_ticker));
    queryContractUI->title = title;
    queryContractUI->titleLength = titleLength;
    queryContractUI->msg = msg;
    queryContractUI->msgLength = msgLength;
}


void plugin_ui_get_id(void) {
    ethQueryContractID_t pluginQueryContractID;
    tron_plugin_prepare_query_contract_ID(&pluginQueryContractID,
                                         addressSummary,
                                         sizeof(addressSummary),
                                         fullContract,
                                         sizeof(fullContract));
    // Query the original contract for ID if it's not an internal alias
    if (!tron_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_ID, (void *) &pluginQueryContractID)) {
        PRINTF("Plugin query contract ID call failed\n");
        ui_callback_tx_cancel(true);
    }
}

void plugin_ui_get_item_internal(char *title_buffer,
                                 size_t title_buffer_size,
                                 char *msg_buffer,
                                 size_t msg_buffer_size) {
    ethQueryContractUI_t pluginQueryContractUI;
    tron_plugin_prepare_query_contract_UI(&pluginQueryContractUI,
                                         dataContext.tokenContext.pluginUiCurrentItem,
                                         title_buffer,
                                         title_buffer_size,
                                         msg_buffer,
                                         msg_buffer_size);
    if (!tron_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_UI, (void *) &pluginQueryContractUI)) {
        PRINTF("Plugin query contract UI call failed\n");
        ui_callback_tx_cancel(true);
    }
}

void plugin_ui_get_item(void) {
    plugin_ui_get_item_internal(addressSummary,
                                sizeof(addressSummary),
                                fullContract,
                                sizeof(fullContract));
}

static void tron_plugin_perform_init_default(uint8_t *contractAddress,
                                            ethPluginInitContract_t *init) {
    // check if the registered external plugin matches the TX contract address / selector
    if (memcmp(contractAddress,
               dataContext.tokenContext.contractAddress,
               sizeof(dataContext.tokenContext.contractAddress)) != 0) {
        PRINTF("Got contract: %.*H\n", ADDRESS_LENGTH, contractAddress);
        PRINTF("Expected contract: %.*H\n",
               ADDRESS_LENGTH,
               dataContext.tokenContext.contractAddress);
        os_sched_exit(0);
    }
    if (memcmp(init->selector,
               dataContext.tokenContext.methodSelector,
               sizeof(dataContext.tokenContext.methodSelector)) != 0) {
        PRINTF("Got selector: %.*H\n", SELECTOR_SIZE, init->selector);
        PRINTF("Expected selector: %.*H\n", SELECTOR_SIZE, dataContext.tokenContext.methodSelector);
        os_sched_exit(0);
    }
    PRINTF("Plugin will be used\n");
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_OK;
}

eth_plugin_result_t tron_plugin_perform_init(uint8_t *contractAddress,
                                            ethPluginInitContract_t *init) {
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_UNAVAILABLE;

    PRINTF("Selector %.*H\n", 4, init->selector);
    tron_plugin_perform_init_default(contractAddress, init);
    contractAddress = NULL;

    eth_plugin_result_t status = ETH_PLUGIN_RESULT_UNAVAILABLE;

    PRINTF("tron_plugin_init\n");
    PRINTF("Trying plugin %s\n", dataContext.tokenContext.pluginName);
    status = tron_plugin_call(ETH_PLUGIN_INIT_CONTRACT, (void *) init);

    if (status <= ETH_PLUGIN_RESULT_UNSUCCESSFUL) {
        return status;
    }
    PRINTF("tron_plugin_init ok %s\n", dataContext.tokenContext.pluginName);
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_OK;
    return ETH_PLUGIN_RESULT_OK;
}

eth_plugin_result_t tron_plugin_call(int method, void *parameter) {
    ethPluginSharedRW_t pluginRW;
    ethPluginSharedRO_t pluginRO;
    char *alias;
    uint8_t i;

    // pluginRW.sha3 = &global_sha3;
    pluginRO.txContent = &txContent;

    if (dataContext.tokenContext.pluginStatus <= ETH_PLUGIN_RESULT_UNSUCCESSFUL) {
        PRINTF("Cached plugin call but no plugin available\n");
        return dataContext.tokenContext.pluginStatus;
    }
    alias = dataContext.tokenContext.pluginName;

    // Prepare the call

    switch (method) {
        case ETH_PLUGIN_INIT_CONTRACT:
            PRINTF("-- PLUGIN INIT CONTRACT --\n");
            ((ethPluginInitContract_t *) parameter)->interfaceVersion =
                ETH_PLUGIN_INTERFACE_VERSION_LATEST;
            ((ethPluginInitContract_t *) parameter)->result = ETH_PLUGIN_RESULT_UNAVAILABLE;
            ((ethPluginInitContract_t *) parameter)->pluginSharedRW = &pluginRW;
            ((ethPluginInitContract_t *) parameter)->pluginSharedRO = &pluginRO;
            ((ethPluginInitContract_t *) parameter)->pluginContext =
                (uint8_t *) &dataContext.tokenContext.pluginContext;
            ((ethPluginInitContract_t *) parameter)->pluginContextLength =
                sizeof(dataContext.tokenContext.pluginContext);
            ((ethPluginInitContract_t *) parameter)->alias = dataContext.tokenContext.pluginName;
            break;
        case ETH_PLUGIN_PROVIDE_PARAMETER:
            PRINTF("-- PLUGIN PROVIDE PARAMETER --\n");
            ((ethPluginProvideParameter_t *) parameter)->result = ETH_PLUGIN_RESULT_UNAVAILABLE;
            ((ethPluginProvideParameter_t *) parameter)->pluginSharedRW = &pluginRW;
            ((ethPluginProvideParameter_t *) parameter)->pluginSharedRO = &pluginRO;
            ((ethPluginProvideParameter_t *) parameter)->pluginContext =
                (uint8_t *) &dataContext.tokenContext.pluginContext;
            break;
        case ETH_PLUGIN_FINALIZE:
            PRINTF("-- PLUGIN FINALIZE --\n");
            ((ethPluginFinalize_t *) parameter)->result = ETH_PLUGIN_RESULT_UNAVAILABLE;
            ((ethPluginFinalize_t *) parameter)->pluginSharedRW = &pluginRW;
            ((ethPluginFinalize_t *) parameter)->pluginSharedRO = &pluginRO;
            ((ethPluginFinalize_t *) parameter)->pluginContext =
                (uint8_t *) &dataContext.tokenContext.pluginContext;
            break;
        case ETH_PLUGIN_PROVIDE_INFO:
            PRINTF("-- PLUGIN PROVIDE INFO --\n");
            ((ethPluginProvideInfo_t *) parameter)->result = ETH_PLUGIN_RESULT_UNAVAILABLE;
            ((ethPluginProvideInfo_t *) parameter)->pluginSharedRW = &pluginRW;
            ((ethPluginProvideInfo_t *) parameter)->pluginSharedRO = &pluginRO;
            ((ethPluginProvideInfo_t *) parameter)->pluginContext =
                (uint8_t *) &dataContext.tokenContext.pluginContext;
            break;
        case ETH_PLUGIN_QUERY_CONTRACT_ID:
            PRINTF("-- PLUGIN QUERY CONTRACT ID --\n");
            ((ethQueryContractID_t *) parameter)->result = ETH_PLUGIN_RESULT_UNAVAILABLE;
            ((ethQueryContractID_t *) parameter)->pluginSharedRW = &pluginRW;
            ((ethQueryContractID_t *) parameter)->pluginSharedRO = &pluginRO;
            ((ethQueryContractID_t *) parameter)->pluginContext =
                (uint8_t *) &dataContext.tokenContext.pluginContext;
            break;
        case ETH_PLUGIN_QUERY_CONTRACT_UI:
            PRINTF("-- PLUGIN QUERY CONTRACT UI --\n");
            ((ethQueryContractUI_t *) parameter)->pluginSharedRW = &pluginRW;
            ((ethQueryContractUI_t *) parameter)->pluginSharedRO = &pluginRO;
            ((ethQueryContractUI_t *) parameter)->pluginContext =
                (uint8_t *) &dataContext.tokenContext.pluginContext;
            break;
        default:
            PRINTF("Unknown plugin method %d\n", method);
            return ETH_PLUGIN_RESULT_UNAVAILABLE;
    }

    uint32_t params[3];
    params[0] = (uint32_t) alias;
    params[1] = method;
    params[2] = (uint32_t) parameter;
    BEGIN_TRY {
        TRY {
            os_lib_call(params);
        }
        CATCH_OTHER(e) {
            PRINTF("Plugin call exception for %s\n", alias);
        }
        FINALLY {
        }
    }
    END_TRY;

    // Check the call result
    PRINTF("method: %d\n", method);
    switch (method) {
        case ETH_PLUGIN_INIT_CONTRACT:
            switch (((ethPluginInitContract_t *) parameter)->result) {
                case ETH_PLUGIN_RESULT_OK:
                    break;
                case ETH_PLUGIN_RESULT_ERROR:
                    return ETH_PLUGIN_RESULT_ERROR;
                default:
                    return ETH_PLUGIN_RESULT_UNAVAILABLE;
            }
            break;
        case ETH_PLUGIN_PROVIDE_PARAMETER:
            switch (((ethPluginProvideParameter_t *) parameter)->result) {
                case ETH_PLUGIN_RESULT_OK:
                case ETH_PLUGIN_RESULT_FALLBACK:
                    break;
                case ETH_PLUGIN_RESULT_ERROR:
                    return ETH_PLUGIN_RESULT_ERROR;
                default:
                    return ETH_PLUGIN_RESULT_UNAVAILABLE;
            }
            break;
        case ETH_PLUGIN_FINALIZE:
            switch (((ethPluginFinalize_t *) parameter)->result) {
                case ETH_PLUGIN_RESULT_OK:
                case ETH_PLUGIN_RESULT_FALLBACK:
                    break;
                case ETH_PLUGIN_RESULT_ERROR:
                    return ETH_PLUGIN_RESULT_ERROR;
                default:
                    return ETH_PLUGIN_RESULT_UNAVAILABLE;
            }
            break;
        case ETH_PLUGIN_PROVIDE_INFO:
            PRINTF("RESULT: %d\n", ((ethPluginProvideInfo_t *) parameter)->result);
            switch (((ethPluginProvideInfo_t *) parameter)->result) {
                case ETH_PLUGIN_RESULT_OK:
                case ETH_PLUGIN_RESULT_FALLBACK:
                    break;
                case ETH_PLUGIN_RESULT_ERROR:
                    return ETH_PLUGIN_RESULT_ERROR;
                default:
                    return ETH_PLUGIN_RESULT_UNAVAILABLE;
            }
            break;
        case ETH_PLUGIN_QUERY_CONTRACT_ID:
            if (((ethQueryContractID_t *) parameter)->result != ETH_PLUGIN_RESULT_OK) {
                return ETH_PLUGIN_RESULT_ERROR;
            }
            break;
        case ETH_PLUGIN_QUERY_CONTRACT_UI:
            if (((ethQueryContractUI_t *) parameter)->result != ETH_PLUGIN_RESULT_OK) {
                return ETH_PLUGIN_RESULT_ERROR;
            }
            break;
        default:
            return ETH_PLUGIN_RESULT_UNAVAILABLE;
    }

    return ETH_PLUGIN_RESULT_OK;
}
