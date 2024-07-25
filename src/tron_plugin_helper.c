#include <string.h>
#include "tron_plugin_helper.h"
#include "tron_plugin_interface.h"
#include "plugin_utils.h"

extraInfo_t *getKnownExtraToken(uint8_t *contractAddress, transactionContext_t *tContext) {
    union extraInfo_t *currentItem = NULL;
    // Works for ERC-20 & NFT tokens since both structs in the union have the
    // contract address aligned
    for (uint8_t i = 0; i < MAX_ITEMS; i++) {
        currentItem = (union extraInfo_t *) &tContext->extraInfo[i].token;
        if ((memcmp(currentItem->token.address, contractAddress, ADDRESS_SIZE) == 0)) {
            PRINTF("Token found at index %d\n", i);
            return currentItem;
        }
    }

    return NULL;
}

void tron_plugin_prepare_init(tronPluginInitContract_t *init,
                              const uint8_t *selector,
                              uint32_t dataSize) {
    memset((uint8_t *) init, 0, sizeof(tronPluginInitContract_t));
    init->selector = selector;
    init->dataSize = dataSize;
}

void tron_plugin_prepare_provide_parameter(tronPluginProvideParameter_t *provideParameter,
                                           uint8_t *parameter,
                                           uint32_t parameterOffset) {
    memset((uint8_t *) provideParameter, 0, sizeof(tronPluginProvideParameter_t));
    provideParameter->parameter = parameter;
    provideParameter->parameterOffset = parameterOffset;
}

void tron_plugin_prepare_finalize(tronPluginFinalize_t *finalize) {
    memset((uint8_t *) finalize, 0, sizeof(tronPluginFinalize_t));
}

void tron_plugin_prepare_provide_info(tronPluginProvideInfo_t *provideToken) {
    memset((uint8_t *) provideToken, 0, sizeof(tronPluginProvideInfo_t));
}

void tron_plugin_prepare_query_contract_ID(tronQueryContractID_t *queryContractID,
                                           char *name,
                                           uint32_t nameLength,
                                           char *version,
                                           uint32_t versionLength) {
    memset((uint8_t *) queryContractID, 0, sizeof(tronQueryContractID_t));
    queryContractID->name = name;
    queryContractID->nameLength = nameLength;
    queryContractID->version = version;
    queryContractID->versionLength = versionLength;
}

static void tron_plugin_perform_init_default(uint8_t *contractAddress,
                                             tronPluginInitContract_t *init) {
    // check if the registered external plugin matches the TX contract address / selector
    if (memcmp(contractAddress,
               dataContext.tokenContext.contractAddress,
               sizeof(dataContext.tokenContext.contractAddress)) != 0) {
        PRINTF("Got contract: %.*H\n", ADDRESS_SIZE, contractAddress);
        PRINTF("Expected contract: %.*H\n", ADDRESS_SIZE, dataContext.tokenContext.contractAddress);
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
    dataContext.tokenContext.pluginStatus = TRON_PLUGIN_RESULT_OK;
}

tron_plugin_result_t tron_plugin_perform_init(uint8_t *contractAddress,
                                              tronPluginInitContract_t *init) {
    dataContext.tokenContext.pluginStatus = TRON_PLUGIN_RESULT_UNAVAILABLE;

    PRINTF("Selector %.*H\n", 4, init->selector);
    tron_plugin_perform_init_default(contractAddress, init);
    contractAddress = NULL;

    tron_plugin_result_t status = TRON_PLUGIN_RESULT_UNAVAILABLE;

    PRINTF("tron_plugin_init\n");
    PRINTF("Trying plugin %s\n", dataContext.tokenContext.pluginName);
    status = tron_plugin_call(TRON_PLUGIN_INIT_CONTRACT, (void *) init);

    if (status <= TRON_PLUGIN_RESULT_UNSUCCESSFUL) {
        return status;
    }
    PRINTF("tron_plugin_init ok %s\n", dataContext.tokenContext.pluginName);
    dataContext.tokenContext.pluginStatus = TRON_PLUGIN_RESULT_OK;
    return TRON_PLUGIN_RESULT_OK;
}

tron_plugin_result_t tron_plugin_call(int method, void *parameter) {
    tronPluginSharedRW_t pluginRW;
    tronPluginSharedRO_t pluginRO;
    char *alias;
    // uint8_t i;

    // pluginRW.sha3 = &global_sha3;
    pluginRO.txContent = &txContent;

    if (dataContext.tokenContext.pluginStatus <= TRON_PLUGIN_RESULT_UNSUCCESSFUL) {
        PRINTF("Cached plugin call but no plugin available\n");
        return dataContext.tokenContext.pluginStatus;
    }
    alias = dataContext.tokenContext.pluginName;

    // Prepare the call

    switch (method) {
        case TRON_PLUGIN_INIT_CONTRACT:
            PRINTF("-- PLUGIN INIT CONTRACT --\n");
            ((tronPluginInitContract_t *) parameter)->interfaceVersion =
                TRON_PLUGIN_INTERFACE_VERSION_LATEST;
            ((tronPluginInitContract_t *) parameter)->result = TRON_PLUGIN_RESULT_UNAVAILABLE;
            ((tronPluginInitContract_t *) parameter)->pluginSharedRW = &pluginRW;
            ((tronPluginInitContract_t *) parameter)->pluginSharedRO = &pluginRO;
            ((tronPluginInitContract_t *) parameter)->pluginContext =
                (uint8_t *) &dataContext.tokenContext.pluginContext;
            ((tronPluginInitContract_t *) parameter)->pluginContextLength =
                sizeof(dataContext.tokenContext.pluginContext);
            ((tronPluginInitContract_t *) parameter)->alias = dataContext.tokenContext.pluginName;
            break;
        case TRON_PLUGIN_PROVIDE_PARAMETER:
            PRINTF("-- PLUGIN PROVIDE PARAMETER --\n");
            ((tronPluginProvideParameter_t *) parameter)->result = TRON_PLUGIN_RESULT_UNAVAILABLE;
            ((tronPluginProvideParameter_t *) parameter)->pluginSharedRW = &pluginRW;
            ((tronPluginProvideParameter_t *) parameter)->pluginSharedRO = &pluginRO;
            ((tronPluginProvideParameter_t *) parameter)->pluginContext =
                (uint8_t *) &dataContext.tokenContext.pluginContext;
            break;
        case TRON_PLUGIN_FINALIZE:
            PRINTF("-- PLUGIN FINALIZE --\n");
            ((tronPluginFinalize_t *) parameter)->result = TRON_PLUGIN_RESULT_UNAVAILABLE;
            ((tronPluginFinalize_t *) parameter)->pluginSharedRW = &pluginRW;
            ((tronPluginFinalize_t *) parameter)->pluginSharedRO = &pluginRO;
            ((tronPluginFinalize_t *) parameter)->pluginContext =
                (uint8_t *) &dataContext.tokenContext.pluginContext;
            break;
        case TRON_PLUGIN_PROVIDE_INFO:
            PRINTF("-- PLUGIN PROVIDE INFO --\n");
            ((tronPluginProvideInfo_t *) parameter)->result = TRON_PLUGIN_RESULT_UNAVAILABLE;
            ((tronPluginProvideInfo_t *) parameter)->pluginSharedRW = &pluginRW;
            ((tronPluginProvideInfo_t *) parameter)->pluginSharedRO = &pluginRO;
            ((tronPluginProvideInfo_t *) parameter)->pluginContext =
                (uint8_t *) &dataContext.tokenContext.pluginContext;
            break;
        case TRON_PLUGIN_QUERY_CONTRACT_ID:
            PRINTF("-- PLUGIN QUERY CONTRACT ID --\n");
            ((tronQueryContractID_t *) parameter)->result = TRON_PLUGIN_RESULT_UNAVAILABLE;
            ((tronQueryContractID_t *) parameter)->pluginSharedRW = &pluginRW;
            ((tronQueryContractID_t *) parameter)->pluginSharedRO = &pluginRO;
            ((tronQueryContractID_t *) parameter)->pluginContext =
                (uint8_t *) &dataContext.tokenContext.pluginContext;
            break;
        case TRON_PLUGIN_QUERY_CONTRACT_UI:
            PRINTF("-- PLUGIN QUERY CONTRACT UI --\n");
            ((tronQueryContractUI_t *) parameter)->pluginSharedRW = &pluginRW;
            ((tronQueryContractUI_t *) parameter)->pluginSharedRO = &pluginRO;
            ((tronQueryContractUI_t *) parameter)->pluginContext =
                (uint8_t *) &dataContext.tokenContext.pluginContext;
            break;
        default:
            PRINTF("Unknown plugin method %d\n", method);
            return TRON_PLUGIN_RESULT_UNAVAILABLE;
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
        case TRON_PLUGIN_INIT_CONTRACT:
            switch (((tronPluginInitContract_t *) parameter)->result) {
                case TRON_PLUGIN_RESULT_OK:
                    break;
                case TRON_PLUGIN_RESULT_ERROR:
                    return TRON_PLUGIN_RESULT_ERROR;
                default:
                    return TRON_PLUGIN_RESULT_UNAVAILABLE;
            }
            break;
        case TRON_PLUGIN_PROVIDE_PARAMETER:
            switch (((tronPluginProvideParameter_t *) parameter)->result) {
                case TRON_PLUGIN_RESULT_OK:
                case TRON_PLUGIN_RESULT_FALLBACK:
                    break;
                case TRON_PLUGIN_RESULT_ERROR:
                    return TRON_PLUGIN_RESULT_ERROR;
                default:
                    return TRON_PLUGIN_RESULT_UNAVAILABLE;
            }
            break;
        case TRON_PLUGIN_FINALIZE:
            switch (((tronPluginFinalize_t *) parameter)->result) {
                case TRON_PLUGIN_RESULT_OK:
                case TRON_PLUGIN_RESULT_FALLBACK:
                    break;
                case TRON_PLUGIN_RESULT_ERROR:
                    return TRON_PLUGIN_RESULT_ERROR;
                default:
                    return TRON_PLUGIN_RESULT_UNAVAILABLE;
            }
            break;
        case TRON_PLUGIN_PROVIDE_INFO:
            PRINTF("RESULT: %d\n", ((tronPluginProvideInfo_t *) parameter)->result);
            switch (((tronPluginProvideInfo_t *) parameter)->result) {
                case TRON_PLUGIN_RESULT_OK:
                case TRON_PLUGIN_RESULT_FALLBACK:
                    break;
                case TRON_PLUGIN_RESULT_ERROR:
                    return TRON_PLUGIN_RESULT_ERROR;
                default:
                    return TRON_PLUGIN_RESULT_UNAVAILABLE;
            }
            break;
        case TRON_PLUGIN_QUERY_CONTRACT_ID:
            if (((tronQueryContractID_t *) parameter)->result != TRON_PLUGIN_RESULT_OK) {
                return TRON_PLUGIN_RESULT_ERROR;
            }
            break;
        case TRON_PLUGIN_QUERY_CONTRACT_UI:
            if (((tronQueryContractUI_t *) parameter)->result != TRON_PLUGIN_RESULT_OK) {
                return TRON_PLUGIN_RESULT_ERROR;
            }
            break;
        default:
            return TRON_PLUGIN_RESULT_UNAVAILABLE;
    }

    return TRON_PLUGIN_RESULT_OK;
}
