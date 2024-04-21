#ifndef _ETH_PLUGIN_HANDLER_H_
#define _ETH_PLUGIN_HANDLER_H_

#include "tron_plugin_interface.h"
#include "parse.h"

#define NO_EXTRA_INFO(transactionContext, idx) \
    (allzeroes(&(transactionContext.extraInfo[idx]), sizeof(extraInfo_t)))

#define NO_NFT_METADATA (NO_EXTRA_INFO(transactionContext, 1))

void tron_plugin_prepare_init(ethPluginInitContract_t *init,
                             const uint8_t *selector,
                             uint32_t dataSize);
void tron_plugin_prepare_provide_parameter(ethPluginProvideParameter_t *provideParameter,
                                          uint8_t *parameter,
                                          uint32_t parameterOffset);
void tron_plugin_prepare_finalize(ethPluginFinalize_t *finalize);
void tron_plugin_prepare_provide_info(ethPluginProvideInfo_t *provideToken);
void tron_plugin_prepare_query_contract_ID(ethQueryContractID_t *queryContractID,
                                          char *name,
                                          uint32_t nameLength,
                                          char *version,
                                          uint32_t versionLength);
void tron_plugin_prepare_query_contract_UI(ethQueryContractUI_t *queryContractUI,
                                          uint8_t screenIndex,
                                          char *title,
                                          uint32_t titleLength,
                                          char *msg,
                                          uint32_t msgLength);

eth_plugin_result_t tron_plugin_perform_init(uint8_t *contractAddress,
                                            ethPluginInitContract_t *init);
// NULL for cached address, or base contract address
eth_plugin_result_t tron_plugin_call(int method, void *parameter);

extraInfo_t *getKnownExtraToken(uint8_t *contractAddress, transactionContext_t *transactionContext);

void plugin_ui_get_item(void);

#endif  // _ETH_PLUGIN_HANDLER_H_
