#ifndef _TRON_PLUGIN_HANDLER_H_
#define _TRON_PLUGIN_HANDLER_H_

#include "tron_plugin_interface.h"
#include "parse.h"

typedef enum { PLUGIN_UI_INSIDE = 0, PLUGIN_UI_OUTSIDE } plugin_ui_state_t;

void tron_plugin_prepare_init(tronPluginInitContract_t *init,
                              const uint8_t *selector,
                              uint32_t dataSize);
void tron_plugin_prepare_provide_parameter(tronPluginProvideParameter_t *provideParameter,
                                           uint8_t *parameter,
                                           uint32_t parameterOffset);
void tron_plugin_prepare_finalize(tronPluginFinalize_t *finalize);
void tron_plugin_prepare_provide_info(tronPluginProvideInfo_t *provideToken);
void tron_plugin_prepare_query_contract_ID(tronQueryContractID_t *queryContractID,
                                           char *name,
                                           uint32_t nameLength,
                                           char *version,
                                           uint32_t versionLength);

tron_plugin_result_t tron_plugin_perform_init(uint8_t *contractAddress,
                                              tronPluginInitContract_t *init);
// NULL for cached address, or base contract address
tron_plugin_result_t tron_plugin_call(int method, void *parameter);

extraInfo_t *getKnownExtraToken(uint8_t *contractAddress, transactionContext_t *transactionContext);

#endif  // _TRON_PLUGIN_HANDLER_H_
