#include "ui_plugin.h"
#include "ui_globals.h"
#include "tron_plugin_helper.h"
#include "ux.h"

void plugin_ui_get_item_internal(char *title_buffer,
                                 size_t title_buffer_size,
                                 char *msg_buffer,
                                 size_t msg_buffer_size) {
    tronQueryContractUI_t pluginQueryContractUI;
    tron_plugin_prepare_query_contract_UI(&pluginQueryContractUI,
                                          dataContext.tokenContext.pluginUiCurrentItem,
                                          title_buffer,
                                          title_buffer_size,
                                          msg_buffer,
                                          msg_buffer_size);
    if (!tron_plugin_call(TRON_PLUGIN_QUERY_CONTRACT_UI, (void *) &pluginQueryContractUI)) {
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

void tron_plugin_prepare_query_contract_UI(tronQueryContractUI_t *queryContractUI,
                                           uint8_t screenIndex,
                                           char *title,
                                           uint32_t titleLength,
                                           char *msgTmp,
                                           uint32_t msgLength) {
    memset((uint8_t *) queryContractUI, 0, sizeof(tronQueryContractUI_t));

    // If no extra information was found, set the pointer to NULL
    if (NO_EXTRA_INFO(global_ctx.transactionContext, 1)) {
        queryContractUI->item1 = NULL;
    } else {
        queryContractUI->item1 = &global_ctx.transactionContext.extraInfo[1];
    }

    // If no extra information was found, set the pointer to NULL
    if (NO_EXTRA_INFO(global_ctx.transactionContext, 0)) {
        queryContractUI->item2 = NULL;
    } else {
        queryContractUI->item2 = &global_ctx.transactionContext.extraInfo[0];
    }

    queryContractUI->screenIndex = screenIndex;
    strlcpy(queryContractUI->network_ticker, "TRX", sizeof(queryContractUI->network_ticker));
    queryContractUI->title = title;
    queryContractUI->titleLength = titleLength;
    queryContractUI->msg = msgTmp;
    queryContractUI->msgLength = msgLength;
}

void plugin_ui_get_id(void) {
    tronQueryContractID_t pluginQueryContractID;
    tron_plugin_prepare_query_contract_ID(&pluginQueryContractID,
                                          addressSummary,
                                          sizeof(addressSummary),
                                          fullContract,
                                          sizeof(fullContract));
    // Query the original contract for ID if it's not an internal alias
    if (!tron_plugin_call(TRON_PLUGIN_QUERY_CONTRACT_ID, (void *) &pluginQueryContractID)) {
        PRINTF("Plugin query contract ID call failed\n");
        ui_callback_tx_cancel(true);
    }
}

#ifdef HAVE_BAGL
// This function is not exported by the SDK
void ux_layout_paging_redisplay_by_addr(unsigned int stack_slot);

void display_next_plugin_item(bool entering) {
    if (entering) {
        if (dataContext.tokenContext.pluginUiState == PLUGIN_UI_OUTSIDE) {
            dataContext.tokenContext.pluginUiState = PLUGIN_UI_INSIDE;
            dataContext.tokenContext.pluginUiCurrentItem = 0;
            plugin_ui_get_item();
            ux_flow_next();
        } else {
            if (dataContext.tokenContext.pluginUiCurrentItem > 0) {
                dataContext.tokenContext.pluginUiCurrentItem--;
                plugin_ui_get_item();
                ux_flow_next();
            } else {
                dataContext.tokenContext.pluginUiState = PLUGIN_UI_OUTSIDE;
                dataContext.tokenContext.pluginUiCurrentItem = 0;
                ux_flow_prev();
            }
        }
    } else {
        if (dataContext.tokenContext.pluginUiState == PLUGIN_UI_OUTSIDE) {
            dataContext.tokenContext.pluginUiState = PLUGIN_UI_INSIDE;
            plugin_ui_get_item();
            ux_flow_prev();
        } else {
            if (dataContext.tokenContext.pluginUiCurrentItem <
                dataContext.tokenContext.pluginUiMaxItems - 1) {
                dataContext.tokenContext.pluginUiCurrentItem++;
                plugin_ui_get_item();
                ux_flow_prev();
                // Reset multi page layout to the first page
                G_ux.layout_paging.current = 0;
                ux_layout_paging_redisplay_by_addr(G_ux.stack_count - 1);
            } else {
                dataContext.tokenContext.pluginUiState = PLUGIN_UI_OUTSIDE;
                ux_flow_next();
            }
        }
    }
}
#endif