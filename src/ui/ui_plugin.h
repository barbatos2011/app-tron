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

#pragma once

#include "tron_plugin_interface.h"

#define NO_EXTRA_INFO(transactionContext, idx) \
    (allzeroes(&(transactionContext.extraInfo[idx]), sizeof(extraInfo_t)))

#define NO_NFT_METADATA (NO_EXTRA_INFO(transactionContext, 1))

void plugin_ui_get_item_internal(char *title_buffer,
                                 size_t title_buffer_size,
                                 char *msg_buffer,
                                 size_t msg_buffer_size);

void plugin_ui_get_id(void);
void plugin_ui_get_item(void);

void tron_plugin_prepare_query_contract_UI(tronQueryContractUI_t *queryContractUI,
                                           uint8_t screenIndex,
                                           char *title,
                                           uint32_t titleLength,
                                           char *msg,
                                           uint32_t msgLength);

#ifdef HAVE_BAGL
void display_next_plugin_item(bool entering);
#endif