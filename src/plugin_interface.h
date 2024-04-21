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

// Codes for the different requests Tron can send to the plugin
// The dispatch is handled by the SDK itself, the plugin code does not have to handle it
typedef enum tron_plugin_msg_e {
    // Codes for actions the Tron app can ask the plugin to perform
    TRON_PLUGIN_INIT_CONTRACT = 0x0101,
    TRON_PLUGIN_PROVIDE_PARAMETER = 0x0102,
    TRON_PLUGIN_FINALIZE = 0x0103,
    TRON_PLUGIN_PROVIDE_INFO = 0x0104,
    TRON_PLUGIN_QUERY_CONTRACT_ID = 0x0105,
    TRON_PLUGIN_QUERY_CONTRACT_UI = 0x0106,

    // Special request: the Tron app is checking if we are installed on the device
    TRON_PLUGIN_CHECK_PRESENCE = 0x01FF,
} tron_plugin_msg_t;

typedef enum {
    PLUGIN_UI_INSIDE = 0,
    PLUGIN_UI_OUTSIDE
} plugin_ui_state_t;