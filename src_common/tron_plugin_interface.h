// clang-format off

#pragma once

#include "os.h"
#include "cx.h"

// Include other header compatible with plugins
#include "asset_info.h"
#include "common_utils.h"
#include "plugin_utils.h"
#include "tx_content.h"

// Interface version. Will be updated every time a breaking change in the interface is introduced.
typedef enum tron_plugin_interface_version_e {
    TRON_PLUGIN_INTERFACE_VERSION_1 = 1,
    TRON_PLUGIN_INTERFACE_VERSION_LATEST = 2,
} tron_plugin_interface_version_t;


// Codes for the different requests TRON can send to the plugin
// The dispatch is handled by the SDK itself, the plugin code does not have to handle it
typedef enum tron_plugin_msg_e {
    // Codes for actions the TRON app can ask the plugin to perform
    TRON_PLUGIN_INIT_CONTRACT = 0x0101,
    TRON_PLUGIN_PROVIDE_PARAMETER = 0x0102,
    TRON_PLUGIN_FINALIZE = 0x0103,
    TRON_PLUGIN_PROVIDE_INFO = 0x0104,
    TRON_PLUGIN_QUERY_CONTRACT_ID = 0x0105,
    TRON_PLUGIN_QUERY_CONTRACT_UI = 0x0106,

    // Special request: the TRON app is checking if we are installed on the device
    TRON_PLUGIN_CHECK_PRESENCE = 0x01FF,
} tron_plugin_msg_t;


// Reply codes when responding to the TRON application
typedef enum tron_plugin_result_e {
    // Unsuccessful return values
    TRON_PLUGIN_RESULT_ERROR = 0x00,
    TRON_PLUGIN_RESULT_UNAVAILABLE = 0x01,
    TRON_PLUGIN_RESULT_UNSUCCESSFUL = 0x02,  // Used for comparison

    // Successful return values
    TRON_PLUGIN_RESULT_SUCCESSFUL = 0x03,  // Used for comparison
    TRON_PLUGIN_RESULT_OK = 0x04,
    TRON_PLUGIN_RESULT_OK_ALIAS = 0x05,
    TRON_PLUGIN_RESULT_FALLBACK = 0x06,
} tron_plugin_result_t;


// Format of UI the TRON application has to use for this plugin
typedef enum tron_ui_type_e {
    // If uiType is UI_AMOUNT_ADDRESS, TRON will use the amount/address UI
    // the amount and address provided by the plugin will be used
    // If tokenLookup1 is set, the amount is provided for this token
    TRON_UI_TYPE_AMOUNT_ADDRESS = 0x01,

    // If uiType is UI_TYPE_GENERIC, TRON will use the dedicated ETH plugin UI
    // the ETH application provides tokens if requested then prompts for each UI field
    // The first field is forced by the ETH app to be the name + version of the plugin handling the
    // request. The last field is the fee amount
    TRON_UI_TYPE_GENERIC = 0x02,
} tron_ui_type_t;


// Scratch objects and utilities available to the plugin READ-WRITE
typedef struct tronPluginSharedRW_s {
    cx_sha3_t *sha3;
} tronPluginSharedRW_t;


// Transaction data available to the plugin READ-ONLY
typedef struct tronPluginSharedRO_s {
    txContent_t *txContent;
} tronPluginSharedRO_t;


// Plugin-only memory allocated by the TRON application and used by the plugin.
#define PLUGIN_CONTEXT_SIZE (5 * INT256_LENGTH)
// It is recommended to cast the raw uin8_t array to a structure meaningful for your plugin
// Helper to check that the actual plugin context structure is not bigger than the allocated memory
#define ASSERT_SIZEOF_PLUGIN_CONTEXT(s) \
    _Static_assert(sizeof(s) <= PLUGIN_CONTEXT_SIZE, "Plugin context structure is too big.")


/*
 * HANDLERS AND PARAMETERS
 * Parameters associated with the requests the TRON application can ask the plugin to perform
 * The plugin SDK will automatically call the relevant handler for the received code, so the plugin
 * has to define each of the handler functions declared below.
 */


// Init Contract

typedef struct tronPluginInitContract_s {
    tron_plugin_interface_version_t interfaceVersion;
    tron_plugin_result_t result;

    // in
    tronPluginSharedRW_t *pluginSharedRW;
    tronPluginSharedRO_t *pluginSharedRO;
    uint8_t *pluginContext;
    size_t pluginContextLength;
    const uint8_t *selector;  // 4 bytes selector
    size_t dataSize;

    char *alias;  // 29 bytes alias if TRON_PLUGIN_RESULT_OK_ALIAS set

} tronPluginInitContract_t;
// void handle_init_contract(tronPluginInitContract_t *parameters);


// Provide parameter

typedef struct tronPluginProvideParameter_s {
    tronPluginSharedRW_t *pluginSharedRW;
    tronPluginSharedRO_t *pluginSharedRO;
    uint8_t *pluginContext; // PLUGIN_CONTEXT_SIZE
    const uint8_t *parameter;  // 32 bytes parameter
    uint32_t parameterOffset;

    tron_plugin_result_t result;

} tronPluginProvideParameter_t;
// void handle_provide_parameter(tronPluginProvideParameter_t *parameters);


// Finalize

typedef struct tronPluginFinalize_s {
    tronPluginSharedRW_t *pluginSharedRW;
    tronPluginSharedRO_t *pluginSharedRO;
    uint8_t *pluginContext; // PLUGIN_CONTEXT_SIZE

    uint8_t *tokenLookup1;  // set by the plugin if a token should be looked up
    uint8_t *tokenLookup2;

    const uint8_t *amount;   // set an uint256 pointer if uiType is UI_AMOUNT_ADDRESS
    const uint8_t *address;  // set to the destination address if uiType is UI_AMOUNT_ADDRESS. Set
                             // to the user's address if uiType is UI_TYPE_GENERIC

    tron_ui_type_t uiType;
    uint8_t numScreens;  // ignored if uiType is UI_AMOUNT_ADDRESS
    tron_plugin_result_t result;

} tronPluginFinalize_t;
// void handle_finalize(tronPluginFinalize_t *parameters);


// Provide token

typedef struct tronPluginProvideInfo_s {
    tronPluginSharedRW_t *pluginSharedRW;
    tronPluginSharedRO_t *pluginSharedRO;
    uint8_t *pluginContext; // PLUGIN_CONTEXT_SIZE

    union extraInfo_t *item1;  // set by the ETH application, to be saved by the plugin
    union extraInfo_t *item2;

    uint8_t additionalScreens;  // Used by the plugin if it needs to display additional screens
                                // based on the information received from the token definitions.

    tron_plugin_result_t result;

} tronPluginProvideInfo_t;
// void handle_provide_token(tronPluginProvideInfo_t *parameters);


// Query Contract name and version

// This is always called on the non aliased contract

typedef struct tronQueryContractID_s {
    tronPluginSharedRW_t *pluginSharedRW;
    tronPluginSharedRO_t *pluginSharedRO;
    uint8_t *pluginContext; // PLUGIN_CONTEXT_SIZE

    char *name;
    size_t nameLength;
    char *version;
    size_t versionLength;

    tron_plugin_result_t result;

} tronQueryContractID_t;
// void handle_query_contract_id(tronQueryContractID_t *parameters);


// Query Contract UI

typedef struct tronQueryContractUI_s {
    tronPluginSharedRW_t *pluginSharedRW;
    tronPluginSharedRO_t *pluginSharedRO;
    union extraInfo_t *item1;
    union extraInfo_t *item2;
    char network_ticker[MAX_TICKER_LEN];
    uint8_t *pluginContext; // PLUGIN_CONTEXT_SIZE
    uint8_t screenIndex;

    char *title;
    size_t titleLength;
    char *msg;
    size_t msgLength;

    tron_plugin_result_t result;

} tronQueryContractUI_t;
// void handle_query_contract_ui(tronQueryContractUI_t *parameters);

// clang-format on
