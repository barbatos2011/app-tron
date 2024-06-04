#include "os.h"
#include "cx.h"
#include <stdbool.h>
#include "core/Contract.pb.h"
#include "asset_info.h"
#include "tx_content.h"

#ifndef PARSE_H
#define PARSE_H

#define MAX_BIP32_PATH 10

#define ADD_PRE_FIX_STRING       "T"
#define ADDRESS_SIZE             21
#define TOKENID_SIZE             7
#define BASE58CHECK_ADDRESS_SIZE 34
#define PUBLIC_KEY_SIZE          65
#define CHAIN_CODE_SIZE          32
#define HASH_SIZE                32

#define TRC20_DATA_FIELD_SIZE 68

#define SUN_DIG                  6
#define ADD_PRE_FIX_BYTE_MAINNET 0x41
#define MAX_RAW_SIGNATURE        65
#define MAX_TOKEN_LENGTH         67

#define SELECTOR_SIZE    4
#define PLUGIN_ID_LENGTH 30

typedef union {
    protocol_TransferContract transfer_contract;
    protocol_TransferAssetContract transfer_asset_contract;
    protocol_TriggerSmartContract trigger_smart_contract;
    protocol_VoteWitnessContract vote_witness_contract;
    protocol_ProposalCreateContract proposal_create_contract;
    protocol_ExchangeCreateContract exchange_create_contract;
    protocol_ExchangeInjectContract exchange_inject_contract;
    protocol_ExchangeWithdrawContract exchange_withdraw_contract;
    protocol_ExchangeTransactionContract exchange_transaction_contract;
    protocol_AccountUpdateContract account_update_contract;
    protocol_ProposalApproveContract proposal_approve_contract;
    protocol_ProposalDeleteContract proposal_delete_contract;
    protocol_WithdrawBalanceContract withdraw_balance_contract;
    protocol_FreezeBalanceContract freeze_balance_contract;
    protocol_UnfreezeBalanceContract unfreeze_balance_contract;
    protocol_AccountPermissionUpdateContract account_permission_update_contract;
    protocol_FreezeBalanceV2Contract freeze_balance_v2_contract;
    protocol_UnfreezeBalanceV2Contract unfreeze_balance_v2_contract;
    protocol_WithdrawExpireUnfreezeContract withdraw_expire_unfreeze_contract;
    protocol_DelegateResourceContract delegate_resource_contract;
    protocol_UnDelegateResourceContract undelegate_resource_contract;
} contract_t;

extern contract_t msg;

typedef enum parserStatus_e {
    USTREAM_PROCESSING,
    USTREAM_FINISHED,
    USTREAM_FAULT,
    USTREAM_MISSING_SETTING_DATA_ALLOWED
} parserStatus_e;

// typedef enum contractType_e {
//     ACCOUNTCREATECONTRACT = 0,
//     TRANSFERCONTRACT,
//     TRANSFERASSETCONTRACT,
//     VOTEASSETCONTRACT,
//     VOTEWITNESSCONTRACT,
//     WITNESSCREATECONTRACT,
//     ASSETISSUECONTRACT,
//     WITNESSUPDATECONTRACT = 8,
//     PARTICIPATEASSETISSUECONTRACT,
//     ACCOUNTUPDATECONTRACT,
//     FREEZEBALANCECONTRACT,
//     UNFREEZEBALANCECONTRACT,
//     WITHDRAWBALANCECONTRACT,
//     UNFREEZEASSETCONTRACT,
//     UPDATEASSETCONTRACT,
//     PROPOSALCREATECONTRACT,
//     PROPOSALAPPROVECONTRACT,
//     PROPOSALDELETECONTRACT,
//     SETACCOUNTIDCONTRACT,
//     CUSTOMCONTRACT,
//     CREATESMARTCONTRACT = 30,
//     TRIGGERSMARTCONTRACT,
//     EXCHANGECREATECONTRACT = 41,
//     EXCHANGEINJECTCONTRACT,
//     EXCHANGEWITHDRAWCONTRACT,
//     EXCHANGETRANSACTIONCONTRACT,
//     UPDATEENERGYLIMITCONTRACT,
//     ACCOUNTPERMISSIONUPDATECONTRACT,
//     FREEZEBALANCEV2CONTRACT = 54,
//     UNFREEZEBALANCEV2CONTRACT,
//     WITHDRAWEXPIREUNFREEZECONTRACT,
//     DELEGATERESOURCECONTRACT,
//     UNDELEGATERESOURCECONTRACT,

//     UNKNOWN_CONTRACT = 254,
//     INVALID_CONTRACT = 255
// } contractType_e;

typedef struct stage_t {
    uint16_t total;
    uint16_t count;
} stage_t;

typedef struct txContext_t {
    cx_sha256_t sha2;
    bool initialized;
} txContext_t;

typedef struct publicKeyContext_t {
    uint8_t publicKey[PUBLIC_KEY_SIZE];
    char address58[BASE58CHECK_ADDRESS_SIZE + 1];
    uint8_t chainCode[CHAIN_CODE_SIZE];
    bool getChaincode;
} publicKeyContext_t;

typedef struct {
    uint32_t indices[MAX_BIP32_PATH];
    uint8_t length;
} bip32_path_t;

typedef struct transactionContext_t {
    bip32_path_t bip32_path;
    uint8_t hash[HASH_SIZE];
    uint8_t signature[MAX_RAW_SIGNATURE];
    uint8_t signatureLength;
    union extraInfo_t extraInfo[MAX_ITEMS];
    uint8_t tokenSet[MAX_ITEMS];
} transactionContext_t;

// typedef struct txContent_t {
//     uint64_t amount[2];
//     uint64_t exchangeID;
//     uint8_t account[ADDRESS_SIZE];
//     uint8_t destination[ADDRESS_SIZE];
//     uint8_t contractAddress[ADDRESS_SIZE];
//     uint8_t TRC20Amount[32];
//     uint8_t decimals[2];
//     char tokenNames[2][MAX_TOKEN_LENGTH];
//     uint8_t tokenNamesLength[2];
//     uint8_t resource;
//     uint8_t TRC20Method;
//     uint32_t customSelector;
//     contractType_e contractType;
//     uint64_t dataBytes;
//     uint8_t permission_id;
//     uint32_t customData;
// } txContent_t;

typedef struct tokenContext_t {
    char pluginName[PLUGIN_ID_LENGTH];

    uint8_t data[HASH_SIZE];
    uint16_t fieldIndex;
    uint8_t fieldOffset;

    uint8_t pluginUiMaxItems;
    uint8_t pluginUiCurrentItem;
    uint8_t pluginUiState;

    union {
        struct {
            uint8_t contractAddress[ADDRESS_SIZE];
            uint8_t methodSelector[SELECTOR_SIZE];
        };
        // This needs to be strictly 4 bytes aligned since pointers to it will be casted as
        // plugin context struct pointers (structs that contain up to 4 bytes wide elements)
        uint8_t pluginContext[5 * HASH_SIZE] __attribute__((aligned(4)));
    };

    uint8_t pluginStatus;

} tokenContext_t;

_Static_assert((offsetof(tokenContext_t, pluginContext) % 4) == 0, "Plugin context not aligned");

typedef union {
    tokenContext_t tokenContext;
} dataContext_t;

bool setContractType(contractType_e type, char *out, size_t outlen);
bool setExchangeContractDetail(contractType_e type, char *out, size_t outlen);

bool parseTokenName(uint8_t token_id, uint8_t *data, uint32_t dataLength, txContent_t *context);
bool parseExchange(const uint8_t *data, size_t dataLength, txContent_t *context);

unsigned short print_amount(uint64_t amount, char *out, uint32_t outlen, uint8_t sun);
bool adjustDecimals(const char *src,
                    uint32_t srcLength,
                    char *target,
                    uint32_t targetLength,
                    uint8_t decimals);

void initTx(txContext_t *context, txContent_t *content);

parserStatus_e processTx(uint8_t *buffer, uint32_t length, txContent_t *content);
parserStatus_e processTxForClearSign(uint8_t *buffer, uint32_t length, txContent_t *content);
uint32_t processTxForCSMultiParts(uint8_t *buffer, uint32_t length, txContent_t *content, uint8_t state);

extern txContent_t txContent;
extern txContext_t txContext;
extern dataContext_t dataContext;

#endif
