#include "os.h"
#include "cx.h"
#include "bip32.h"
// #include "bip32_utils.h"
#include <stdbool.h>
#include "core/Contract.pb.h"
#include "common_utils.h"

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

#define NETWORK_STRING_MAX_SIZE 16
#ifdef TARGET_NANOS
#define SHARED_CTX_FIELD_1_SIZE 100
#else
#define SHARED_CTX_FIELD_1_SIZE 256
#endif
#define SHARED_CTX_FIELD_2_SIZE 40

#define SHARED_BUFFER_SIZE SHARED_CTX_FIELD_1_SIZE

#define MAX_ASSETS 5

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

typedef enum contractType_e {
    ACCOUNTCREATECONTRACT = 0,
    TRANSFERCONTRACT,
    TRANSFERASSETCONTRACT,
    VOTEASSETCONTRACT,
    VOTEWITNESSCONTRACT,
    WITNESSCREATECONTRACT,
    ASSETISSUECONTRACT,
    WITNESSUPDATECONTRACT = 8,
    PARTICIPATEASSETISSUECONTRACT,
    ACCOUNTUPDATECONTRACT,
    FREEZEBALANCECONTRACT,
    UNFREEZEBALANCECONTRACT,
    WITHDRAWBALANCECONTRACT,
    UNFREEZEASSETCONTRACT,
    UPDATEASSETCONTRACT,
    PROPOSALCREATECONTRACT,
    PROPOSALAPPROVECONTRACT,
    PROPOSALDELETECONTRACT,
    SETACCOUNTIDCONTRACT,
    CUSTOMCONTRACT,
    CREATESMARTCONTRACT = 30,
    TRIGGERSMARTCONTRACT,
    EXCHANGECREATECONTRACT = 41,
    EXCHANGEINJECTCONTRACT,
    EXCHANGEWITHDRAWCONTRACT,
    EXCHANGETRANSACTIONCONTRACT,
    UPDATEENERGYLIMITCONTRACT,
    ACCOUNTPERMISSIONUPDATECONTRACT,
    FREEZEBALANCEV2CONTRACT = 54,
    UNFREEZEBALANCEV2CONTRACT,
    WITHDRAWEXPIREUNFREEZECONTRACT,
    DELEGATERESOURCECONTRACT,
    UNDELEGATERESOURCECONTRACT,

    UNKNOWN_CONTRACT = 254,
    INVALID_CONTRACT = 255
} contractType_e;

enum { OFFSET_CLA = 0, OFFSET_INS, OFFSET_P1, OFFSET_P2, OFFSET_LC, OFFSET_CDATA };
typedef enum {
    APP_STATE_IDLE,
    APP_STATE_SIGNING_MESSAGE,
    APP_STATE_SIGNING_MESSAGE_FULL_DISPLAY,
    APP_STATE_SIGNING
} app_state_t;

typedef enum { STATE_191_HASH_DISPLAY = 0, STATE_191_HASH_ONLY } sign_message_state;
typedef struct states191_t {
    sign_message_state sign_state : 1;
    bool ui_started : 1;
} states191_t;

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

#define COLLECTION_NAME_MAX_LEN 70

typedef struct nftInfo_t {
    uint8_t contractAddress[ADDRESS_SIZE_712];  // must be first item
    char collectionName[COLLECTION_NAME_MAX_LEN + 1];
} nftInfo_t;

// TOKENS

#define MAX_TICKER_LEN 11  // 10 characters + '\0'

typedef struct tokenDefinition_t {
    uint8_t address[ADDRESS_SIZE];  // must be first item
    char ticker[MAX_TICKER_LEN];
    uint8_t decimals;
} tokenDefinition_t;

// UNION

typedef union extraInfo_t {
    tokenDefinition_t token;
// Would have used HAVE_NFT_SUPPORT but it is only declared for the Tron app
// and not plugins
#ifndef TARGET_NANOS
    nftInfo_t nft;
#endif
} extraInfo_t;

typedef struct transactionContext_t {
    bip32_path_t bip32_path;
    uint8_t hash[HASH_SIZE];
    uint8_t signature[MAX_RAW_SIGNATURE];
    uint8_t signatureLength;
#ifndef TARGET_NANOS
    union extraInfo_t extraInfo[MAX_ASSETS];
    bool assetSet[MAX_ASSETS];
    uint8_t currentAssetIndex;
#endif
} transactionContext_t;

typedef struct txContent_t {
    uint64_t amount[2];
    uint64_t exchangeID;
    uint8_t account[ADDRESS_SIZE];
    uint8_t destination[ADDRESS_SIZE];
    uint8_t contractAddress[ADDRESS_SIZE];
    uint8_t TRC20Amount[32];
    uint8_t decimals[2];
    char tokenNames[2][MAX_TOKEN_LENGTH];
    uint8_t tokenNamesLength[2];
    uint8_t resource;
    uint8_t TRC20Method;
    uint32_t customSelector;
    contractType_e contractType;
    uint64_t dataBytes;
    uint8_t permission_id;
    uint32_t customData;
} txContent_t;

typedef struct messageSigningContext712_t {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t domainHash[32];
    uint8_t messageHash[32];
} messageSigningContext712_t;

// typedef struct messageSigningContext_t {
//     bip32_path_t bip32;
//     uint8_t hash[HASH_SIZE];
//     uint32_t remainingLength;
// } messageSigningContext_t;

typedef union {
    transactionContext_t transactionContext;
    publicKeyContext_t publicKeyContext;
    messageSigningContext712_t messageSigningContext712;
    // messageSigningContext_t messageSigningContext;
} tmpCtx_t;

typedef struct txStringProperties_t {
    char fullAddress[43];
    char fullAmount[79];  // 2^256 is 78 digits long
    char maxFee[50];
    char nonce[8];  // 10M tx per account ought to be enough for everybody
    char network_name[NETWORK_STRING_MAX_SIZE];
} txStringProperties_t;

typedef struct strDataTmp_t {
    char tmp[SHARED_CTX_FIELD_1_SIZE];
    char tmp2[SHARED_CTX_FIELD_2_SIZE];
} strDataTmp_t;

typedef union {
    txStringProperties_t common;
    strDataTmp_t tmp;
} strings_t;

typedef struct chain_config_s {
    char coinName[10];  // ticker
    uint64_t chainId;
} chain_config_t;

extern const chain_config_t *chainConfig;

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

extern tmpCtx_t tmpCtx;
extern txContent_t txContent;
extern txContext_t txContext;
extern uint8_t appState;
extern states191_t states191;
extern uint8_t processed_size_191;
extern uint16_t apdu_response_code;

int bytes_to_string(char *out, size_t outl, const void *value, size_t len);

void hash_nbytes(const uint8_t *bytes_ptr, size_t n, cx_hash_t *hash_ctx);
void hash_byte(uint8_t byte, cx_hash_t *hash_ctx);

void forget_known_assets(void);
extraInfo_t *get_current_asset_info(void);
int get_asset_index_by_addr(const uint8_t *addr);
void validate_current_asset_info(void);
int array_bytes_string(char *out, size_t outl, const void *value, size_t len);
#endif
