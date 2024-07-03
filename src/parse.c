/*******************************************************************************
 *   TRON Ledger
 *   (c) 2018 Ledger
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

#include <string.h>

#include "pb.h"
#include "misc/TronApp.pb.h"
#include "format.h"
#include "parse.h"
#include "settings.h"
#include "tokens.h"
#include "app_errors.h"
#include "tron_plugin_interface.h"
#include "tron_plugin_helper.h"

tokenDefinition_t *getKnownToken(txContent_t *context) {
    uint16_t i;

    tokenDefinition_t *currentToken = NULL;
    for (i = 0; i < NUM_TOKENS_TRC20; i++) {
        currentToken = (tokenDefinition_t *) PIC(&TOKENS_TRC20[i]);
        if (memcmp(currentToken->address, context->contractAddress, ADDRESS_SIZE) == 0) {
            PRINTF("Selected token %d\n", i);
            return currentToken;
        }
    }
    return NULL;
}

bool adjustDecimals(const char *src,
                    uint32_t srcLength,
                    char *target,
                    uint32_t targetLength,
                    uint8_t decimals) {
    uint32_t startOffset;
    uint32_t lastZeroOffset = 0;
    uint32_t offset = 0;

    if ((srcLength == 1) && (*src == '0')) {
        if (targetLength < 2) {
            return false;
        }
        target[offset++] = '0';
        target[offset++] = '\0';
        return true;
    }
    if (srcLength <= decimals) {
        uint32_t delta = decimals - srcLength;
        if (targetLength < srcLength + 1 + 2 + delta) {
            return false;
        }
        target[offset++] = '0';
        target[offset++] = '.';
        for (uint32_t i = 0; i < delta; i++) {
            target[offset++] = '0';
        }
        startOffset = offset;
        for (uint32_t i = 0; i < srcLength; i++) {
            target[offset++] = src[i];
        }
        target[offset] = '\0';
    } else {
        uint32_t sourceOffset = 0;
        uint32_t delta = srcLength - decimals;
        if (targetLength < srcLength + 1 + 1) {
            return false;
        }
        while (offset < delta) {
            target[offset++] = src[sourceOffset++];
        }
        if (decimals != 0) {
            target[offset++] = '.';
        }
        startOffset = offset;
        while (sourceOffset < srcLength) {
            target[offset++] = src[sourceOffset++];
        }
        target[offset] = '\0';
    }
    for (uint32_t i = startOffset; i < offset; i++) {
        if (target[i] == '0') {
            if (lastZeroOffset == 0) {
                lastZeroOffset = i;
            }
        } else {
            lastZeroOffset = 0;
        }
    }
    if (lastZeroOffset != 0) {
        target[lastZeroOffset] = '\0';
        if (target[lastZeroOffset - 1] == '.') {
            target[lastZeroOffset - 1] = '\0';
        }
    }
    return true;
}
unsigned short print_amount(uint64_t amount, char *out, uint32_t outlen, uint8_t sun) {
    char tmp[20];
    char tmp2[25];
    uint32_t numDigits = 0, i;
    uint64_t base = 1;
    while (base <= amount) {
        base *= 10;
        numDigits++;
    }
    if (numDigits > sizeof(tmp) - 1) {
        THROW(E_INCORRECT_LENGTH);
    }
    base /= 10;
    for (i = 0; i < numDigits; i++) {
        tmp[i] = '0' + ((amount / base) % 10);
        base /= 10;
    }
    tmp[i] = '\0';
    adjustDecimals(tmp, i, tmp2, 25, sun);
    if (strlen(tmp2) < outlen - 1) {
        strlcpy(out, tmp2, outlen);
    } else {
        out[0] = '\0';
    }
    return strlen(out);
}

bool setContractType(contractType_e type, char *out, size_t outlen) {
    switch (type) {
        case ACCOUNTCREATECONTRACT:
            strlcpy(out, "Account Create", outlen);
            break;
        case VOTEASSETCONTRACT:
            strlcpy(out, "Vote Asset", outlen);
            break;
        case WITNESSCREATECONTRACT:
            strlcpy(out, "Witness Create", outlen);
            break;
        case ASSETISSUECONTRACT:
            strlcpy(out, "Asset Issue", outlen);
            break;
        case WITNESSUPDATECONTRACT:
            strlcpy(out, "Witness Update", outlen);
            break;
        case PARTICIPATEASSETISSUECONTRACT:
            strlcpy(out, "Participate Asset", outlen);
            break;
        case ACCOUNTUPDATECONTRACT:
            strlcpy(out, "Account Update", outlen);
            break;
        case UNFREEZEBALANCECONTRACT:
            strlcpy(out, "Unfreeze Balance", outlen);
            break;
        case UNFREEZEBALANCEV2CONTRACT:
            strlcpy(out, "UnfreezeV2 Balance", outlen);
            break;
        case WITHDRAWBALANCECONTRACT:
            strlcpy(out, "Claim Rewards", outlen);
            break;
        case UNFREEZEASSETCONTRACT:
            strlcpy(out, "Unfreeze Asset", outlen);
            break;
        case WITHDRAWEXPIREUNFREEZECONTRACT:
            strlcpy(out, "Withdraw Unfreeze", outlen);
            break;
        case UPDATEASSETCONTRACT:
            strlcpy(out, "Update Asset", outlen);
            break;
        case PROPOSALCREATECONTRACT:
            strlcpy(out, "Proposal Create", outlen);
            break;
        case PROPOSALAPPROVECONTRACT:
            strlcpy(out, "Proposal Approve", outlen);
            break;
        case PROPOSALDELETECONTRACT:
            strlcpy(out, "Proposal Delete", outlen);
            break;
        case ACCOUNTPERMISSIONUPDATECONTRACT:
            strlcpy(out, "Permission Update", outlen);
            break;
        case UNKNOWN_CONTRACT:
            strlcpy(out, "Unknown Type", outlen);
            break;
        default:
            return false;
    }
    return true;
}

bool setExchangeContractDetail(contractType_e type, char *out, size_t outlen) {
    switch (type) {
        case EXCHANGECREATECONTRACT:
            strlcpy(out, "create", outlen);
            break;
        case EXCHANGEINJECTCONTRACT:
            strlcpy(out, "inject", outlen);
            break;
        case EXCHANGEWITHDRAWCONTRACT:
            strlcpy(out, "withdraw", outlen);
            break;
        case EXCHANGETRANSACTIONCONTRACT:
            strlcpy(out, "transaction", outlen);
            break;
        default:
            return false;
    }
    return true;
}

#include "../proto/core/Contract.pb.h"
#include "../proto/core/Tron.pb.h"
#include "../proto/misc/TronApp.pb.h"
#include "pb_decode.h"

// ALLOW SAME NAME TOKEN
// CHECK SIGNATURE(ID+NAME+PRECISION)
// Parse token Name and Signature
bool parseTokenName(uint8_t token_id, uint8_t *data, uint32_t dataLength, txContent_t *content) {
    TokenDetails details = {};

    pb_istream_t stream = pb_istream_from_buffer(data, dataLength);
    if (!pb_decode(&stream, TokenDetails_fields, &details)) {
        return false;
    }

    // Validate token ID + Name
    if (verifyTokenNameID((const char *) content->tokenNames[token_id],
                          details.name,
                          details.precision,
                          details.signature.bytes,
                          details.signature.size) != 1) {
        return false;
    }

    // UPDATE Token with Name[ID]
    char tmp[MAX_TOKEN_LENGTH];
    snprintf(tmp, MAX_TOKEN_LENGTH, "%s[%s]", details.name, content->tokenNames[token_id]);
    content->tokenNamesLength[token_id] = strlen((const char *) tmp);
    strlcpy(content->tokenNames[token_id], tmp, MAX_TOKEN_LENGTH);
    content->decimals[token_id] = details.precision;
    return true;
}

static bool printTokenFromID(char *out, size_t outlen, const uint8_t *data, size_t size) {
    if (size != TOKENID_SIZE && size != 1) {
        return false;
    }

    if (size == 1) {
        if (data[0] != '_') {
            return false;
        }
        strlcpy(out, "TRX", outlen);
        return true;
    }
    strlcpy(out, (char *) data, outlen);
    return true;
}

static bool set_token_info(txContent_t *content,
                           unsigned int token_index,
                           const char *name,
                           const char *id,
                           int precision) {
    if (token_index >= 2) {
        return false;
    }

    /* Ugly, but snprintf does not have a return value... */
    snprintf((char *) content->tokenNames[token_index], MAX_TOKEN_LENGTH, "%s[%s]", name, id);
    content->tokenNamesLength[token_index] = strlen((char *) content->tokenNames[token_index]);
    content->decimals[token_index] = precision;
    return true;
}

// Exchange Token ID + Name
// CHECK SIGNATURE(EXCHANGEID+TOKEN1ID+NAME1+PRECISION1+TOKEN2ID+NAME2+PRECISION2)
// Parse token Name and Signature
bool parseExchange(const uint8_t *data, size_t length, txContent_t *content) {
    ExchangeDetails details;
    char buffer[90];

    pb_istream_t stream = pb_istream_from_buffer(data, length);
    if (!pb_decode(&stream, ExchangeDetails_fields, &details)) {
        return false;
    }

    if (content->exchangeID != details.exchangeId) {
        return false;
    }

    /* Replace token ID with Name[ID] */
    if (strlen(details.token1Id) != 1 && strlen(details.token1Id) != 7) {
        return false;
    }
    if (strlen(details.token2Id) != 1 && strlen(details.token2Id) != 7) {
        return false;
    }

    /* Check provided signature. Strange serialization, it would have been
     * easier to sign the whole protobuf data...
     *
     * exchangeId is casted to int32_t as the custom snprintf implementation does
     * not seem to support %lld. Moreover, two calls to snprintf are made as
     * implementation does not return the number of written chars...
     */
    size_t msg_size;
    snprintf(buffer, sizeof(buffer), "%d", (int32_t) details.exchangeId);
    msg_size = strlen(buffer);

    snprintf(buffer,
             sizeof(buffer),
             "%d%s%s%c%s%s%c",
             (int32_t) details.exchangeId,
             details.token1Id,
             details.token1Name,
             details.token1Precision,
             details.token2Id,
             details.token2Name,
             details.token2Precision);
    msg_size += strlen(details.token1Id) + strlen(details.token1Name) + 1;
    msg_size += strlen(details.token2Id) + strlen(details.token2Name) + 1;

    if (!verifyExchangeID((uint8_t *) buffer,
                          msg_size,
                          details.signature.bytes,
                          details.signature.size)) {
        return false;
    }

    int first_token = 0, second_token = 0;
    if (strcmp((char *) content->tokenNames[0], details.token1Id) == 0) {
        first_token = 0;
        second_token = 1;
    } else if (strcmp((char *) content->tokenNames[0], details.token2Id) == 0) {
        first_token = 1;
        second_token = 0;
    } else {
        return false;
    }

    if (!set_token_info(content,
                        first_token,
                        details.token1Name,
                        details.token1Id,
                        details.token1Precision) ||
        !set_token_info(content,
                        second_token,
                        details.token2Name,
                        details.token2Id,
                        details.token2Precision)) {
        return false;
    }

    PRINTF("Lengths: %d,%d\n",
           content->tokenNamesLength[first_token],
           content->tokenNamesLength[second_token]);
    return true;
}

void initTx(txContext_t *context, txContent_t *content) {
    memset(context, 0, sizeof(txContext_t));
    memset(content, 0, sizeof(txContent_t));
    context->initialized = true;
    content->contractType = INVALID_CONTRACT;
    cx_sha256_init(&context->sha2);  // init sha
}

#define COPY_ADDRESS(a, b) memcpy((a), (b), ADDRESS_SIZE)

contract_t msg;

static bool transfer_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_TransferContract_fields, &msg.transfer_contract)) {
        return false;
    }

    content->amount[0] = msg.transfer_contract.amount;

    COPY_ADDRESS(content->account, &msg.transfer_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.transfer_contract.to_address);

    content->tokenNamesLength[0] = 4;
    strcpy(content->tokenNames[0], "TRX");
    return true;
}

static bool transfer_asset_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_TransferAssetContract_fields, &msg.transfer_asset_contract)) {
        return false;
    }
    content->amount[0] = msg.transfer_asset_contract.amount;

    if (!printTokenFromID(content->tokenNames[0],
                          MAX_TOKEN_LENGTH,
                          msg.transfer_asset_contract.asset_name.bytes,
                          msg.transfer_asset_contract.asset_name.size)) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    COPY_ADDRESS(content->account, &msg.transfer_asset_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.transfer_asset_contract.to_address);
    return true;
}

static bool vote_witness_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_VoteWitnessContract_fields, &msg.vote_witness_contract)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.vote_witness_contract.owner_address);
    return true;
}

static bool freeze_balance_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_FreezeBalanceContract_fields, &msg.freeze_balance_contract)) {
        return false;
    }
    /* Tron only accepts 3 days freezing */
    if (msg.freeze_balance_contract.frozen_duration != 3) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.freeze_balance_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.freeze_balance_contract.receiver_address);
    content->amount[0] = msg.freeze_balance_contract.frozen_balance;
    content->resource = msg.freeze_balance_contract.resource;
    return true;
}

static bool unfreeze_balance_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_UnfreezeBalanceContract_fields,
                   &msg.unfreeze_balance_contract)) {
        return false;
    }
    content->resource = msg.unfreeze_balance_contract.resource;

    COPY_ADDRESS(content->account, &msg.unfreeze_balance_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.unfreeze_balance_contract.receiver_address);
    return true;
}

static bool freeze_balance_v2_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_FreezeBalanceV2Contract_fields,
                   &msg.freeze_balance_v2_contract)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.freeze_balance_v2_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.freeze_balance_v2_contract.owner_address);
    content->amount[0] = msg.freeze_balance_v2_contract.frozen_balance;
    content->resource = msg.freeze_balance_v2_contract.resource;
    return true;
}

static bool unfreeze_balance_v2_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_UnfreezeBalanceV2Contract_fields,
                   &msg.unfreeze_balance_v2_contract)) {
        return false;
    }
    content->resource = msg.unfreeze_balance_v2_contract.resource;
    content->amount[0] = msg.unfreeze_balance_v2_contract.unfreeze_balance;

    COPY_ADDRESS(content->account, &msg.unfreeze_balance_v2_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.unfreeze_balance_v2_contract.owner_address);
    return true;
}

static bool withdraw_expire_unfreeze_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_WithdrawExpireUnfreezeContract_fields,
                   &msg.withdraw_expire_unfreeze_contract)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.withdraw_expire_unfreeze_contract.owner_address);
    return true;
}

static bool delegate_resource_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_DelegateResourceContract_fields,
                   &msg.delegate_resource_contract)) {
        return false;
    }
    content->resource = msg.delegate_resource_contract.resource;
    content->amount[0] = msg.delegate_resource_contract.balance;
    content->customData = msg.delegate_resource_contract.lock;

    COPY_ADDRESS(content->account, &msg.delegate_resource_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.delegate_resource_contract.receiver_address);
    return true;
}

static bool undelegate_resource_contrace(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_UnDelegateResourceContract_fields,
                   &msg.undelegate_resource_contract)) {
        return false;
    }
    content->resource = msg.undelegate_resource_contract.resource;
    content->amount[0] = msg.undelegate_resource_contract.balance;

    COPY_ADDRESS(content->account, &msg.undelegate_resource_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.undelegate_resource_contract.receiver_address);
    return true;
}

static bool withdraw_balance_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_WithdrawBalanceContract_fields,
                   &msg.withdraw_balance_contract)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.withdraw_balance_contract.owner_address);
    return true;
}

static bool proposal_create_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_ProposalCreateContract_fields, &msg.proposal_create_contract)) {
        return false;
    }

    content->amount[0] = msg.proposal_create_contract.parameters_count;
    COPY_ADDRESS(content->account, &msg.proposal_create_contract.owner_address);
    return true;
}

static bool proposal_approve_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_ProposalApproveContract_fields,
                   &msg.proposal_approve_contract)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.proposal_approve_contract.owner_address);
    return true;
}

static bool proposal_delete_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_ProposalDeleteContract_fields, &msg.proposal_delete_contract)) {
        return false;
    }

    content->exchangeID = msg.proposal_delete_contract.proposal_id;
    COPY_ADDRESS(content->account, &msg.proposal_delete_contract.owner_address);
    return true;
}

static bool account_update_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_AccountUpdateContract_fields, &msg.account_update_contract)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.account_update_contract.owner_address);
    return true;
}

bool pb_decode_trigger_smart_contract_data(pb_istream_t *stream,
                                           const pb_field_t *field,
                                           void **arg) {
    UNUSED(field);

    if (stream->bytes_left < 4) {
        return false;
    }

    txContent_t *content = *arg;
    uint8_t buf[32];  // a single encoded TVM value

    // method selector
    if (!pb_read(stream, buf, 4)) {
        return false;
    }

    content->customSelector = U4BE(buf, 0);

    if (memcmp(buf, SELECTOR[0], 4) == 0) {
        content->TRC20Method = 1;  // a9059cbb -> transfer(address,uint256)
    } else if (memcmp(buf, SELECTOR[1], 4) == 0) {
        content->TRC20Method = 2;  // 095ea7b3 -> approve(address,uint256)
    } else {
        // arbitrary contracts
        if (stream->bytes_left % 32 != 0) {
            return false;
        }
        content->TRC20Method = 0;
        // consume this field
        return pb_read(stream, NULL, stream->bytes_left);
    }

    // TRC20 data size check: 32 + 32
    if (stream->bytes_left != 32 + 32) {
        return false;
    }

    // to address
    if (!pb_read(stream, buf, 32)) {
        return false;
    }
    memcpy(content->destination, buf + (32 - 21), ADDRESS_SIZE);
    // fix address prefix 0x41: mainnet
    content->destination[0] = ADD_PRE_FIX_BYTE_MAINNET;

    // amount
    if (!pb_read(stream, buf, 32)) {
        return false;
    }
    memmove(content->TRC20Amount, buf, 32);

    return true;
}

static bool trigger_smart_contract(txContent_t *content, pb_istream_t *stream) {
    msg.trigger_smart_contract.data.funcs.decode = pb_decode_trigger_smart_contract_data;
    msg.trigger_smart_contract.data.arg = content;

    if (!pb_decode(stream, protocol_TriggerSmartContract_fields, &msg.trigger_smart_contract)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.trigger_smart_contract.owner_address);
    COPY_ADDRESS(content->contractAddress, &msg.trigger_smart_contract.contract_address);
    content->amount[0] = msg.trigger_smart_contract.call_value;

    tokenDefinition_t *trc20 = getKnownToken(content);

    if (trc20 == NULL) {
        // treat unknown TRC20 token as arbitrary contract
        content->TRC20Method = 0;
        return true;
    }

    content->decimals[0] = trc20->decimals;
    content->tokenNamesLength[0] = strlen(trc20->ticker) + 1;
    memmove(content->tokenNames[0], trc20->ticker, content->tokenNamesLength[0]);

    return true;
}

static bool exchange_create_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_ExchangeCreateContract_fields, &msg.exchange_create_contract)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.exchange_create_contract.owner_address);

    if (!printTokenFromID(content->tokenNames[0],
                          MAX_TOKEN_LENGTH,
                          msg.exchange_create_contract.first_token_id.bytes,
                          msg.exchange_create_contract.first_token_id.size)) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    if (!printTokenFromID(content->tokenNames[1],
                          MAX_TOKEN_LENGTH,
                          msg.exchange_create_contract.second_token_id.bytes,
                          msg.exchange_create_contract.second_token_id.size)) {
        return false;
    }
    content->tokenNamesLength[1] = strlen(content->tokenNames[1]);

    content->amount[0] = msg.exchange_create_contract.first_token_balance;
    content->amount[1] = msg.exchange_create_contract.second_token_balance;
    return true;
}

static bool exchange_inject_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_ExchangeInjectContract_fields, &msg.exchange_inject_contract)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.exchange_inject_contract.owner_address);
    content->exchangeID = msg.exchange_inject_contract.exchange_id;

    if (!printTokenFromID(content->tokenNames[0],
                          MAX_TOKEN_LENGTH,
                          msg.exchange_inject_contract.token_id.bytes,
                          msg.exchange_inject_contract.token_id.size)) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    content->amount[0] = msg.exchange_inject_contract.quant;
    return true;
}

static bool exchange_withdraw_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_ExchangeWithdrawContract_fields,
                   &msg.exchange_withdraw_contract)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.exchange_withdraw_contract.owner_address);
    content->exchangeID = msg.exchange_withdraw_contract.exchange_id;

    if (!printTokenFromID(content->tokenNames[0],
                          MAX_TOKEN_LENGTH,
                          msg.exchange_withdraw_contract.token_id.bytes,
                          msg.exchange_withdraw_contract.token_id.size)) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    content->amount[0] = msg.exchange_withdraw_contract.quant;
    return true;
}

static bool exchange_transaction_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_ExchangeTransactionContract_fields,
                   &msg.exchange_transaction_contract)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.exchange_transaction_contract.owner_address);
    content->exchangeID = msg.exchange_transaction_contract.exchange_id;

    if (!printTokenFromID(content->tokenNames[0],
                          MAX_TOKEN_LENGTH,
                          msg.exchange_transaction_contract.token_id.bytes,
                          msg.exchange_transaction_contract.token_id.size)) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    content->amount[0] = msg.exchange_transaction_contract.quant;
    content->amount[1] = msg.exchange_transaction_contract.expected;
    return true;
}

static bool account_permission_update_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_AccountPermissionUpdateContract_fields,
                   &msg.account_permission_update_contract)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.account_permission_update_contract.owner_address);
    // TODO: Update tx content
    return true;
}

typedef struct {
    const uint8_t *buf;
    size_t size;
} buffer_t;

bool pb_decode_contract_parameter(pb_istream_t *stream, const pb_field_t *field, void **arg) {
    PB_UNUSED(field);
    buffer_t *buffer = *arg;

    buffer->buf = stream->state;
    buffer->size = stream->bytes_left;
    return true;
}

bool pb_get_tx_data_size(pb_istream_t *stream, const pb_field_t *field, void **arg) {
    PB_UNUSED(field);
    uint64_t *data_size = *arg;
    *data_size = (uint64_t) stream->bytes_left;
    return true;
}

parserStatus_e processTx(uint8_t *buffer, uint32_t length, txContent_t *content) {
    protocol_Transaction_raw transaction;

    if (length == 0) {
        return USTREAM_FINISHED;
    }

    memset(&transaction, 0, sizeof(transaction));
    memset(&msg, 0, sizeof(msg));

    pb_istream_t stream = pb_istream_from_buffer(buffer, length);

    /* Set callbacks to retrieve "Contract" message bounds.
     * This is required because contract type is not necessarily parsed at the
     * time of the transaction is decoded (fields are not required to be ordered)
     * and deserializing the nested contract inside the message requires too much
     * stack for Nano S
     */
    buffer_t contract_buffer;
    transaction.contract->parameter.value.funcs.decode = pb_decode_contract_parameter;
    transaction.contract->parameter.value.arg = &contract_buffer;

    /* Set callback to determine if transaction contains custom data.
     * This allows to retrieve the size of arbitrary data. */
    transaction.custom_data.funcs.decode = pb_get_tx_data_size;
    transaction.custom_data.arg = &content->dataBytes;

    if (!pb_decode(&stream, protocol_Transaction_raw_fields, &transaction)) {
        return USTREAM_FAULT;
    }

    if (!HAS_SETTING(S_DATA_ALLOWED) && content->dataBytes != 0) {
        return USTREAM_MISSING_SETTING_DATA_ALLOWED;
    }

    /* Parse contract parameters if any...
       and it may come in different message chunk
       so test if chunk has the contract
     */
    if (transaction.contract->has_parameter) {
        content->permission_id = transaction.contract->Permission_id;
        content->contractType = (contractType_e) transaction.contract->type;

        pb_istream_t tx_stream = pb_istream_from_buffer(contract_buffer.buf, contract_buffer.size);
        bool ret;

        switch (transaction.contract->type) {
            case protocol_Transaction_Contract_ContractType_TransferContract:
                ret = transfer_contract(content, &tx_stream);
                break;

            case protocol_Transaction_Contract_ContractType_TransferAssetContract:
                ret = transfer_asset_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_VoteWitnessContract:
                ret = vote_witness_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_FreezeBalanceContract:
                ret = freeze_balance_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_UnfreezeBalanceContract:
                ret = unfreeze_balance_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_FreezeBalanceV2Contract:
                ret = freeze_balance_v2_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_UnfreezeBalanceV2Contract:
                ret = unfreeze_balance_v2_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_WithdrawExpireUnfreezeContract:
                ret = withdraw_expire_unfreeze_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_DelegateResourceContract:
                ret = delegate_resource_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_UnDelegateResourceContract:
                ret = undelegate_resource_contrace(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_WithdrawBalanceContract:
                ret = withdraw_balance_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_ProposalCreateContract:
                ret = proposal_create_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_ProposalApproveContract:
                ret = proposal_approve_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_ProposalDeleteContract:
                ret = proposal_delete_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_AccountUpdateContract:
                ret = account_update_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_TriggerSmartContract:
                ret = trigger_smart_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_ExchangeCreateContract:
                ret = exchange_create_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_ExchangeInjectContract:
                ret = exchange_inject_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_ExchangeWithdrawContract:
                ret = exchange_withdraw_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_ExchangeTransactionContract:
                ret = exchange_transaction_contract(content, &tx_stream);
                break;
            case protocol_Transaction_Contract_ContractType_AccountPermissionUpdateContract:
                ret = account_permission_update_contract(content, &tx_stream);
                break;
            default:
                return USTREAM_FAULT;
        }
        return ret ? USTREAM_PROCESSING : USTREAM_FAULT;
    }

    return USTREAM_PROCESSING;
}

bool process_trigger_smart_contract_data_v2(pb_istream_t *stream, txContent_t *content) {
    // If handling the beginning of the data field, assume that the function selector is
    // present
    if (stream->bytes_left < SELECTOR_SIZE) {
        PRINTF("Missing function selector\n");
        return false;
    }

    uint8_t buf[32];  // a single encoded TVM value
    // method selector
    if (!pb_read(stream, buf, 4)) {
        return false;
    }
    // content->customSelector = U4BE(buf, 0);
    // check is plugin call or not
    if (memcmp(content->contractAddress, dataContext.tokenContext.contractAddress, ADDRESS_SIZE) !=
            0 ||
        memcmp(buf, dataContext.tokenContext.methodSelector, SELECTOR_SIZE) != 0) {
        return false;
    }

    tronPluginInitContract_t pluginInit;
    dataContext.tokenContext.pluginStatus = TRON_PLUGIN_RESULT_UNAVAILABLE;
    // // If contract debugging mode is activated, do not go through the plugin activation
    // // as they wouldn't be displayed if the plugin consumes all data but fallbacks
    // if (!N_storage.contractDetails) {
    tron_plugin_prepare_init(&pluginInit, buf, SELECTOR_SIZE);
    dataContext.tokenContext.pluginStatus =
        tron_plugin_perform_init(content->contractAddress, &pluginInit);
    // }
    PRINTF("pluginstatus %d\n", dataContext.tokenContext.pluginStatus);
    if (dataContext.tokenContext.pluginStatus == TRON_PLUGIN_RESULT_ERROR) {
        PRINTF("Plugin error\n");
        return false;
    } else if (dataContext.tokenContext.pluginStatus >= TRON_PLUGIN_RESULT_SUCCESSFUL) {
        dataContext.tokenContext.fieldIndex = 0;
        dataContext.tokenContext.fieldOffset = 0;
    }

    uint32_t blockSize;
    uint32_t copySize;
    while (stream->bytes_left > 0) {
        blockSize = 32 - (dataContext.tokenContext.fieldOffset % 32);
        copySize = (stream->bytes_left < blockSize ? stream->bytes_left : blockSize);
        PRINTF("currentFieldPos %d copySize %d\n", context->currentFieldPos, copySize);

        if (!pb_read(stream,
                     dataContext.tokenContext.data + dataContext.tokenContext.fieldOffset,
                     copySize)) {
            return false;
        }

        dataContext.tokenContext.fieldOffset += copySize;
        if (copySize == blockSize) {
            // Can process or display
            if (dataContext.tokenContext.pluginStatus >= TRON_PLUGIN_RESULT_SUCCESSFUL) {
                tronPluginProvideParameter_t pluginProvideParameter;
                tron_plugin_prepare_provide_parameter(&pluginProvideParameter,
                                                      dataContext.tokenContext.data,
                                                      dataContext.tokenContext.fieldIndex * 32 + 4);
                if (!tron_plugin_call(TRON_PLUGIN_PROVIDE_PARAMETER,
                                      (void *) &pluginProvideParameter)) {
                    PRINTF("Plugin parameter call failed\n");
                    return false;
                }
                dataContext.tokenContext.fieldIndex++;
                dataContext.tokenContext.fieldOffset = 0;
                memset(dataContext.tokenContext.data, 0, sizeof(dataContext.tokenContext.data));
                continue;
            }

            dataContext.tokenContext.fieldIndex++;
            dataContext.tokenContext.fieldOffset = 0;
        } else {
            return false;
        }
    }

    return true;
}

static bool trigger_smart_contract_v2(txContent_t *content, pb_istream_t *stream) {
    buffer_t contract_buffer;
    msg.trigger_smart_contract.data.funcs.decode = pb_decode_contract_parameter;
    msg.trigger_smart_contract.data.arg = &contract_buffer;

    if (!pb_decode(stream, protocol_TriggerSmartContract_fields, &msg.trigger_smart_contract)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.trigger_smart_contract.owner_address);
    COPY_ADDRESS(content->contractAddress, &msg.trigger_smart_contract.contract_address);
    content->amount[0] = msg.trigger_smart_contract.call_value;

    pb_istream_t tx_stream = pb_istream_from_buffer(contract_buffer.buf, contract_buffer.size);

    return process_trigger_smart_contract_data_v2(&tx_stream, content);
}

uint8_t process_trigger_smart_contract_data_v2_for_multi(pb_istream_t *stream,
                                                         txContent_t *content,
                                                         bool init) {
    if (init) {
        // If handling the beginning of the data field, assume that the function selector is
        // present
        if (stream->bytes_left < SELECTOR_SIZE) {
            PRINTF("Missing function selector\n");
            return 1;
        }

        uint8_t buf[32];  // a single encoded TVM value
        // method selector
        if (!pb_read(stream, buf, 4)) {
            return 2;
        }
        // content->customSelector = U4BE(buf, 0);
        // check is plugin call or not
        if (memcmp(content->contractAddress,
                   dataContext.tokenContext.contractAddress,
                   ADDRESS_SIZE) != 0 ||
            memcmp(buf, dataContext.tokenContext.methodSelector, SELECTOR_SIZE) != 0) {
            return 3;
        }

        tronPluginInitContract_t pluginInit;
        dataContext.tokenContext.pluginStatus = TRON_PLUGIN_RESULT_UNAVAILABLE;
        // // If contract debugging mode is activated, do not go through the plugin activation
        // // as they wouldn't be displayed if the plugin consumes all data but fallbacks
        // if (!N_storage.contractDetails) {
        tron_plugin_prepare_init(&pluginInit, buf, SELECTOR_SIZE);
        dataContext.tokenContext.pluginStatus =
            tron_plugin_perform_init(content->contractAddress, &pluginInit);
        // }
        PRINTF("pluginstatus %d\n", dataContext.tokenContext.pluginStatus);
        if (dataContext.tokenContext.pluginStatus == TRON_PLUGIN_RESULT_ERROR) {
            PRINTF("Plugin error\n");
            return 4;
        } else if (dataContext.tokenContext.pluginStatus >= TRON_PLUGIN_RESULT_SUCCESSFUL) {
            dataContext.tokenContext.fieldIndex = 0;
            dataContext.tokenContext.fieldOffset = 0;
        }
    }

    uint32_t blockSize;
    uint32_t copySize;
    while (stream->bytes_left > 0) {
        blockSize = 32 - (dataContext.tokenContext.fieldOffset % 32);
        copySize = (stream->bytes_left < blockSize ? stream->bytes_left : blockSize);
        PRINTF("currentFieldPos %d copySize %d\n", context->currentFieldPos, copySize);

        if (!pb_read(stream,
                     dataContext.tokenContext.data + dataContext.tokenContext.fieldOffset,
                     copySize)) {
            return 5;
        }

        dataContext.tokenContext.fieldOffset += copySize;
        if (copySize == blockSize) {
            // Can process or display
            if (dataContext.tokenContext.pluginStatus >= TRON_PLUGIN_RESULT_SUCCESSFUL) {
                tronPluginProvideParameter_t pluginProvideParameter;
                tron_plugin_prepare_provide_parameter(&pluginProvideParameter,
                                                      dataContext.tokenContext.data,
                                                      dataContext.tokenContext.fieldIndex * 32 + 4);
                if (!tron_plugin_call(TRON_PLUGIN_PROVIDE_PARAMETER,
                                      (void *) &pluginProvideParameter)) {
                    PRINTF("Plugin parameter call failed\n");
                    return false;
                }
                dataContext.tokenContext.fieldIndex++;
                dataContext.tokenContext.fieldOffset = 0;
                memset(dataContext.tokenContext.data, 0, sizeof(dataContext.tokenContext.data));
                continue;
            }

            dataContext.tokenContext.fieldIndex++;
            dataContext.tokenContext.fieldOffset = 0;
        }
    }

    return 7;
}

void copyTriggerSmartContract(uint32_t tag_last, uint32_t tag_now, txContent_t *content) {
    switch (tag_now) {
        case protocol_TriggerSmartContract_owner_address_tag:
            break;
        case protocol_TriggerSmartContract_contract_address_tag:
            if (tag_last <= protocol_TriggerSmartContract_owner_address_tag) {
                COPY_ADDRESS(content->account, &msg.trigger_smart_contract.owner_address);
            }
            break;
        case protocol_TriggerSmartContract_call_value_tag:
            if (tag_last <= protocol_TriggerSmartContract_owner_address_tag) {
                COPY_ADDRESS(content->account, &msg.trigger_smart_contract.owner_address);
                COPY_ADDRESS(content->contractAddress,
                             &msg.trigger_smart_contract.contract_address);
            }
            if (tag_last <= protocol_TriggerSmartContract_contract_address_tag) {
                COPY_ADDRESS(content->contractAddress,
                             &msg.trigger_smart_contract.contract_address);
            }
            break;
        default:
            if (tag_now >= protocol_TriggerSmartContract_data_tag) {
                if (tag_last <= protocol_TriggerSmartContract_owner_address_tag) {
                    COPY_ADDRESS(content->account, &msg.trigger_smart_contract.owner_address);
                    COPY_ADDRESS(content->contractAddress,
                                 &msg.trigger_smart_contract.contract_address);
                    content->amount[0] = msg.trigger_smart_contract.call_value;
                }
                if (tag_last <= protocol_TriggerSmartContract_contract_address_tag) {
                    COPY_ADDRESS(content->contractAddress,
                                 &msg.trigger_smart_contract.contract_address);
                    content->amount[0] = msg.trigger_smart_contract.call_value;
                }
                if (tag_last <= protocol_TriggerSmartContract_call_value_tag) {
                    content->amount[0] = msg.trigger_smart_contract.call_value;
                }
            }
            break;
    }
}

void copyContract(uint32_t tag_last,
                  uint32_t tag_now,
                  txContent_t *content,
                  protocol_Transaction_Contract *contract) {
    switch (tag_now) {
        case protocol_Transaction_Contract_type_tag:
            break;
        case protocol_Transaction_Contract_parameter_tag:
            if (tag_last <= protocol_Transaction_Contract_type_tag) {
                content->contractType = (contractType_e) contract->type;
            }
            break;
        case protocol_Transaction_Contract_Permission_id_tag:
            if (tag_last <= protocol_Transaction_Contract_type_tag) {
                content->contractType = (contractType_e) contract->type;
            }
            break;
        default:
            if (tag_now > protocol_Transaction_Contract_Permission_id_tag) {
                if (tag_last <= protocol_Transaction_Contract_type_tag) {
                    content->contractType = (contractType_e) contract->type;
                }
                if (tag_last <= protocol_Transaction_Contract_Permission_id_tag) {
                    content->permission_id = contract->Permission_id;
                }
            }
            break;
    }
}

bool initTargetSize(txContent_t *content, uint8_t level, uint32_t tar_size) {
    switch (level) {
        case 0:  // init all to 0
            // bytes left for transaction_raw.contract
            content->customData = 0;
            // bytes left for transaction_raw.contract.parameter
            content->amount[1] = 0;
            // bytes left for transaction_raw.contract.parameter.value (in google.protobuf.Any)
            content->customSelector = 0;
            // bytes left for transaction_raw.contract.parameter.value.(TriggerSmartContract)data
            content->exchangeID = 0;
            // length for last package remained
            content->tokenNamesLength[0] = 0;
            content->tokenNamesLength[1] = 0;
            break;
        case 1:  // transaction_raw.contract level
            content->customData = tar_size;
            break;
        case 2:  // transaction_raw.contract.parameter level
            content->amount[1] = tar_size;
            break;
        case 3:  // transaction_raw.contract.parameter.value (in google.protobuf.Any) level
            content->customSelector = tar_size;
            break;
        case 4:  // transaction_raw.contract.parameter.value.(TriggerSmartContract)data level
            content->exchangeID = tar_size;
            break;
        case 10:
            content->tokenNamesLength[0] = tar_size;
            break;
        default:
            return false;
    }

    return true;
}

bool updateTargetSize(txContent_t *content, uint8_t level, uint8_t bytes_left) {
    switch (level) {
        case 1:  // transaction_raw.contract level
            content->customData -= content->tokenNamesLength[0] - bytes_left;
            content->tokenNamesLength[0] = bytes_left;
            break;
        case 2:  // transaction_raw.contract.parameter level
            content->customData -= content->tokenNamesLength[0] - bytes_left;
            content->amount[1] -= content->tokenNamesLength[0] - bytes_left;
            content->tokenNamesLength[0] = bytes_left;
            break;
        case 3:  // transaction_raw.contract.parameter.value (in google.protobuf.Any) level
            content->customData -= content->tokenNamesLength[0] - bytes_left;
            content->amount[1] -= content->tokenNamesLength[0] - bytes_left;
            content->customSelector -= content->tokenNamesLength[0] - bytes_left;
            content->tokenNamesLength[0] = bytes_left;
            break;
        case 4:  // transaction_raw.contract.parameter.value.(TriggerSmartContract)data level
            content->customData -= content->tokenNamesLength[0] - bytes_left;
            content->amount[1] -= content->tokenNamesLength[0] - bytes_left;
            content->customSelector -= content->tokenNamesLength[0] - bytes_left;
            content->exchangeID -= content->tokenNamesLength[0] - bytes_left;
            content->tokenNamesLength[0] = bytes_left;
            break;
        default:
            return false;
    }

    return true;
}

bool isContractDataDone(txContent_t *content) {
    return content->exchangeID == 0 ? true : false;
}

bool isCustomDataDone(txContent_t *content) {
    return content->customData == 0 ? true : false;
}

bool packageLeftForNext(uint8_t *buffer,
                        uint32_t length,
                        txContent_t *content,
                        uint8_t bytes_left) {
    // wait for next time to process
    content->tokenNamesLength[0] = bytes_left;
    memmove(content->tokenNames[0],
            buffer + (length - content->tokenNamesLength[0]),
            content->tokenNamesLength[0]);
    return true;
}

bool moveBuffer(uint8_t *buffer, uint32_t length, uint8_t steps) {
    if (length + steps > 255) {
        return false;
    }

    for (uint32_t i = length + steps - 1; i >= steps; i--) {
        *(buffer + i) = *(buffer + i - steps);
    }
    return true;
}

bool mergeLeftPackToBuffer(txContent_t *content, uint8_t *buffer, uint32_t *length) {
    if (content->tokenNamesLength[0] > 0) {
        if (*length + content->tokenNamesLength[0] > 255) {
            content->tokenNamesLength[1] = content->tokenNamesLength[0] - (255 - *length);
            memmove(content->tokenNames[1],
                    buffer + (*length - content->tokenNamesLength[1]),
                    content->tokenNamesLength[1]);
            *length -= content->tokenNamesLength[1];
        }
        if (!moveBuffer(buffer, *length, content->tokenNamesLength[0])) {
            return false;
        }
        memmove(buffer, content->tokenNames[0], content->tokenNamesLength[0]);
        *length += content->tokenNamesLength[0];
        if (*length > 255) {
            return false;
        }
        content->tokenNamesLength[0] = 0;
    }
    return true;
}

bool oneMoreTimeForLeftBytes(txContent_t *content, uint8_t *buffer, uint32_t *length) {
    *length = 0;

    if (content->tokenNamesLength[1] > 0) {
        if (content->tokenNamesLength[0] > 0) {
            *length = content->tokenNamesLength[0] + content->tokenNamesLength[1];
            if (*length > 255) {
                return false;
            }

            memmove(buffer, content->tokenNames[0], content->tokenNamesLength[0]);
            content->tokenNamesLength[0] = 0;
            memmove(buffer + content->tokenNamesLength[0],
                    content->tokenNames[1],
                    content->tokenNamesLength[1]);
            content->tokenNamesLength[1] = 0;
        } else {
            *length = content->tokenNamesLength[1];
            memmove(buffer, content->tokenNames[1], content->tokenNamesLength[1]);
            content->tokenNamesLength[1] = 0;
        }
    }
    return true;
}

uint32_t getLeftForLevel(txContent_t *content, uint8_t level, uint32_t length) {
    switch (level) {
        case 0:  // transaction_raw.custom_data level
            return length >= content->customData ? content->customData : length;
        case 1:  // transaction_raw.contract level
            return length >= content->customData ? content->customData : length;
        case 2:  // transaction_raw.contract.parameter level
            return length >= content->amount[1] ? content->amount[1] : length;
        case 3:  // transaction_raw.contract.parameter.value (in google.protobuf.Any) level
            return length >= content->customSelector ? content->customSelector : length;
        case 4:  // transaction_raw.contract.parameter.value.(TriggerSmartContract)data level
            return length >= (uint32_t) content->exchangeID ? (uint32_t) content->exchangeID
                                                            : length;
        default:
            return 0;
    }
    return 0;
}

bool updateTag(txContent_t *content, uint8_t level, uint8_t tag) {
    switch (level) {
        case 0:
            // tag for transaction_raw level
            content->TRC20Amount[0] = tag;
            // tag for transaction_raw/contract level
            content->TRC20Amount[1] = tag;
            // tag for transaction_raw/contract/parameter (google.protobuf.Any) level
            content->TRC20Amount[2] = tag;
            // tag for transaction_raw/contract/parameter.value.(TriggerSmartContract) level
            content->TRC20Amount[3] = tag;
            break;
        case 1:  // transaction_raw level
            content->TRC20Amount[0] = tag;
            break;
        case 2:  // transaction_raw.contract level
            content->TRC20Amount[1] = tag;
            break;
        case 3:  // transaction_raw.contract.parameter (google.protobuf.Any) level
            content->TRC20Amount[2] = tag;
            break;
        case 4:  // transaction_raw.contract.parameter.value.(TriggerSmartContract) level
            content->TRC20Amount[3] = tag;
            break;
        default:
            return false;
    }
    return true;
}

bool updateTagForFinished(txContent_t *content, uint8_t level) {
    switch (level) {
        case 0:  // transaction_raw.custom_data level
            content->TRC20Amount[0] = 0;
            break;
        case 1:  // transaction_raw level
            content->TRC20Amount[0] = protocol_Transaction_raw_fee_limit_tag + 1;
            break;
        case 2:  // transaction_raw.contract level
            content->TRC20Amount[0]++;
            content->TRC20Amount[1] = protocol_Transaction_Contract_Permission_id_tag + 1;
            break;
        case 3:  // transaction_raw.contract.parameter (google.protobuf.Any) level
            if (content->customData == 0) {
                content->TRC20Amount[1] = protocol_Transaction_Contract_Permission_id_tag + 1;
            } else {
                content->TRC20Amount[1]++;
            }
            content->TRC20Amount[2] = google_protobuf_Any_value_tag + 1;
            break;
        case 4:  // transaction_raw.contract.parameter.value.(TriggerSmartContract) level
            if (content->amount[1] == 0) {
                content->TRC20Amount[2] = google_protobuf_Any_value_tag + 1;
                // because any is done, means transaction_raw.contract.parameter is done
                content->TRC20Amount[1]++;
                if (content->customData == 0) {
                    content->TRC20Amount[1] = protocol_Transaction_Contract_Permission_id_tag + 1;
                }
            } else {
                content->TRC20Amount[2]++;
            }
            content->TRC20Amount[3] = protocol_TriggerSmartContract_token_id_tag + 1;
            break;
        case 5:
            if (content->customSelector == 0) {
                content->TRC20Amount[3] = protocol_TriggerSmartContract_token_id_tag + 1;
                if (content->amount[1] == 0) {
                    content->TRC20Amount[2] = google_protobuf_Any_value_tag + 1;
                    // because any is done, means transaction_raw.contract.parameter is done
                    content->TRC20Amount[1]++;
                    if (content->customData == 0) {
                        content->TRC20Amount[1] =
                            protocol_Transaction_Contract_Permission_id_tag + 1;
                    }
                }
            } else {
                content->TRC20Amount[3]++;
            }
            break;
        default:
            return false;
    }
    return true;
}

uint8_t getTag(txContent_t *content, uint8_t level) {
    switch (level) {
        case 1:  // transaction_raw level
            return content->TRC20Amount[0];
        case 2:  // transaction_raw.contract level
            return content->TRC20Amount[1];
        case 3:  // transaction_raw.contract.parameter (google.protobuf.Any) level
            return content->TRC20Amount[2];
        case 4:  // transaction_raw.contract.parameter.value.(TriggerSmartContract) level
            return content->TRC20Amount[3];
        default:
            return 0;
    }
    return 0;
}

uint8_t locatePackageLevel(txContent_t *content) {
    // all done
    if (content->TRC20Amount[0] == protocol_Transaction_raw_fee_limit_tag + 1) {
        return 10;
    }

    // transaction_raw level
    if (content->TRC20Amount[0] == protocol_Transaction_raw_custom_data_tag) {
        return 0;
    }
    if (content->TRC20Amount[0] == 0) {
        return 1;
    }
    if (content->TRC20Amount[0] != protocol_Transaction_raw_contract_tag) {
        return 1;
    }

    // transaction_raw.contract level
    if (content->TRC20Amount[1] == 0) {
        return 1;
    }
    if (content->TRC20Amount[1] == protocol_Transaction_Contract_Permission_id_tag + 1) {
        return 1;
    }
    if (content->TRC20Amount[1] != protocol_Transaction_Contract_parameter_tag) {
        return 2;
    }

    // transaction_raw.contract.parameter (google.protobuf.Any) level
    if (content->TRC20Amount[2] == 0) {
        return 2;
    }
    if (content->TRC20Amount[2] == google_protobuf_Any_value_tag + 1) {
        return 2;
    }
    if (content->TRC20Amount[2] != google_protobuf_Any_value_tag) {
        return 3;
    }

    if (content->TRC20Amount[3] == 0) {
        return 3;
    }
    if (content->TRC20Amount[3] == protocol_TriggerSmartContract_token_id_tag + 1) {
        return 3;
    }
    if (content->TRC20Amount[3] != protocol_TriggerSmartContract_data_tag) {
        return 4;
    }

    return 5;
}

uint32_t processTxForCSMulti(uint8_t *buffer, uint32_t length, txContent_t *content) {
    uint32_t tag_last = getTag(content, 1);
    protocol_Transaction_raw transaction;

    if (length == 0) {
        return USTREAM_FINISHED;
    }

    memset(&transaction, 0, sizeof(transaction));
    memset(&msg, 0, sizeof(msg));

    pb_istream_t stream = pb_istream_from_buffer(buffer, length);

    buffer_t contract_buffer;
    transaction.contract->parameter.value.funcs.decode = pb_decode_contract_parameter;
    transaction.contract->parameter.value.arg = &contract_buffer;

    transaction.custom_data.funcs.decode = pb_get_tx_data_size;
    transaction.custom_data.arg = &content->dataBytes;

    uint32_t tag;
    if (!pb_decode_contract(&stream, protocol_Transaction_raw_fields, &transaction, &tag)) {
        if (!decode_tag(&stream, &tag)) {
            // return USTREAM_FAULT;
            return 6;
        }
        // not support for large authority now
        if (tag < protocol_Transaction_raw_custom_data_tag) {
            // return USTREAM_FAULT;
            return 7;
        }
        updateTag(content, 1, tag);
        if (tag == protocol_Transaction_raw_custom_data_tag) {
            if (stream.bytes_left < 2) {
                packageLeftForNext(buffer, length, content, stream.bytes_left);
                return USTREAM_PROCESSING;
            }

            uint32_t tar_size;
            if (!decode_field_for_contract(&stream,
                                           protocol_Transaction_raw_fields,
                                           &transaction,
                                           &tar_size)) {
                // return USTREAM_FAULT;
                return 8;
            }

            content->dataBytes = tar_size;
            initTargetSize(content, 1, tar_size);
            initTargetSize(content, 10, stream.bytes_left);
            updateTargetSize(content, 1, 0);
            return USTREAM_PROCESSING;
        }

        // not support for large custom_data now
        if (tag < protocol_Transaction_raw_contract_tag) {
            // return USTREAM_FAULT;
            return 7;
        }

        // contract is complete, process it like normal
        if (!HAS_SETTING(S_DATA_ALLOWED) && content->dataBytes != 0) {
            return USTREAM_MISSING_SETTING_DATA_ALLOWED;
        }

        // multi-parts contract data processing
        if (tag == protocol_Transaction_raw_contract_tag) {
            if (stream.bytes_left < 8) {
                packageLeftForNext(buffer, length, content, stream.bytes_left);
                return USTREAM_PROCESSING;
            }

            uint32_t tar_size;
            if (!decode_field_for_contract(&stream,
                                           protocol_Transaction_raw_fields,
                                           &transaction,
                                           &tar_size)) {
                // return USTREAM_FAULT;
                return 8;
            }
            initTargetSize(content, 1, tar_size);
            initTargetSize(content, 10, stream.bytes_left);

            protocol_Transaction_Contract contract;
            memset(&contract, 0, sizeof(contract));
            contract.parameter.value.funcs.decode = pb_decode_contract_parameter;
            contract.parameter.value.arg = &contract_buffer;

            if (!pb_decode_contract(&stream,
                                    protocol_Transaction_Contract_fields,
                                    &contract,
                                    &tag)) {
                updateTargetSize(content, 1, stream.bytes_left);

                if (decode_tag(&stream, &tag)) {
                    updateTag(content, 2, tag);

                    content->contractType = (contractType_e) contract.type;
                    if (contract.type !=
                        protocol_Transaction_Contract_ContractType_TriggerSmartContract) {
                        // return USTREAM_FAULT;
                        return 9;
                    }

                    if (tag > protocol_Transaction_Contract_parameter_tag) {
                        // Contract parameter is complete, try to parse it.
                        pb_istream_t tx_stream =
                            pb_istream_from_buffer(contract_buffer.buf, contract_buffer.size);
                        if (!trigger_smart_contract_v2(content, &tx_stream)) {
                            // return USTREAM_FAULT;
                            return 10;
                        }
                        // not stream.bytes_left check, maybe 'provider' 'ContractName' is big
                        // wait for next time to process
                        if (stream.bytes_left > 200) {
                            // return USTREAM_FAULT;
                            return 11;
                        }
                        packageLeftForNext(buffer, length, content, stream.bytes_left);
                        return USTREAM_PROCESSING;

                    } else if (tag == protocol_Transaction_Contract_parameter_tag) {
                        if (stream.bytes_left < 8) {
                            // wait for next time to process
                            packageLeftForNext(buffer, length, content, stream.bytes_left);
                            return USTREAM_PROCESSING;
                        }

                        if (!decode_field_for_contract(&stream,
                                                       protocol_Transaction_Contract_fields,
                                                       &contract,
                                                       &tar_size)) {
                            // return USTREAM_FAULT;
                            return 11;
                        }
                        initTargetSize(content, 2, tar_size);
                        updateTargetSize(content, 1, stream.bytes_left);

                        google_protobuf_Any anyValue;
                        memset(&anyValue, 0, sizeof(anyValue));
                        if (!pb_decode_contract(&stream,
                                                google_protobuf_Any_fields,
                                                &anyValue,
                                                &tag)) {
                            updateTargetSize(content, 2, stream.bytes_left);

                            if (decode_tag(&stream, &tag)) {
                                updateTag(content, 3, tag);

                                if (tag == google_protobuf_Any_value_tag) {
                                    if (stream.bytes_left < 8) {
                                        // wait for next time to process
                                        packageLeftForNext(buffer,
                                                           length,
                                                           content,
                                                           stream.bytes_left);
                                        return USTREAM_PROCESSING;
                                    }

                                    if (!decode_field_for_contract(&stream,
                                                                   google_protobuf_Any_fields,
                                                                   &anyValue,
                                                                   &tar_size)) {
                                        // return USTREAM_FAULT;
                                        return 12;
                                    }
                                    initTargetSize(content, 3, tar_size);
                                    updateTargetSize(content, 2, stream.bytes_left);

                                    msg.trigger_smart_contract.data.funcs.decode =
                                        pb_decode_contract_parameter;
                                    msg.trigger_smart_contract.data.arg = &contract_buffer;

                                    if (!pb_decode_contract(&stream,
                                                            protocol_TriggerSmartContract_fields,
                                                            &msg.trigger_smart_contract,
                                                            &tag)) {
                                        updateTargetSize(content, 3, stream.bytes_left);

                                        if (decode_tag(&stream, &tag)) {
                                            updateTag(content, 4, tag);

                                            copyTriggerSmartContract(0, tag, content);

                                            if (tag == protocol_TriggerSmartContract_data_tag) {
                                                if (stream.bytes_left < 8) {
                                                    // wait for next time to process
                                                    packageLeftForNext(buffer,
                                                                       length,
                                                                       content,
                                                                       stream.bytes_left);
                                                    return USTREAM_PROCESSING;
                                                }
                                                if (!decode_field_for_contract(
                                                        &stream,
                                                        protocol_TriggerSmartContract_fields,
                                                        &msg.trigger_smart_contract,
                                                        &tar_size)) {
                                                    // return USTREAM_FAULT;
                                                    return 12;
                                                }
                                                initTargetSize(content, 4, tar_size);
                                                updateTargetSize(content, 3, stream.bytes_left);

                                                if (process_trigger_smart_contract_data_v2_for_multi(
                                                        &stream,
                                                        content,
                                                        true) < 7) {
                                                    // return USTREAM_FAULT;
                                                    return 21;
                                                }
                                                if (stream.bytes_left != 0) {
                                                    // return USTREAM_FAULT;
                                                    return 14;
                                                }

                                                updateTargetSize(content, 4, stream.bytes_left);

                                                // wait for next time to process
                                                packageLeftForNext(buffer,
                                                                   length,
                                                                   content,
                                                                   stream.bytes_left);
                                                return USTREAM_PROCESSING;
                                            } else {
                                                if (tag > protocol_TriggerSmartContract_data_tag) {
                                                    pb_istream_t tx_stream = pb_istream_from_buffer(
                                                        contract_buffer.buf,
                                                        contract_buffer.size);
                                                    if (!process_trigger_smart_contract_data_v2(
                                                            &tx_stream,
                                                            content)) {
                                                        // return USTREAM_FAULT;
                                                        return 15;
                                                    }
                                                }

                                                if (stream.bytes_left > 200) {
                                                    // return USTREAM_FAULT;
                                                    return 30;
                                                }
                                                // wait for next time to process
                                                packageLeftForNext(buffer,
                                                                   length,
                                                                   content,
                                                                   stream.bytes_left);
                                                return USTREAM_PROCESSING;
                                            }
                                        } else {
                                            // return USTREAM_FAULT;
                                            return 31;
                                        }
                                    } else {
                                        updateTag(content, 4, tag + 1);
                                        updateTargetSize(content, 3, stream.bytes_left);
                                        copyTriggerSmartContract(0, tag, content);
                                        return USTREAM_PROCESSING;
                                    }
                                } else {
                                    if (stream.bytes_left > 200) {
                                        // return USTREAM_FAULT;
                                        return 30;
                                    }
                                    // wait for next time to process
                                    packageLeftForNext(buffer, length, content, stream.bytes_left);
                                    return USTREAM_PROCESSING;
                                }
                            }
                            // // wait for next time to process
                            // packageLeftForNext(buffer, length, content, stream.bytes_left);
                            // return USTREAM_PROCESSING;
                            // // return USTREAM_FAULT;
                            return 30;
                        } else {
                            updateTag(content, 3, tag + 1);
                            updateTargetSize(content, 2, stream.bytes_left);
                            return USTREAM_PROCESSING;
                        }
                        // return USTREAM_FAULT;
                        return 32;
                    }
                    // return USTREAM_FAULT;
                    return 16;
                }
                // return USTREAM_FAULT;
                return 17;
            } else {
                updateTag(content, 2, tag + 1);
                updateTargetSize(content, 1, stream.bytes_left);
                copyContract(0, tag, content, &contract);
                return USTREAM_PROCESSING;
            }
            // return USTREAM_FAULT;
            return 18;
        } else {
            if (transaction.contract->has_parameter) {
                copyContract(0,
                             protocol_Transaction_Contract_Permission_id_tag + 1,
                             content,
                             transaction.contract);

                pb_istream_t tx_stream =
                    pb_istream_from_buffer(contract_buffer.buf, contract_buffer.size);
                if (transaction.contract->type !=
                    protocol_Transaction_Contract_ContractType_TriggerSmartContract) {
                    // return USTREAM_FAULT;
                    return 19;
                }

                if (!trigger_smart_contract_v2(content, &tx_stream)) {
                    // return USTREAM_FAULT;
                    return 21;
                }

                // store the left bytes for next pacakge
                if (stream.bytes_left > 8) {
                    // return USTREAM_FAULT;
                    return 21;
                }
                // wait for next time to process
                packageLeftForNext(buffer, length, content, stream.bytes_left);
                return USTREAM_PROCESSING;
            }
            // return USTREAM_FAULT;
            return 22;
        }
    } else {
        if (tag_last <= protocol_Transaction_raw_custom_data_tag) {
            if (!HAS_SETTING(S_DATA_ALLOWED) && content->dataBytes != 0) {
                return USTREAM_MISSING_SETTING_DATA_ALLOWED;
            }
        }

        if (transaction.contract->has_parameter) {
            content->permission_id = transaction.contract->Permission_id;
            content->contractType = (contractType_e) transaction.contract->type;

            pb_istream_t tx_stream =
                pb_istream_from_buffer(contract_buffer.buf, contract_buffer.size);
            if (transaction.contract->type !=
                protocol_Transaction_Contract_ContractType_TriggerSmartContract) {
                // return USTREAM_FAULT;
                return 19;
            }
            if (!trigger_smart_contract_v2(content, &tx_stream)) {
                // return USTREAM_FAULT;
                return 19;
            }
        }
        return USTREAM_FINISHED;
    }
}

uint8_t processTriggerSmartContractData(uint8_t *buffer,
                                        uint32_t length,
                                        txContent_t *content,
                                        bool init) {
    pb_istream_t stream = pb_istream_from_buffer(buffer, length);
    initTargetSize(content, 10, stream.bytes_left);

    uint8_t status = process_trigger_smart_contract_data_v2_for_multi(&stream, content, init);
    if (status < 7) {
        return 25;
        // return USTREAM_FAULT;
    }
    if (stream.bytes_left != 0) {
        return 21;
        // return USTREAM_FAULT;
    }

    // update contract field's size
    // update contract parameter field's size
    updateTargetSize(content, 4, stream.bytes_left);
    if (isContractDataDone(content)) {
        return USTREAM_FINISHED;
    }

    // wait for next time to process
    packageLeftForNext(buffer, length, content, stream.bytes_left);
    return USTREAM_PROCESSING;
}

uint8_t decodeTriggerSmartContract(uint8_t *buffer, uint32_t length, txContent_t *content) {
    uint32_t tag;
    uint32_t tag_last = getTag(content, 4);
    pb_istream_t stream = pb_istream_from_buffer(buffer, length);
    initTargetSize(content, 10, stream.bytes_left);

    buffer_t contract_buffer;
    msg.trigger_smart_contract.data.funcs.decode = pb_decode_contract_parameter;
    msg.trigger_smart_contract.data.arg = &contract_buffer;
    // return tag_last+10;
    if (!pb_decode_contract(&stream,
                            protocol_TriggerSmartContract_fields,
                            &msg.trigger_smart_contract,
                            &tag)) {
        updateTargetSize(content, 3, stream.bytes_left);

        if (decode_tag(&stream, &tag)) {
            copyTriggerSmartContract(tag_last, tag, content);
            updateTag(content, 4, tag);

            if (tag == protocol_TriggerSmartContract_data_tag) {
                if (stream.bytes_left < 8) {
                    // wait for next time to process
                    packageLeftForNext(buffer, length, content, stream.bytes_left);
                    return USTREAM_PROCESSING;
                }

                uint32_t tar_size;
                if (!decode_field_for_contract(&stream,
                                               protocol_TriggerSmartContract_fields,
                                               &msg.trigger_smart_contract,
                                               &tar_size)) {
                    // return USTREAM_FAULT;
                    return 50;
                }
                initTargetSize(content, 4, tar_size);
                updateTargetSize(content, 3, stream.bytes_left);

                uint32_t subLength2 = stream.bytes_left >= content->exchangeID ? content->exchangeID
                                                                               : stream.bytes_left;
                return processTriggerSmartContractData(buffer, subLength2, content, true);
            } else {
                if (tag > protocol_TriggerSmartContract_data_tag) {
                    if (tag_last <= protocol_TriggerSmartContract_data_tag) {
                        pb_istream_t tx_stream =
                            pb_istream_from_buffer(contract_buffer.buf, contract_buffer.size);
                        if (!process_trigger_smart_contract_data_v2(&tx_stream, content)) {
                            // return USTREAM_FAULT;
                            return 51;
                        }
                    }
                }

                // wait for next time to process
                packageLeftForNext(buffer, length, content, stream.bytes_left);
                return USTREAM_PROCESSING;
            }
        } else {
            return 51;
            // return USTREAM_FAULT;
        }
    } else {
        updateTargetSize(content, 3, stream.bytes_left);

        copyTriggerSmartContract(tag_last, tag + 1, content);

        if (tag_last < protocol_TriggerSmartContract_data_tag &&
            tag >= protocol_TriggerSmartContract_data_tag) {
            pb_istream_t tx_stream =
                pb_istream_from_buffer(contract_buffer.buf, contract_buffer.size);
            if (!process_trigger_smart_contract_data_v2(&tx_stream, content)) {
                // return USTREAM_FAULT;
                return 52;
            }
        }
        // if (tag >= protocol_TriggerSmartContract_token_id_tag)
        // {
        return USTREAM_FINISHED;
        // }
        // return USTREAM_PROCESSING;
    }
}

uint8_t decodeAny(uint8_t *buffer, uint32_t length, txContent_t *content) {
    uint32_t tag;
    uint32_t tag_last = getTag(content, 3);
    pb_istream_t stream = pb_istream_from_buffer(buffer, length);
    initTargetSize(content, 10, stream.bytes_left);

    google_protobuf_Any anyValue;
    memset(&anyValue, 0, sizeof(anyValue));

    buffer_t contract_buffer;
    anyValue.value.funcs.decode = pb_decode_contract_parameter;
    anyValue.value.arg = &contract_buffer;
    if (!pb_decode_contract(&stream, google_protobuf_Any_fields, &anyValue, &tag)) {
        updateTargetSize(content, 2, stream.bytes_left);

        if (decode_tag(&stream, &tag)) {
            updateTag(content, 3, tag);

            if (tag == google_protobuf_Any_value_tag) {
                if (stream.bytes_left < 8) {
                    // wait for next time to process
                    packageLeftForNext(buffer, length, content, stream.bytes_left);
                    return USTREAM_PROCESSING;
                }

                uint32_t tar_size;
                if (!decode_field_for_contract(&stream,
                                               google_protobuf_Any_fields,
                                               &anyValue,
                                               &tar_size)) {
                    // return USTREAM_FAULT;
                    return 53;
                }
                initTargetSize(content, 3, tar_size);
                updateTargetSize(content, 2, stream.bytes_left);

                return decodeTriggerSmartContract(buffer + (length - stream.bytes_left),
                                                  stream.bytes_left,
                                                  content);
            } else {
                if (stream.bytes_left > 200) {
                    // return USTREAM_FAULT;
                    return 54;
                }
                // wait for next time to process
                packageLeftForNext(buffer, length, content, stream.bytes_left);
                return USTREAM_PROCESSING;
            }
        } else {
            // return USTREAM_FAULT;
            return 55;
        }
    } else {
        updateTargetSize(content, 2, stream.bytes_left);

        if (tag_last <= google_protobuf_Any_value_tag && tag >= google_protobuf_Any_value_tag) {
            pb_istream_t tx_stream =
                pb_istream_from_buffer(contract_buffer.buf, contract_buffer.size);

            if (!trigger_smart_contract_v2(content, &tx_stream)) {
                // return USTREAM_FAULT;
                return 56;
            }
        }
        return USTREAM_FINISHED;
    }
}

uint8_t decodeContract(uint8_t *buffer, uint32_t length, txContent_t *content) {
    uint32_t tag;
    uint32_t tag_last = getTag(content, 2);
    pb_istream_t stream = pb_istream_from_buffer(buffer, length);
    content->tokenNamesLength[0] = stream.bytes_left;

    protocol_Transaction_Contract contract;
    memset(&contract, 0, sizeof(contract));
    buffer_t contract_buffer;
    contract.parameter.value.funcs.decode = pb_decode_contract_parameter;
    contract.parameter.value.arg = &contract_buffer;

    if (!pb_decode_contract(&stream, protocol_Transaction_Contract_fields, &contract, &tag)) {
        updateTargetSize(content, 1, stream.bytes_left);

        if (decode_tag(&stream, &tag)) {
            updateTag(content, 2, tag);

            if (tag > protocol_Transaction_Contract_parameter_tag) {
                copyContract(tag_last, tag + 1, content, &contract);

                if (tag_last <= protocol_Transaction_Contract_type_tag &&
                    contract.type !=
                        protocol_Transaction_Contract_ContractType_TriggerSmartContract) {
                    // return USTREAM_FAULT;
                    return 57;
                }
                if (tag_last <= protocol_Transaction_Contract_parameter_tag) {
                    // Contract parameter is complete, try to parse it.
                    pb_istream_t tx_stream =
                        pb_istream_from_buffer(contract_buffer.buf, contract_buffer.size);
                    if (!trigger_smart_contract_v2(content, &tx_stream)) {
                        // return USTREAM_FAULT;
                        return 58;
                    }
                }

                // not stream.bytes_left check, maybe 'provider' 'ContractName' is big
                // wait for next time to process
                packageLeftForNext(buffer, length, content, stream.bytes_left);
                return USTREAM_PROCESSING;
            } else if (tag == protocol_Transaction_Contract_parameter_tag) {
                if (stream.bytes_left < 8) {
                    // wait for next time to process
                    packageLeftForNext(buffer, length, content, stream.bytes_left);
                    return USTREAM_PROCESSING;
                }

                uint32_t tar_size;
                if (!decode_field_for_contract(&stream,
                                               protocol_Transaction_Contract_fields,
                                               &contract,
                                               &tar_size)) {
                    // return USTREAM_FAULT;
                    return 59;
                }
                initTargetSize(content, 2, tar_size);
                updateTargetSize(content, 1, stream.bytes_left);

                return decodeAny(buffer + (length - stream.bytes_left), stream.bytes_left, content);
            }
            // return USTREAM_FAULT;
            return 60;
        }
        // return USTREAM_FAULT;
        return 61;
    } else {
        updateTargetSize(content, 1, stream.bytes_left);
        copyContract(tag_last, tag + 1, content, &contract);

        if (contract.has_parameter) {
            pb_istream_t tx_stream =
                pb_istream_from_buffer(contract_buffer.buf, contract_buffer.size);
            if (contract.type != protocol_Transaction_Contract_ContractType_TriggerSmartContract) {
                // return USTREAM_FAULT;
                return 62;
            }
            if (!trigger_smart_contract_v2(content, &tx_stream)) {
                // return USTREAM_FAULT;
                return 63;
            }
        }
        return USTREAM_FINISHED;
    }
}

uint8_t processCustomData(uint8_t *buffer, uint32_t length, txContent_t *content) {
    initTargetSize(content, 10, length);
    updateTargetSize(content, 1, 0);
    if (isCustomDataDone(content)) {
        return USTREAM_FINISHED;
    }
    return USTREAM_PROCESSING;
}

uint32_t processTxForCSPart(uint8_t *buffer, uint32_t length, txContent_t *content, uint8_t state) {
    if (length == 0) {
        return USTREAM_FINISHED;
    }

    memset(&msg, 0, sizeof(msg));

    // P1_FIRST
    if (state == 0x00) {
        updateTag(content, 0, 0);
        initTargetSize(content, 0, 0);

        return processTxForCSMulti(buffer, length, content);
    }

    if (length < 8 && state != 0x90) {
        // wait for next time to process
        packageLeftForNext(buffer, length, content, length);
        return USTREAM_PROCESSING;
    }

    uint8_t ret = 0;
    uint32_t subLength = 0;
    uint8_t level = locatePackageLevel(content);
    // if (state == 0x90)
    // {
    //     return locatePackageLevel(content)+10;
    // }
    switch (level) {
        case 0:
            subLength = getLeftForLevel(content, 0, length);
            ret = processCustomData(buffer, subLength, content);
            break;
        case 1:
            subLength = length;
            ret = processTxForCSMulti(buffer, subLength, content);
            // return content->amount[1];
            // return ret+10;
            // return content->amount[1]+10;
            // return content->tokenNamesLength[0];
            break;
        case 2:
            subLength = getLeftForLevel(content, 1, length);
            // return length+10;
            //    return content->customData+10;
            // return content->amount[1]+10;
            // return content->customSelector+10;
            // return content->exchangeID;
            // return content->tokenNamesLength[0]+10;
            // return length;
            // return subLength+10;
            // return buffer[0];
            ret = decodeContract(buffer, subLength, content);
            // return content->tokenNamesLength[0]+10;
            // return ret+10;
            // return content->permission_id+10;
            // return length-subLength+10;
            //    return content->customData+10;
            // return content->tokenNamesLength[1]+10;
            // return locatePackageLevel(content)+10;
            break;
        case 3:
            subLength = getLeftForLevel(content, 2, length);
            // return content->amount[1];
            // return length; //107
            ret = decodeAny(buffer, subLength, content);
            // return content->customSelector+10;
            break;
        case 4:
            subLength = getLeftForLevel(content, 3, length);
            // return content->amount[1]; //116
            // return content->customSelector;
            // return content->customData+10; //118
            ret = decodeTriggerSmartContract(buffer, subLength, content);
            // return content->customData+10;
            // return content->tokenNamesLength[0]+10;
            // return content->amount[1]+10;
            // return length;
            // return length-subLength+10;
            // return subLength;
            // return (buffer+subLength)[2];
            // return ret+10;
            break;
        case 5:
            subLength = getLeftForLevel(content, 4, length);
            // if (state == 0x90)
            // {
            //     // return locatePackageLevel(content)+10;
            //     // return content->amount[1];
            //     // return content->customSelector+10;
            //     // return subLength;
            // }
            // return content->amount[1]+10;
            ret = processTriggerSmartContractData(buffer, subLength, content, false);
            // if (state == 0x90)
            // {
            //     // return locatePackageLevel(content)+10;
            // return content->amount[1]+10;
            //     // return content->customSelector+10;
            // }
            break;
        case 10:
            return USTREAM_FINISHED;
        default:
            return 101;
            return USTREAM_FAULT;
    }
    if (ret == USTREAM_PROCESSING) {
        return USTREAM_PROCESSING;
    } else if (ret != USTREAM_FINISHED) {
        return ret;
        return USTREAM_FAULT;
    } else {
        updateTagForFinished(content, level);
        // if (state == 0x90)
        // {
        //     return length-subLength+10;
        //     // return content->TRC20Amount[3]+10;
        //     return locatePackageLevel(content)+10;
        // }

        if (subLength < length) {
            return processTxForCSPart(buffer + subLength, length - subLength, content, state);
        }
    }
    if (state == 0x90) {
        // return content->permission_id+10;
        return USTREAM_FINISHED;
    }
    return USTREAM_PROCESSING;
}

uint32_t processTxForCSMultiParts(uint8_t *buffer,
                                  uint32_t length,
                                  txContent_t *content,
                                  uint8_t state) {
    // if (state == 0x90)
    // {
    //     // return content->tokenNamesLength[0]+20;
    //     return length;
    // }
    if (!mergeLeftPackToBuffer(content, buffer, &length)) {
        // return USTREAM_FAULT;
        return 200;
    }
    // if (state == 0x90)
    // {
    //     // return content->permission_id+10;
    //     // return content->tokenNamesLength[0]+20;
    //     return length;
    // }

    uint16_t txResult = processTxForCSPart(buffer, length, content, state);
    if (txResult != USTREAM_FINISHED && txResult != USTREAM_PROCESSING) {
        // return 10;
        return txResult;
    }
    // return content->customData;
    // return content->amount[1];
    // return content->customSelector;
    // return content->exchangeID;
    // return content->tokenNamesLength[0];
    // return 101;
    // if (state == 0x90)
    // {
    //     // return content->tokenNamesLength[0]+10;
    //     return content->tokenNamesLength[1]+10;
    // }

    if (!oneMoreTimeForLeftBytes(content, buffer, &length)) {
        // return USTREAM_FAULT;
        return 101;
    }
    // if (state == 0x90)
    // {
    //     return length+20;
    // }
    if (length > 0) {
        // return 100;
        // return length;
        // return locatePackageLevel(content)+10;
        return processTxForCSPart(buffer, length, content, state);
    }

    // P1_LAST
    if (state == 0x90) {
        if (content->tokenNamesLength[0] > 0) {
            // return USTREAM_FAULT;
            return 3;
        }
        if (content->tokenNamesLength[1] > 0) {
            return processTxForCSPart((uint8_t *) content->tokenNames[1],
                                      content->tokenNamesLength[1],
                                      content,
                                      state);
        }
    }
    return txResult;
}

parserStatus_e processTxForClearSign(uint8_t *buffer, uint32_t length, txContent_t *content) {
    protocol_Transaction_raw transaction;

    if (length == 0) {
        return USTREAM_FINISHED;
    }

    memset(&transaction, 0, sizeof(transaction));
    memset(&msg, 0, sizeof(msg));

    pb_istream_t stream = pb_istream_from_buffer(buffer, length);

    buffer_t contract_buffer;
    transaction.contract->parameter.value.funcs.decode = pb_decode_contract_parameter;
    transaction.contract->parameter.value.arg = &contract_buffer;

    transaction.custom_data.funcs.decode = pb_get_tx_data_size;
    transaction.custom_data.arg = &content->dataBytes;

    if (!pb_decode(&stream, protocol_Transaction_raw_fields, &transaction)) {
        return USTREAM_FAULT;
    }

    if (!HAS_SETTING(S_DATA_ALLOWED) && content->dataBytes != 0) {
        return USTREAM_MISSING_SETTING_DATA_ALLOWED;
    }

    if (transaction.contract->has_parameter) {
        content->permission_id = transaction.contract->Permission_id;
        content->contractType = (contractType_e) transaction.contract->type;

        pb_istream_t tx_stream = pb_istream_from_buffer(contract_buffer.buf, contract_buffer.size);
        bool ret;

        switch (transaction.contract->type) {
            case protocol_Transaction_Contract_ContractType_TriggerSmartContract:
                ret = trigger_smart_contract_v2(content, &tx_stream);
                break;
            default:
                return USTREAM_FAULT;
        }
        return ret ? USTREAM_PROCESSING : 4;
    }

    return USTREAM_PROCESSING;
}
int bytes_to_string(char *out, size_t outl, const void *value, size_t len) {
    if (outl <= 2) {
        // Need at least '0x' and 1 digit
        return -1;
    }
    if (strlcpy(out, "0x", outl) != 2) {
        goto err;
    }
    if (format_hex(value, len, out + 2, outl - 2) < 0) {
        goto err;
    }
    return 0;
err:
    *out = '\0';
    return -1;
}
