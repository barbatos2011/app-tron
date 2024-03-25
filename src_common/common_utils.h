/*******************************************************************************
 *   Ledger Ethereum App
 *   (c) 2016-2019 Ledger
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

#include <stddef.h>
#include <stdint.h>

#include "os.h"
#include "cx.h"
#include "base58.h"

#define ADDRESS_SIZE   21
#define MAX_TOKEN_LENGTH         67
#define ADD_PRE_FIX_BYTE_MAINNET 0x41
#define INT256_LENGTH  32
#define BASE58CHECK_ADDRESS_SIZE 34
#define HASH_SIZE                32

static const char HEXDIGITS[] = "0123456789abcdef";

bool u64_to_string(uint64_t src, char *dst, uint8_t dst_size);

bool uint256_to_decimal(const uint8_t *value, size_t value_len, char *out, size_t out_len);

bool amountToString(const uint8_t *amount,
                    uint8_t amount_len,
                    uint8_t decimals,
                    const char *ticker,
                    char *out_buffer,
                    size_t out_buffer_size);

bool adjustDecimals_v2(const char *src,
                    size_t srcLength,
                    char *target,
                    size_t targetLength,
                    uint8_t decimals);

static __attribute__((no_instrument_function)) inline int allzeroes(const void *buf, size_t n) {
    uint8_t *p = (uint8_t *) buf;
    for (size_t i = 0; i < n; ++i) {
        if (p[i]) {
            return 0;
        }
    }
    return 1;
}

void getBase58FromAddress(const uint8_t address[static ADDRESS_SIZE], char *out, bool truncate);
