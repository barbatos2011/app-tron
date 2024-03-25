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

#include <stdint.h>
#include <string.h>

#include "asset_info.h"
#include "common_utils.h"
#include "lcx_ecfp.h"
#include "lcx_sha3.h"

bool u64_to_string(uint64_t src, char *dst, uint8_t dst_size) {
    // Copy the numbers in ASCII format.
    uint8_t i = 0;
    do {
        // Checking `i + 1` to make sure we have enough space for '\0'.
        if (i + 1 >= dst_size) {
            return false;
        }
        dst[i] = src % 10 + '0';
        src /= 10;
        i++;
    } while (src);

    // Null terminate string
    dst[i] = '\0';

    // Revert the string
    i--;
    uint8_t j = 0;
    while (j < i) {
        char tmp = dst[i];
        dst[i] = dst[j];
        dst[j] = tmp;
        i--;
        j++;
    }
    return true;
}

bool uint256_to_decimal(const uint8_t *value, size_t value_len, char *out, size_t out_len) {
    if (value_len > INT256_LENGTH) {
        // value len is bigger than INT256_LENGTH ?!
        return false;
    }

    uint16_t n[16] = {0};
    // Copy and right-align the number
    memcpy((uint8_t *) n + INT256_LENGTH - value_len, value, value_len);

    // Special case when value is 0
    if (allzeroes(n, INT256_LENGTH)) {
        if (out_len < 2) {
            // Not enough space to hold "0" and \0.
            return false;
        }
        strlcpy(out, "0", out_len);
        return true;
    }

    uint16_t *p = n;
    for (int i = 0; i < 16; i++) {
        n[i] = __builtin_bswap16(*p++);
    }
    int pos = out_len;
    while (!allzeroes(n, sizeof(n))) {
        if (pos == 0) {
            return false;
        }
        pos -= 1;
        unsigned int carry = 0;
        for (int i = 0; i < 16; i++) {
            int rem = ((carry << 16) | n[i]) % 10;
            n[i] = ((carry << 16) | n[i]) / 10;
            carry = rem;
        }
        out[pos] = '0' + carry;
    }
    memmove(out, out + pos, out_len - pos);
    out[out_len - pos] = 0;
    return true;
}

bool adjustDecimals_v2(const char *src,
                    size_t srcLength,
                    char *target,
                    size_t targetLength,
                    uint8_t decimals) {
    uint32_t startOffset;
    uint32_t lastZeroOffset = 0;
    uint32_t offset = 0;

    if ((srcLength == 1) && (*src == '0')) {
        if (targetLength < 2) {
            return false;
        }
        target[0] = '0';
        target[1] = '\0';
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

bool amountToString(const uint8_t *amount,
                    uint8_t amount_size,
                    uint8_t decimals,
                    const char *ticker,
                    char *out_buffer,
                    size_t out_buffer_size) {
    char tmp_buffer[100] = {0};

    if (uint256_to_decimal(amount, amount_size, tmp_buffer, sizeof(tmp_buffer)) == false) {
        return false;
    }

    uint8_t amount_len = strnlen(tmp_buffer, sizeof(tmp_buffer));
    uint8_t ticker_len = strnlen(ticker, MAX_TICKER_LEN);

    if (ticker_len > 0) {
        if (out_buffer_size <= ticker_len + 1) {
            return false;
        }
        memcpy(out_buffer, ticker, ticker_len);
        out_buffer[ticker_len++] = ' ';
    }

    if (adjustDecimals_v2(tmp_buffer,
                       amount_len,
                       out_buffer + ticker_len,
                       out_buffer_size - ticker_len - 1,
                       decimals) == false) {
        return false;
    }

    out_buffer[out_buffer_size - 1] = '\0';
    return true;
}

void getBase58FromAddress(const uint8_t address[static ADDRESS_SIZE], char *out, bool truncate) {
    uint8_t sha256[HASH_SIZE];
    uint8_t addchecksum[ADDRESS_SIZE + 4];

    cx_hash_sha256(address, ADDRESS_SIZE, sha256, HASH_SIZE);
    cx_hash_sha256(sha256, HASH_SIZE, sha256, HASH_SIZE);

    memmove(addchecksum, address, ADDRESS_SIZE);
    memmove(addchecksum + ADDRESS_SIZE, sha256, 4);

    base58_encode(addchecksum, sizeof(addchecksum), out, BASE58CHECK_ADDRESS_SIZE);
    out[BASE58CHECK_ADDRESS_SIZE] = '\0';
    if (truncate) {
        memmove((void *) out + 5, "...", 3);
        memmove((void *) out + 8,
                (const void *) (out + BASE58CHECK_ADDRESS_SIZE - 5),
                6);  // include \0 char
    }
}