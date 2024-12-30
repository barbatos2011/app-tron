/*******************************************************************************
 *   Ledger Tron App
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

#include "common_utils.h"
#include "lcx_ecfp.h"
#include "lcx_sha3.h"
#include "parse.h"

uint64_t u64_from_BE(const uint8_t *in, uint8_t size) {
    uint8_t i = 0;
    uint64_t res = 0;

    while (i < size && i < sizeof(res)) {
        res <<= 8;
        res |= in[i];
        i++;
    }

    return res;
}

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

    if (adjustDecimals(tmp_buffer,
                       amount_len,
                       out_buffer + ticker_len,
                       out_buffer_size - ticker_len - 1,
                       decimals) == false) {
        return false;
    }

    out_buffer[out_buffer_size - 1] = '\0';
    return true;
}

bool getEthAddressStringFromBinary(uint8_t *address,
                                   char out[static(ADDRESS_SIZE_712 * 2) + 1],
                                   uint64_t chainId) {
    // save some precious stack space
    union locals_union {
        uint8_t hashChecksum[INT256_LENGTH];
        uint8_t tmp[51];
    } locals_union;

    uint8_t i;
    bool tip1191 = false;
    uint32_t offset = 0;
    switch (chainId) {
        case 30:
        case 31:
            tip1191 = true;
            break;
    }
    if (tip1191) {
        if (!u64_to_string(chainId, (char *) locals_union.tmp, sizeof(locals_union.tmp))) {
            return false;
        }
        offset = strnlen((char *) locals_union.tmp, sizeof(locals_union.tmp));
        strlcat((char *) locals_union.tmp + offset, "0x", sizeof(locals_union.tmp) - offset);
        offset = strnlen((char *) locals_union.tmp, sizeof(locals_union.tmp));
    }
    for (i = 0; i < 20; i++) {
        uint8_t digit = address[i];
        locals_union.tmp[offset + 2 * i] = HEXDIGITS[(digit >> 4) & 0x0f];
        locals_union.tmp[offset + 2 * i + 1] = HEXDIGITS[digit & 0x0f];
    }
    if (cx_keccak_256_hash(locals_union.tmp, offset + 40, locals_union.hashChecksum) != CX_OK) {
        return false;
    }

    for (i = 0; i < 40; i++) {
        uint8_t digit = address[i / 2];
        if ((i % 2) == 0) {
            digit = (digit >> 4) & 0x0f;
        } else {
            digit = digit & 0x0f;
        }
        if (digit < 10) {
            out[i] = HEXDIGITS[digit];
        } else {
            int v = (locals_union.hashChecksum[i / 2] >> (4 * (1 - i % 2))) & 0x0f;
            if (v >= 8) {
                out[i] = HEXDIGITS[digit] - 'a' + 'A';
            } else {
                out[i] = HEXDIGITS[digit];
            }
        }
    }
    out[ADDRESS_SIZE_712 * 2] = '\0';

    return true;
}

/* Fills the `out` buffer with the lowercase string representation of the pubkey passed in as binary
format by `in`. (eg: uint8_t*:0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB ->
char*:"0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB\0" ).*/
bool getEthDisplayableAddress(uint8_t *in, char *out, size_t out_len, uint64_t chainId) {
    if (out_len < 43) {
        strlcpy(out, "ERROR", out_len);
        return false;
    }
    out[0] = '0';
    out[1] = 'x';
    if (!getEthAddressStringFromBinary(in, out + 2, chainId)) {
        strlcpy(out, "ERROR", out_len);
        return false;
    }

    return true;
}