/*******************************************************************************
 *   Ledger Blue
 *   (c) 2016 Ledger
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

// Adapted from https://github.com/calccrypto/uint256_t

#include <stdio.h>
#include <stdlib.h>
#include "read.h"
#include "uint256.h"
#include "common_utils.h"

void readu128BE(uint8_t *buffer, uint128_t *target) {
    UPPER_P(target) = read_u64_be(buffer, 0);
    LOWER_P(target) = read_u64_be(buffer + 8, 0);
}

void readu256BE(uint8_t *buffer, uint256_t *target) {
    readu128BE(buffer, &UPPER_P(target));
    readu128BE(buffer + 16, &LOWER_P(target));
}

bool zero128(uint128_t *number) {
    return ((LOWER_P(number) == 0) && (UPPER_P(number) == 0));
}

bool zero256(uint256_t *number) {
    return (zero128(&LOWER_P(number)) && zero128(&UPPER_P(number)));
}

void copy128(uint128_t *target, const uint128_t *number) {
    UPPER_P(target) = UPPER_P(number);
    LOWER_P(target) = LOWER_P(number);
}

void copy256(uint256_t *target, const uint256_t *number) {
    copy128(&UPPER_P(target), &UPPER_P(number));
    copy128(&LOWER_P(target), &LOWER_P(number));
}

void clear128(uint128_t *target) {
    UPPER_P(target) = 0;
    LOWER_P(target) = 0;
}

void clear256(uint256_t *target) {
    clear128(&UPPER_P(target));
    clear128(&LOWER_P(target));
}

void shiftl128(uint128_t *number, uint32_t value, uint128_t *target) {
    if (value >= 128) {
        clear128(target);
    } else if (value == 64) {
        UPPER_P(target) = LOWER_P(number);
        LOWER_P(target) = 0;
    } else if (value == 0) {
        copy128(target, number);
    } else if (value < 64) {
        UPPER_P(target) = (UPPER_P(number) << value) + (LOWER_P(number) >> (64 - value));
        LOWER_P(target) = (LOWER_P(number) << value);
    } else if ((128 > value) && (value > 64)) {
        UPPER_P(target) = LOWER_P(number) << (value - 64);
        LOWER_P(target) = 0;
    } else {
        clear128(target);
    }
}

void shiftl256(uint256_t *number, uint32_t value, uint256_t *target) {
    if (value >= 256) {
        clear256(target);
    } else if (value == 128) {
        copy128(&UPPER_P(target), &LOWER_P(number));
        clear128(&LOWER_P(target));
    } else if (value == 0) {
        copy256(target, number);
    } else if (value < 128) {
        uint128_t tmp1;
        uint128_t tmp2;
        uint256_t result;
        shiftl128(&UPPER_P(number), value, &tmp1);
        shiftr128(&LOWER_P(number), (128 - value), &tmp2);
        add128(&tmp1, &tmp2, &UPPER(result));
        shiftl128(&LOWER_P(number), value, &LOWER(result));
        copy256(target, &result);
    } else if ((256 > value) && (value > 128)) {
        shiftl128(&LOWER_P(number), (value - 128), &UPPER_P(target));
        clear128(&LOWER_P(target));
    } else {
        clear256(target);
    }
}

void shiftr128(uint128_t *number, uint32_t value, uint128_t *target) {
    if (value >= 128) {
        clear128(target);
    } else if (value == 64) {
        UPPER_P(target) = 0;
        LOWER_P(target) = UPPER_P(number);
    } else if (value == 0) {
        copy128(target, number);
    } else if (value < 64) {
        uint128_t result;
        UPPER(result) = UPPER_P(number) >> value;
        LOWER(result) = (UPPER_P(number) << (64 - value)) + (LOWER_P(number) >> value);
        copy128(target, &result);
    } else if ((128 > value) && (value > 64)) {
        LOWER_P(target) = UPPER_P(number) >> (value - 64);
        UPPER_P(target) = 0;
    } else {
        clear128(target);
    }
}

void shiftr256(uint256_t *number, uint32_t value, uint256_t *target) {
    if (value >= 256) {
        clear256(target);
    } else if (value == 128) {
        copy128(&LOWER_P(target), &UPPER_P(number));
        clear128(&UPPER_P(target));
    } else if (value == 0) {
        copy256(target, number);
    } else if (value < 128) {
        uint128_t tmp1;
        uint128_t tmp2;
        uint256_t result;
        shiftr128(&UPPER_P(number), value, &UPPER(result));
        shiftr128(&LOWER_P(number), value, &tmp1);
        shiftl128(&UPPER_P(number), (128 - value), &tmp2);
        add128(&tmp1, &tmp2, &LOWER(result));
        copy256(target, &result);
    } else if ((256 > value) && (value > 128)) {
        shiftr128(&UPPER_P(number), (value - 128), &LOWER_P(target));
        clear128(&UPPER_P(target));
    } else {
        clear256(target);
    }
}

uint32_t bits128(uint128_t *number) {
    uint32_t result = 0;
    if (UPPER_P(number)) {
        result = 64;
        uint64_t up = UPPER_P(number);
        while (up) {
            up >>= 1;
            result++;
        }
    } else {
        uint64_t low = LOWER_P(number);
        while (low) {
            low >>= 1;
            result++;
        }
    }
    return result;
}

uint32_t bits256(uint256_t *number) {
    uint32_t result = 0;
    if (!zero128(&UPPER_P(number))) {
        result = 128;
        uint128_t up;
        copy128(&up, &UPPER_P(number));
        while (!zero128(&up)) {
            shiftr128(&up, 1, &up);
            result++;
        }
    } else {
        uint128_t low;
        copy128(&low, &LOWER_P(number));
        while (!zero128(&low)) {
            shiftr128(&low, 1, &low);
            result++;
        }
    }
    return result;
}

bool equal128(const uint128_t *number1, uint128_t *number2) {
    return (UPPER_P(number1) == UPPER_P(number2)) && (LOWER_P(number1) == LOWER_P(number2));
}

bool equal256(uint256_t *number1, uint256_t *number2) {
    return (equal128(&UPPER_P(number1), &UPPER_P(number2)) &&
            equal128(&LOWER_P(number1), &LOWER_P(number2)));
}

bool gt128(const uint128_t *number1, const uint128_t *number2) {
    if (UPPER_P(number1) == UPPER_P(number2)) {
        return (LOWER_P(number1) > LOWER_P(number2));
    }
    return (UPPER_P(number1) > UPPER_P(number2));
}

bool gt256(const uint256_t *number1, uint256_t *number2) {
    if (equal128(&UPPER_P(number1), &UPPER_P(number2))) {
        return gt128(&LOWER_P(number1), &LOWER_P(number2));
    }
    return gt128(&UPPER_P(number1), &UPPER_P(number2));
}

bool gte128(uint128_t *number1, uint128_t *number2) {
    return gt128(number1, number2) || equal128(number1, number2);
}

bool gte256(uint256_t *number1, uint256_t *number2) {
    return gt256(number1, number2) || equal256(number1, number2);
}

void add128(uint128_t *number1, uint128_t *number2, uint128_t *target) {
    UPPER_P(target) = UPPER_P(number1) + UPPER_P(number2) +
                      ((LOWER_P(number1) + LOWER_P(number2)) < LOWER_P(number1));
    LOWER_P(target) = LOWER_P(number1) + LOWER_P(number2);
}

void add256(uint256_t *number1, uint256_t *number2, uint256_t *target) {
    uint128_t tmp;
    add128(&UPPER_P(number1), &UPPER_P(number2), &UPPER_P(target));
    add128(&LOWER_P(number1), &LOWER_P(number2), &tmp);
    if (gt128(&LOWER_P(number1), &tmp)) {
        uint128_t one;
        UPPER(one) = 0;
        LOWER(one) = 1;
        add128(&UPPER_P(target), &one, &UPPER_P(target));
    }
    add128(&LOWER_P(number1), &LOWER_P(number2), &LOWER_P(target));
}

void minus128(uint128_t *number1, uint128_t *number2, uint128_t *target) {
    UPPER_P(target) = UPPER_P(number1) - UPPER_P(number2) -
                      ((LOWER_P(number1) - LOWER_P(number2)) > LOWER_P(number1));
    LOWER_P(target) = LOWER_P(number1) - LOWER_P(number2);
}

void minus256(uint256_t *number1, uint256_t *number2, uint256_t *target) {
    uint128_t tmp;
    minus128(&UPPER_P(number1), &UPPER_P(number2), &UPPER_P(target));
    minus128(&LOWER_P(number1), &LOWER_P(number2), &tmp);
    if (gt128(&tmp, &LOWER_P(number1))) {
        uint128_t one;
        UPPER(one) = 0;
        LOWER(one) = 1;
        minus128(&UPPER_P(target), &one, &UPPER_P(target));
    }
    minus128(&LOWER_P(number1), &LOWER_P(number2), &LOWER_P(target));
}

void or128(uint128_t *number1, uint128_t *number2, uint128_t *target) {
    UPPER_P(target) = UPPER_P(number1) | UPPER_P(number2);
    LOWER_P(target) = LOWER_P(number1) | LOWER_P(number2);
}

void or256(uint256_t *number1, uint256_t *number2, uint256_t *target) {
    or128(&UPPER_P(number1), &UPPER_P(number2), &UPPER_P(target));
    or128(&LOWER_P(number1), &LOWER_P(number2), &LOWER_P(target));
}

void mul128(uint128_t *number1, uint128_t *number2, uint128_t *target) {
    uint64_t top[4] = {UPPER_P(number1) >> 32,
                       UPPER_P(number1) & 0xffffffff,
                       LOWER_P(number1) >> 32,
                       LOWER_P(number1) & 0xffffffff};
    uint64_t bottom[4] = {UPPER_P(number2) >> 32,
                          UPPER_P(number2) & 0xffffffff,
                          LOWER_P(number2) >> 32,
                          LOWER_P(number2) & 0xffffffff};
    uint64_t products[4][4];
    uint128_t tmp, tmp2;

    for (int y = 3; y > -1; y--) {
        for (int x = 3; x > -1; x--) {
            products[3 - x][y] = top[x] * bottom[y];
        }
    }

    uint64_t fourth32 = products[0][3] & 0xffffffff;
    uint64_t third32 = (products[0][2] & 0xffffffff) + (products[0][3] >> 32);
    uint64_t second32 = (products[0][1] & 0xffffffff) + (products[0][2] >> 32);
    uint64_t first32 = (products[0][0] & 0xffffffff) + (products[0][1] >> 32);

    third32 += products[1][3] & 0xffffffff;
    second32 += (products[1][2] & 0xffffffff) + (products[1][3] >> 32);
    first32 += (products[1][1] & 0xffffffff) + (products[1][2] >> 32);

    second32 += products[2][3] & 0xffffffff;
    first32 += (products[2][2] & 0xffffffff) + (products[2][3] >> 32);

    first32 += products[3][3] & 0xffffffff;

    UPPER(tmp) = first32 << 32;
    LOWER(tmp) = 0;
    UPPER(tmp2) = third32 >> 32;
    LOWER(tmp2) = third32 << 32;
    add128(&tmp, &tmp2, target);
    UPPER(tmp) = second32;
    LOWER(tmp) = 0;
    add128(&tmp, target, &tmp2);
    UPPER(tmp) = 0;
    LOWER(tmp) = fourth32;
    add128(&tmp, &tmp2, target);
}

void mul256(uint256_t *number1, uint256_t *number2, uint256_t *target) {
    uint128_t top[4];
    uint128_t bottom[4];
    uint128_t products[4][4];
    uint128_t tmp, tmp2, fourth64, third64, second64, first64;
    uint256_t target1, target2;
    UPPER(top[0]) = 0;
    LOWER(top[0]) = UPPER(UPPER_P(number1));
    UPPER(top[1]) = 0;
    LOWER(top[1]) = LOWER(UPPER_P(number1));
    UPPER(top[2]) = 0;
    LOWER(top[2]) = UPPER(LOWER_P(number1));
    UPPER(top[3]) = 0;
    LOWER(top[3]) = LOWER(LOWER_P(number1));
    UPPER(bottom[0]) = 0;
    LOWER(bottom[0]) = UPPER(UPPER_P(number2));
    UPPER(bottom[1]) = 0;
    LOWER(bottom[1]) = LOWER(UPPER_P(number2));
    UPPER(bottom[2]) = 0;
    LOWER(bottom[2]) = UPPER(LOWER_P(number2));
    UPPER(bottom[3]) = 0;
    LOWER(bottom[3]) = LOWER(LOWER_P(number2));

    for (int y = 3; y > -1; y--) {
        for (int x = 3; x > -1; x--) {
            mul128(&top[x], &bottom[y], &products[3 - x][y]);
        }
    }

    UPPER(fourth64) = 0;
    LOWER(fourth64) = LOWER(products[0][3]);
    UPPER(tmp) = 0;
    LOWER(tmp) = LOWER(products[0][2]);
    UPPER(tmp2) = 0;
    LOWER(tmp2) = UPPER(products[0][3]);
    add128(&tmp, &tmp2, &third64);
    UPPER(tmp) = 0;
    LOWER(tmp) = LOWER(products[0][1]);
    UPPER(tmp2) = 0;
    LOWER(tmp2) = UPPER(products[0][2]);
    add128(&tmp, &tmp2, &second64);
    UPPER(tmp) = 0;
    LOWER(tmp) = LOWER(products[0][0]);
    UPPER(tmp2) = 0;
    LOWER(tmp2) = UPPER(products[0][1]);
    add128(&tmp, &tmp2, &first64);

    UPPER(tmp) = 0;
    LOWER(tmp) = LOWER(products[1][3]);
    add128(&tmp, &third64, &tmp2);
    copy128(&third64, &tmp2);
    UPPER(tmp) = 0;
    LOWER(tmp) = LOWER(products[1][2]);
    add128(&tmp, &second64, &tmp2);
    UPPER(tmp) = 0;
    LOWER(tmp) = UPPER(products[1][3]);
    add128(&tmp, &tmp2, &second64);
    UPPER(tmp) = 0;
    LOWER(tmp) = LOWER(products[1][1]);
    add128(&tmp, &first64, &tmp2);
    UPPER(tmp) = 0;
    LOWER(tmp) = UPPER(products[1][2]);
    add128(&tmp, &tmp2, &first64);

    UPPER(tmp) = 0;
    LOWER(tmp) = LOWER(products[2][3]);
    add128(&tmp, &second64, &tmp2);
    copy128(&second64, &tmp2);
    UPPER(tmp) = 0;
    LOWER(tmp) = LOWER(products[2][2]);
    add128(&tmp, &first64, &tmp2);
    UPPER(tmp) = 0;
    LOWER(tmp) = UPPER(products[2][3]);
    add128(&tmp, &tmp2, &first64);

    UPPER(tmp) = 0;
    LOWER(tmp) = LOWER(products[3][3]);
    add128(&tmp, &first64, &tmp2);
    copy128(&first64, &tmp2);

    clear256(&target1);
    shiftl128(&first64, 64, &UPPER(target1));
    clear256(&target2);
    UPPER(UPPER(target2)) = UPPER(third64);
    shiftl128(&third64, 64, &LOWER(target2));
    add256(&target1, &target2, target);
    clear256(&target1);
    copy128(&UPPER(target1), &second64);
    add256(&target1, target, &target2);
    clear256(&target1);
    copy128(&LOWER(target1), &fourth64);
    add256(&target1, &target2, target);
}

void divmod128(uint128_t *l, uint128_t *r, uint128_t *retDiv, uint128_t *retMod) {
    uint128_t copyd, adder, resDiv, resMod;
    uint128_t one;
    UPPER(one) = 0;
    LOWER(one) = 1;
    uint32_t diffBits = bits128(l) - bits128(r);
    clear128(&resDiv);
    copy128(&resMod, l);
    if (gt128(r, l)) {
        copy128(retMod, l);
        clear128(retDiv);
    } else {
        shiftl128(r, diffBits, &copyd);
        shiftl128(&one, diffBits, &adder);
        if (gt128(&copyd, &resMod)) {
            shiftr128(&copyd, 1, &copyd);
            shiftr128(&adder, 1, &adder);
        }
        while (gte128(&resMod, r)) {
            if (gte128(&resMod, &copyd)) {
                minus128(&resMod, &copyd, &resMod);
                or128(&resDiv, &adder, &resDiv);
            }
            shiftr128(&copyd, 1, &copyd);
            shiftr128(&adder, 1, &adder);
        }
        copy128(retDiv, &resDiv);
        copy128(retMod, &resMod);
    }
}

void divmod256(uint256_t *l, uint256_t *r, uint256_t *retDiv, uint256_t *retMod) {
    uint256_t copyd, adder, resDiv, resMod;
    uint256_t one;
    clear256(&one);
    UPPER(LOWER(one)) = 0;
    LOWER(LOWER(one)) = 1;
    uint32_t diffBits = bits256(l) - bits256(r);
    clear256(&resDiv);
    copy256(&resMod, l);
    if (gt256(r, l)) {
        copy256(retMod, l);
        clear256(retDiv);
    } else {
        shiftl256(r, diffBits, &copyd);
        shiftl256(&one, diffBits, &adder);
        if (gt256(&copyd, &resMod)) {
            shiftr256(&copyd, 1, &copyd);
            shiftr256(&adder, 1, &adder);
        }
        while (gte256(&resMod, r)) {
            if (gte256(&resMod, &copyd)) {
                minus256(&resMod, &copyd, &resMod);
                or256(&resDiv, &adder, &resDiv);
            }
            shiftr256(&copyd, 1, &copyd);
            shiftr256(&adder, 1, &adder);
        }
        copy256(retDiv, &resDiv);
        copy256(retMod, &resMod);
    }
}

static void reverseString(char *str, uint32_t length) {
    uint32_t i, j;
    for (i = 0, j = length - 1; i < j; i++, j--) {
        uint8_t c;
        c = str[i];
        str[i] = str[j];
        str[j] = c;
    }
}

bool tostring128(const uint128_t *number, uint32_t baseParam, char *out, uint32_t outLength) {
    uint128_t rDiv;
    uint128_t rMod;
    uint128_t base;
    copy128(&rDiv, number);
    clear128(&rMod);
    clear128(&base);
    LOWER(base) = baseParam;
    uint32_t offset = 0;
    if ((baseParam < 2) || (baseParam > 16)) {
        return false;
    }
    do {
        if (offset > (outLength - 1)) {
            return false;
        }
        divmod128(&rDiv, &base, &rDiv, &rMod);
        out[offset++] = HEXDIGITS[(uint8_t) LOWER(rMod)];
    } while (!zero128(&rDiv));
    out[offset] = '\0';
    reverseString(out, offset);
    return true;
}

bool tostring256(const uint256_t *number, uint32_t baseParam, char *out, uint32_t outLength) {
    uint256_t rDiv;
    uint256_t rMod;
    uint256_t base;
    copy256(&rDiv, number);
    clear256(&rMod);
    clear256(&base);
    UPPER(LOWER(base)) = 0;
    LOWER(LOWER(base)) = baseParam;
    uint32_t offset = 0;
    if ((baseParam < 2) || (baseParam > 16)) {
        return false;
    }
    do {
        if (offset > (outLength - 1)) {
            return false;
        }
        divmod256(&rDiv, &base, &rDiv, &rMod);
        out[offset++] = HEXDIGITS[(uint8_t) LOWER(LOWER(rMod))];
    } while (!zero256(&rDiv));
    out[offset] = '\0';
    reverseString(out, offset);
    return true;
}

/**
 * Format a uint256_t into a string as a signed integer
 *
 * @param[in] number the number to format
 * @param[in] base the radix used in formatting
 * @param[out] out the output buffer
 * @param[in] out_length the length of the output buffer
 * @return whether the formatting was successful or not
 */
bool tostring256_signed(const uint256_t *const number,
                        uint32_t base,
                        char *const out,
                        uint32_t out_length) {
    uint256_t max_unsigned_val;
    uint256_t max_signed_val;
    uint256_t one_val;
    uint256_t two_val;
    uint256_t tmp;

    // showing negative numbers only really makes sense in base 10
    if (base == 10) {
        explicit_bzero(&one_val, sizeof(one_val));
        LOWER(LOWER(one_val)) = 1;
        explicit_bzero(&two_val, sizeof(two_val));
        LOWER(LOWER(two_val)) = 2;

        memset(&max_unsigned_val, 0xFF, sizeof(max_unsigned_val));
        divmod256(&max_unsigned_val, &two_val, &max_signed_val, &tmp);
        if (gt256(number, &max_signed_val))  // negative value
        {
            sub256(&max_unsigned_val, number, &tmp);
            add256(&tmp, &one_val, &tmp);
            out[0] = '-';
            return tostring256(&tmp, base, out + 1, out_length - 1);
        }
    }
    return tostring256(number, base, out, out_length);  // positive value
}

void convertUint64BEto128(const uint8_t *const data, uint32_t length, uint128_t *const target) {
    uint8_t tmp[INT128_LENGTH];
    int64_t value;

    value = u64_from_BE(data, length);
    memset(tmp, ((value < 0) ? 0xff : 0), sizeof(tmp) - length);
    memmove(tmp + sizeof(tmp) - length, data, length);
    readu128BE(tmp, target);
}

void convertUint256BE(const uint8_t *const data, uint32_t length, uint256_t *const target) {
    uint8_t tmp[INT256_LENGTH];

    memset(tmp, 0, sizeof(tmp) - length);
    memmove(tmp + sizeof(tmp) - length, data, length);
    readu256BE(tmp, target);
}

void sub256(const uint256_t *const number1,
            const uint256_t *const number2,
            uint256_t *const target) {
    uint128_t tmp;
    sub128(&UPPER_P(number1), &UPPER_P(number2), &UPPER_P(target));
    sub128(&LOWER_P(number1), &LOWER_P(number2), &tmp);
    if (gt128(&tmp, &LOWER_P(number1))) {
        uint128_t one;
        UPPER(one) = 0;
        LOWER(one) = 1;
        sub128(&UPPER_P(target), &one, &UPPER_P(target));
    }
    sub128(&LOWER_P(number1), &LOWER_P(number2), &LOWER_P(target));
}

void convertUint128BE(const uint8_t *const data, uint32_t length, uint128_t *const target) {
    uint8_t tmp[INT128_LENGTH];

    memset(tmp, 0, sizeof(tmp) - length);
    memmove(tmp + sizeof(tmp) - length, data, length);
    readu128BE(tmp, target);
}

/**
 * Format a uint128_t into a string as a signed integer
 *
 * @param[in] number the number to format
 * @param[in] base the radix used in formatting
 * @param[out] out the output buffer
 * @param[in] out_length the length of the output buffer
 * @return whether the formatting was successful or not
 */
bool tostring128_signed(const uint128_t *const number,
                        uint32_t base,
                        char *const out,
                        uint32_t out_length) {
    uint128_t max_unsigned_val;
    uint128_t max_signed_val;
    uint128_t one_val;
    uint128_t two_val;
    uint128_t tmp;

    // showing negative numbers only really makes sense in base 10
    if (base == 10) {
        explicit_bzero(&one_val, sizeof(one_val));
        LOWER(one_val) = 1;
        explicit_bzero(&two_val, sizeof(two_val));
        LOWER(two_val) = 2;

        memset(&max_unsigned_val, 0xFF, sizeof(max_unsigned_val));
        divmod128(&max_unsigned_val, &two_val, &max_signed_val, &tmp);
        if (gt128(number, &max_signed_val))  // negative value
        {
            sub128(&max_unsigned_val, number, &tmp);
            add128(&tmp, &one_val, &tmp);
            out[0] = '-';
            return tostring128(&tmp, base, out + 1, out_length - 1);
        }
    }
    return tostring128(number, base, out, out_length);  // positive value
}

void sub128(const uint128_t *const number1,
            const uint128_t *const number2,
            uint128_t *const target) {
    UPPER_P(target) = UPPER_P(number1) - UPPER_P(number2) -
                      ((LOWER_P(number1) - LOWER_P(number2)) > LOWER_P(number1));
    LOWER_P(target) = LOWER_P(number1) - LOWER_P(number2);
}