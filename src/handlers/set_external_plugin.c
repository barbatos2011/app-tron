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
#include <string.h>
#include <stdint.h>

#include "io.h"
#include "parse.h"
#include "os_io_seproxyhal.h"
#include "public_keys.h"
#include "app_errors.h"
#include "tron_plugin_helper.h"

int handleSetExternalPlugin(uint8_t p1,
                            uint8_t p2,
                            const uint8_t *workBuffer,
                            uint16_t dataLength) {
    UNUSED(p1);
    UNUSED(p2);
    PRINTF("Handling set Plugin\n");
    uint8_t hash[HASH_SIZE];
    cx_ecfp_public_key_t tokenKey;
    uint8_t pluginNameLength = *workBuffer;
    PRINTF("plugin Name Length: %d\n", pluginNameLength);
    const size_t payload_size = 1 + pluginNameLength + ADDRESS_SIZE + SELECTOR_SIZE;
    // const size_t payload_size = 1 + pluginNameLength + 20 + SELECTOR_SIZE;

    if (dataLength <= payload_size) {
        PRINTF("data too small: expected at least %d got %d\n", payload_size, dataLength);
        return io_send_sw(E_INCORRECT_LENGTH);
    }

    if (pluginNameLength + 1 > sizeof(dataContext.tokenContext.pluginName)) {
        PRINTF("name length too big: expected max %d, got %d\n",
               sizeof(dataContext.tokenContext.pluginName),
               pluginNameLength + 1);
        return io_send_sw(E_INCORRECT_LENGTH);
    }

    // check Ledger's signature over the payload
    cx_hash_sha256(workBuffer, payload_size, hash, sizeof(hash));
    CX_ASSERT(cx_ecfp_init_public_key_no_throw(CX_CURVE_256K1,
                                               LEDGER_SIGNATURE_PUBLIC_KEY,
                                               sizeof(LEDGER_SIGNATURE_PUBLIC_KEY),
                                               &tokenKey));
    if (!cx_ecdsa_verify_no_throw(&tokenKey,
                                  hash,
                                  sizeof(hash),
                                  workBuffer + payload_size,
                                  dataLength - payload_size)) {
        // #ifndef HAVE_BYPASS_SIGNATURES
        PRINTF("Invalid plugin signature %.*H\n",
               dataLength - payload_size,
               workBuffer + payload_size);
        return io_send_sw(E_INCORRECT_DATA);
        // #endif
    }

    // move on to the rest of the payload parsing
    workBuffer++;
    memmove(dataContext.tokenContext.pluginName, workBuffer, pluginNameLength);
    dataContext.tokenContext.pluginName[pluginNameLength] = '\0';
    workBuffer += pluginNameLength;

    PRINTF("Check external plugin %s\n", dataContext.tokenContext.pluginName);

#ifndef PLUGIN_TEST_LOCAL
    // Check if the plugin is present on the device
    uint32_t params[2];
    params[0] = (uint32_t) dataContext.tokenContext.pluginName;
    params[1] = TRON_PLUGIN_CHECK_PRESENCE;
    BEGIN_TRY {
        TRY {
            os_lib_call(params);
        }
        CATCH_OTHER(e) {
            PRINTF("%s external plugin is not present\n", dataContext.tokenContext.pluginName);
            memset(dataContext.tokenContext.pluginName,
                   0,
                   sizeof(dataContext.tokenContext.pluginName));
            return io_send_sw(E_PLUGIN_NOT_FOUND);
        }
        FINALLY {
        }
    }
    END_TRY;
#endif
    PRINTF("Plugin found\n");

    memmove(dataContext.tokenContext.contractAddress, workBuffer, ADDRESS_SIZE);
    workBuffer += ADDRESS_SIZE;
    memmove(dataContext.tokenContext.methodSelector, workBuffer, SELECTOR_SIZE);

    return io_send_sw(E_OK);
}