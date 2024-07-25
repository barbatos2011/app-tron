#include <string.h>

#include "common_utils.h"
#include "plugin_utils.h"

void copy_address(uint8_t* dst, const uint8_t* parameter, uint8_t dst_size) {
    uint8_t copy_size = MIN(dst_size, ADDRESS_SIZE);
    memmove(dst, parameter + PARAMETER_LENGTH - copy_size, copy_size);
}

void copy_parameter(uint8_t* dst, const uint8_t* parameter, uint8_t dst_size) {
    uint8_t copy_size = MIN(dst_size, PARAMETER_LENGTH);
    memmove(dst, parameter, copy_size);
}

bool find_selector(uint32_t selector, const uint32_t* array, size_t size, size_t* idx) {
    for (size_t i = 0; i < size; ++i) {
        if (selector == array[i]) {
            if (idx != NULL) *idx = i;
            return true;
        }
    }
    return false;
}
