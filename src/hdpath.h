#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "coin.h"
#include "zxformat.h"

extern hd_path_t hdPath;
extern uint16_t cryptoOptions;

typedef enum {
    SHOW_ADDRESS_NONE = 0,           // result undefined
    SHOW_ADDRESS_YES,                // we have address
    SHOW_ADDRESS_YES_HASH_MISMATCH,  // we have the address, but hashes do not match
    SHOW_ADDRESS_EMPTY_SLOT,         // slot 0 is empty
    SHOW_ADDRESS_HDPATHS_NOT_EQUAL,  // hdpath on slot 0 does not equal hdPath (or curves do not
                                     // match)
    SHOW_ADDRESS_ERROR,              // error occurred - In menu we cannot handle errors by throwing
} show_address_t;
extern show_address_t show_address;
extern flow_account_t address_to_display;
extern uint8_t addressUsedInTx;

#define SECP256R1_STRING       " SECP256R1"
#define SECP256K1_STRING       " SECP256K1"
#define SHA2_256_STRING        " SHA-2"
#define SHA3_256_STRING        " SHA-3"
#define DESIRED_HD_PATH_LENGTH 17

__Z_INLINE uint32_t add_options_to_path(char *s, uint32_t max, uint16_t options) {
    uint32_t written = strlen(s);
    uint8_t curve = (options >> 8) & 0xFF;
    uint8_t hash = options & 0xFF;

    // For better UI if path is short, we add one or two spaces
    if (written < DESIRED_HD_PATH_LENGTH && max >= DESIRED_HD_PATH_LENGTH + 1) {
        for (; written <= DESIRED_HD_PATH_LENGTH; written++) {
            s[written] = ' ';
        }
        s[written] = 0;
        written--;
    }

    if (curve != 0) {
        if (written + sizeof(SECP256R1_STRING) > max || written + sizeof(SECP256K1_STRING) > max) {
            snprintf(s, max, "ERROR");
            return 0;
        }
        switch (curve) {
            case 0x02:
                snprintf(s + written, max, SECP256R1_STRING);
                written += sizeof(SECP256R1_STRING) - 1;
                break;
            case 0x03:
                snprintf(s + written, max, SECP256K1_STRING);
                written += sizeof(SECP256K1_STRING) - 1;
                break;
            default:
                snprintf(s, max, "ERROR");
                return 0;
        }
    }

    if (hash != 0) {
        if (written + sizeof(SHA2_256_STRING) > max || written + sizeof(SHA3_256_STRING) > max) {
            snprintf(s, max, "ERROR");
            return 0;
        }
        switch (hash) {
            case 0x01:
                snprintf(s + written, max, SHA2_256_STRING);
                written += sizeof(SHA2_256_STRING) - 1;
                break;
            case 0x03:
                snprintf(s + written, max, SHA3_256_STRING);
                written += sizeof(SHA3_256_STRING) - 1;
                break;
            default:
                snprintf(s, max, "ERROR");
                return 0;
        }
    }
    return written;
}

__Z_INLINE void path_options_to_string(char *s,
                                       uint32_t max,
                                       const uint32_t *path,
                                       uint8_t pathLen,
                                       uint16_t crypto_options) {
    bip32_to_str(s, max, path, pathLen);
    add_options_to_path(s, max, crypto_options);
}

#ifdef __cplusplus
}
#endif
