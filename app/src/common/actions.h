/*******************************************************************************
*   (c) 2019 Zondax GmbH
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

#include <stdint.h>
#include "crypto.h"
#include "tx.h"
#include "apdu_codes.h"
#include <os_io_seproxyhal.h>
#include "coin.h"

#define GET_PUB_KEY_RESPONSE_LENGTH (3 * SECP256_PK_LEN)

__Z_INLINE void app_sign() {
    const uint8_t *message = get_signable();
    const uint16_t messageLength = get_signable_length();

    uint16_t replyLen = 0;
    zxerr_t err = crypto_sign(hdPath, message, messageLength, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, &replyLen);

    if (err != zxerr_ok || replyLen == 0) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        set_code(G_io_apdu_buffer, replyLen, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, replyLen + 2);
    }
}

__Z_INLINE void app_reject() {
    set_code(G_io_apdu_buffer, 0, APDU_CODE_COMMAND_NOT_ALLOWED);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE void app_reply_address() {
    set_code(G_io_apdu_buffer, GET_PUB_KEY_RESPONSE_LENGTH, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, GET_PUB_KEY_RESPONSE_LENGTH + 2);
}

__Z_INLINE void app_reply_error() {
    set_code(G_io_apdu_buffer, 0, APDU_CODE_DATA_INVALID);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}
