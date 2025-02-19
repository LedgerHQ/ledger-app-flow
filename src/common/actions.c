/*******************************************************************************
 *   (c) 2016 Ledger
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

#include "actions.h"

uint16_t action_addr_len;

// UTF-8 encoding of "FLOW-V0.0-transaction" padded with zeros to 32 bytes
const uint8_t TX_DOMAIN_TAG_TRANSACTION[DOMAIN_TAG_LENGTH] = {
    0x46, 0x4C, 0x4F, 0x57, 0x2D, 0x56, 0x30, 0x2E, 0x30, 0x2D, 0x74, 0x72, 0x61, 0x6E, 0x73, 0x61,
    0x63, 0x74, 0x69, 0x6F, 0x6E, 0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
};

// UTF-8 encoding of "FLOW-V0.0-user" padded with zeros to 32 bytes
const uint8_t TX_DOMAIN_TAG_MESSAGE[DOMAIN_TAG_LENGTH] = {
    0x46, 0x4C, 0x4F, 0x57, 0x2D, 0x56, 0x30, 0x2E, 0x30, 0x2D, 0x75, 0x73, 0x65, 0x72, 0, 0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, 0,
};
