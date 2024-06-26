/*******************************************************************************
 *   (c) 2020 Zondax GmbH
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

#ifdef __cplusplus
extern "C" {
#endif

#include "zxerror.h"
#include "coin.h"

#define SLOT_COUNT 64

typedef struct {
    flow_account_t account;
    hd_path_t path;
    uint16_t options;
} account_slot_t;

typedef struct {
    account_slot_t slot[SLOT_COUNT];
} slot_store_t;

extern account_slot_t tmp_slot;
extern uint8_t tmp_slotIdx;

/// Return the number of items in the address view
zxerr_t slot_getNumItems(uint8_t *num_items);

/// Gets an specific item from the slot view (including paging)
zxerr_t slot_getItem(int8_t displayIdx,
                     char *outKey,
                     uint16_t outKeyLen,
                     char *outVal,
                     uint16_t outValLen,
                     uint8_t pageIdx,
                     uint8_t *pageCount);

// Updates the slot
void app_slot_setSlot();

// Gets status of all slots
zxerr_t slot_status(uint8_t *out, uint16_t outLen);

// Gets data from he slot
zxerr_t slot_getSlot(uint8_t slotIndex, account_slot_t *out);

// Parses and stores buffer data
zxerr_t slot_parseSlot(uint8_t *buffer, uint16_t bufferLen);

zxerr_t slot_serializeSlot(const account_slot_t *slot, uint8_t *buffer, uint16_t *bufferLen);

void loadHdPathAndAddressFromSlot();

void loadAddressCompareHdPathFromSlot();

#ifdef __cplusplus
}
#endif
