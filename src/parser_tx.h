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

#ifdef __cplusplus
extern "C" {
#endif

#include "parser_impl.h"
#include "crypto.h"
#include "jsmn.h"

const char *parser_getErrorDescription(parser_error_t err);

//// parses a tx buffer
parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen);

//// verifies tx fields
parser_error_t parser_validate(const parser_context_t *ctx);

//// returns the number of items in the current parsing context
parser_error_t parser_getNumItems(__Z_UNUSED const parser_context_t *ctx, uint8_t *num_items);

// retrieves a readable output for each field / page
parser_error_t parser_getItem(__Z_UNUSED const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey,
                              uint16_t outKeyLen,
                              char *outVal,
                              uint16_t outValLen,
                              uint8_t pageIdx,
                              uint8_t *pageCount);

#ifdef TEST
////for testing purposes
parser_error_t parser_printArgument(const flow_argument_list_t *v,
                                    uint8_t argIndex,
                                    const char *expectedType,
                                    jsmntype_t jsonType,
                                    char *outVal,
                                    uint16_t outValLen,
                                    uint8_t pageIdx,
                                    uint8_t *pageCount);

parser_error_t parser_printOptionalArgument(const flow_argument_list_t *v,
                                            uint8_t argIndex,
                                            const char *expectedType,
                                            jsmntype_t jsonType,
                                            char *outVal,
                                            uint16_t outValLen,
                                            uint8_t pageIdx,
                                            uint8_t *pageCount);

parser_error_t parser_printArgumentArray(const flow_argument_list_t *v,
                                         uint8_t argIndex,
                                         uint8_t arrayIndex,
                                         const char *expectedType,
                                         jsmntype_t jsonType,
                                         char *outVal,
                                         uint16_t outValLen,
                                         uint8_t pageIdx,
                                         uint8_t *pageCount);

parser_error_t parser_printHashAlgo(const flow_argument_list_t *v,
                                    uint8_t argIndex,
                                    const char *expectedType,
                                    jsmntype_t jsonType,
                                    char *outVal,
                                    uint16_t outValLen,
                                    uint8_t pageIdx,
                                    uint8_t *pageCount);

parser_error_t parser_printSignatureAlgo(const flow_argument_list_t *v,
                                         uint8_t argIndex,
                                         const char *expectedType,
                                         jsmntype_t jsonType,
                                         char *outVal,
                                         uint16_t outValLen,
                                         uint8_t pageIdx,
                                         uint8_t *pageCount);

parser_error_t parser_printNodeRole(const flow_argument_list_t *v,
                                    uint8_t argIndex,
                                    const char *expectedType,
                                    jsmntype_t jsonType,
                                    char *outVal,
                                    uint16_t outValLen,
                                    uint8_t pageIdx,
                                    uint8_t *pageCount);

parser_error_t parser_printArbitraryArgument(const flow_argument_list_t *v,
                                             uint8_t argIndex,
                                             char *outKey,
                                             uint16_t outKeyLen,
                                             char *outVal,
                                             uint16_t outValLen,
                                             uint8_t pageIdx,
                                             uint8_t *pageCount);
#endif
