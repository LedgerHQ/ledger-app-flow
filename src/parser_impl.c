/*******************************************************************************
 *  (c) 2019 Zondax GmbH
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

#include <zxmacros.h>
#include <zxformat.h>
#include <json/json_parser.h>
#include "parser_impl.h"
#include "parser_txdef.h"
#include "app_mode.h"
#include "rlp.h"
#include "hdpath.h"

parser_tx_t parser_tx_obj;

#define CHECK_KIND(KIND, EXPECTED_KIND)       \
    if (KIND != EXPECTED_KIND) {              \
        return PARSER_RLP_ERROR_INVALID_KIND; \
    }

parser_error_t parser_init_context(parser_context_t *ctx,
                                   const uint8_t *buffer,
                                   uint16_t bufferSize) {
    ctx->offset = 0;
    ctx->buffer = NULL;
    ctx->bufferLen = 0;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        return PARSER_INIT_CONTEXT_EMPTY;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;
    return PARSER_OK;
}

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    CHECK_PARSER_ERR(parser_init_context(ctx, buffer, bufferSize))
    return PARSER_OK;
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        // General errors
        case PARSER_OK:
            return "No error";
        case PARSER_NO_DATA:
            return "No more data";
        case PARSER_INIT_CONTEXT_EMPTY:
            return "Initialized empty context";
        case PARSER_DISPLAY_IDX_OUT_OF_RANGE:
            return "display_idx_out_of_range";
        case PARSER_DISPLAY_PAGE_OUT_OF_RANGE:
            return "display_page_out_of_range";
        case PARSER_UNEXPECTED_ERROR:
            return "Unexpected internal error";
            // Coin specific
        case PARSER_RLP_ERROR_INVALID_KIND:
            return "parser_rlp_error_invalid_kind";
        case PARSER_RLP_ERROR_INVALID_VALUE_LEN:
            return "parser_rlp_error_invalid_value_len";
        case PARSER_RLP_ERROR_INVALID_FIELD_OFFSET:
            return "parser_rlp_error_invalid_field_offset";
        case PARSER_RLP_ERROR_BUFFER_TOO_SMALL:
            return "parser_rlp_error_buffer_too_small";
        case PARSER_RLP_ERROR_INVALID_PAGE:
            return "parser_rlp_error_invalid_page";
        case PARSER_JSON_INVALID:
            return "parser_json_invalid";
        case PARSER_JSON_INVALID_TOKEN_IDX:
            return "parser_json_invalid_token_idx";
        case PARSER_JSON_TOO_MANY_TOKENS:
            return "parser_json_too_many_tokens";
        case PARSER_JSON_INCOMPLETE_JSON:
            return "parser_json_incomplete_json";
        case PARSER_JSON_UNEXPECTED_ERROR:
            return "parser_json_unex[ected_error";
        case PARSER_JSON_ZERO_TOKENS:
            return "parser_json_zero_tokens";
        case PARSER_UNEXPECTED_TX_VERSION:
            return "tx version is not supported";
        case PARSER_UNEXPECTED_TYPE:
            return "Unexpected data type";
        case PARSER_UNEXPECTED_SCRIPT:
            return "Unexpected script";
        case PARSER_UNEXPECTED_METHOD:
            return "Unexpected method";
        case PARSER_UNEXPECTED_BUFFER_END:
            return "Unexpected buffer end";
        case PARSER_UNEXPECTED_VALUE:
            return "Unexpected value";
        case PARSER_UNEXPECTED_NUMBER_ITEMS:
            return "Unexpected number of items";
        case PARSER_UNEXPECTED_CHARACTERS:
            return "Unexpected characters";
        case PARSER_UNEXPECTED_FIELD:
            return "Unexpected field";
        case PARSER_VALUE_OUT_OF_RANGE:
            return "Value out of range";
        case PARSER_INVALID_ADDRESS:
            return "Invalid address format";
            /////////// Context specific
        case PARSER_CONTEXT_MISMATCH:
            return "context prefix is invalid";
        case PARSER_CONTEXT_UNEXPECTED_SIZE:
            return "context unexpected size";
        case PARSER_CONTEXT_INVALID_CHARS:
            return "context invalid chars";
            // Required fields error
        case PARSER_REQUIRED_NONCE:
            return "Required field nonce";
        case PARSER_REQUIRED_METHOD:
            return "Required field method";
        case PARSER_METADATA_TOO_MANY_HASHES:
            return "Metadata too many hashes";
        case PARSER_METADATA_ERROR:
            return "Metadata unknown error";
        case PARSER_TOO_MANY_ARGUMENTS:
            return "Too many arguments";
        default:
            return "Unrecognized error code";
    }
}

__Z_INLINE char hexDigit(uint8_t v) {
    if (v < 10) {
        return (char) ('0' + v);
    }
    if (v < 16) {
        return (char) ('a' + v - 10);
    }
    return '?';
}

parser_error_t json_validateToken(const parsed_json_t *parsedJson, uint16_t tokenIdx) {
    if (!parsedJson->isValid) {
        return PARSER_JSON_INVALID;
    }

    if (!(tokenIdx < parsedJson->numberOfTokens)) {
        return PARSER_JSON_INVALID_TOKEN_IDX;
    }

    const jsmntok_t token = parsedJson->tokens[tokenIdx];
    if (token.start < 0) {
        return PARSER_JSON_UNEXPECTED_ERROR;
    }

    if (token.end > parsedJson->bufferLen) {
        return PARSER_UNEXPECTED_BUFFER_END;
    }

    return PARSER_OK;
}

parser_error_t json_extractToken(char *outVal,
                                 uint16_t outValLen,
                                 const parsed_json_t *parsedJson,
                                 uint16_t tokenIdx) {
    MEMZERO(outVal, outValLen);
    CHECK_PARSER_ERR(json_validateToken(parsedJson, tokenIdx))

    const jsmntok_t token = parsedJson->tokens[tokenIdx];
    if (token.end - token.start > outValLen - 1) {
        return PARSER_UNEXPECTED_BUFFER_END;
    }

    MEMCPY(outVal, parsedJson->buffer + token.start, token.end - token.start);
    return PARSER_OK;
}

parser_error_t json_matchToken(const parsed_json_t *parsedJson,
                               uint16_t tokenIdx,
                               const char *expectedValue) {
    CHECK_PARSER_ERR(json_validateToken(parsedJson, tokenIdx))

    const jsmntok_t token = parsedJson->tokens[tokenIdx];
    if (token.type != JSMN_STRING) {
        return PARSER_UNEXPECTED_TYPE;
    }

    if (token.end < token.start || strlen(expectedValue) != (size_t)(token.end - token.start)) {
        return PARSER_UNEXPECTED_VALUE;
    }

    if (MEMCMP(expectedValue, parsedJson->buffer + token.start, token.end - token.start) != 0) {
        return PARSER_UNEXPECTED_VALUE;
    }

    return PARSER_OK;
}

parser_error_t json_matchNull(const parsed_json_t *parsedJson, uint16_t tokenIdx) {
    CHECK_PARSER_ERR(json_validateToken(parsedJson, tokenIdx))

    const jsmntok_t token = parsedJson->tokens[tokenIdx];
    if (token.type != JSMN_PRIMITIVE) {
        return PARSER_UNEXPECTED_TYPE;
    }

    if (token.end < token.start || 4 != (size_t)(token.end - token.start)) {
        return PARSER_UNEXPECTED_VALUE;
    }

    if (MEMCMP("null", parsedJson->buffer + token.start, token.end - token.start) != 0) {
        return PARSER_UNEXPECTED_VALUE;
    }

    return PARSER_OK;
}

parser_error_t json_matchKeyValue(const parsed_json_t *parsedJson,
                                  uint16_t tokenIdx,
                                  const char *expectedType,
                                  jsmntype_t jsonType,
                                  uint16_t *valueTokenIdx) {
    CHECK_PARSER_ERR(json_validateToken(parsedJson, tokenIdx))
    if (parsedJson->tokens[tokenIdx].type != JSMN_OBJECT) {
        return PARSER_JSON_INVALID;
    }

    uint16_t objectElements = 0;
    CHECK_PARSER_ERR(object_get_element_count(parsedJson, tokenIdx, &objectElements));
    if (objectElements != 2) {
        return PARSER_JSON_INVALID;
    }

    uint16_t keyTokenIdx = 0;
    CHECK_PARSER_ERR(object_get_value(parsedJson, tokenIdx, "type", &keyTokenIdx));
    CHECK_PARSER_ERR(object_get_value(parsedJson, tokenIdx, "value", valueTokenIdx));

    // Type key/value
    CHECK_PARSER_ERR(json_matchToken(parsedJson, keyTokenIdx, expectedType))
    if (parsedJson->tokens[*valueTokenIdx].type != jsonType) {
        return PARSER_JSON_INVALID;
    }
    return PARSER_OK;
}

// valueTokenIdx is JSON_MATCH_VALUE_IDX_NONE if the optional is null
parser_error_t json_matchOptionalKeyValue(const parsed_json_t *parsedJson,
                                          uint16_t tokenIdx,
                                          const char *expectedType,
                                          jsmntype_t jsonType,
                                          uint16_t *valueTokenIdx) {
    CHECK_PARSER_ERR(json_validateToken(parsedJson, tokenIdx))
    if (parsedJson->tokens[tokenIdx].type != JSMN_OBJECT) {
        return PARSER_JSON_INVALID;
    }

    uint16_t objectElements = 0;
    CHECK_PARSER_ERR(object_get_element_count(parsedJson, tokenIdx, &objectElements));
    if (objectElements != 2) {
        return PARSER_JSON_INVALID;
    }

    uint16_t innerKeyTokenIdx = 0;
    uint16_t innerValueTokenIdx = 0;
    CHECK_PARSER_ERR(object_get_value(parsedJson, tokenIdx, "type", &innerKeyTokenIdx));
    CHECK_PARSER_ERR(object_get_value(parsedJson, tokenIdx, "value", &innerValueTokenIdx));
    CHECK_PARSER_ERR(json_matchToken(parsedJson, innerKeyTokenIdx, (char *) "Optional"))

    if (parsedJson->tokens[innerValueTokenIdx].type == JSMN_PRIMITIVE) {  // optional null
        CHECK_PARSER_ERR(json_matchNull(parsedJson, innerValueTokenIdx))
        *valueTokenIdx = JSON_MATCH_VALUE_IDX_NONE;
        return PARSER_OK;
    }

    if (parsedJson->tokens[innerValueTokenIdx].type == JSMN_OBJECT) {  // optional not null
        return json_matchKeyValue(parsedJson,
                                  innerValueTokenIdx,
                                  expectedType,
                                  jsonType,
                                  valueTokenIdx);
    }

    return PARSER_JSON_INVALID;
}

parser_error_t json_matchArbitraryKeyValue(const parsed_json_t *parsedJson,
                                           uint16_t tokenIdx,
                                           jsmntype_t *valueJsonType,
                                           uint16_t *keyTokenIdx,
                                           uint16_t *valueTokenIdx) {
    CHECK_PARSER_ERR(json_validateToken(parsedJson, tokenIdx))
    if (parsedJson->tokens[tokenIdx].type != JSMN_OBJECT) {
        return PARSER_JSON_INVALID;
    }
    uint16_t objectElements = 0;
    CHECK_PARSER_ERR(object_get_element_count(parsedJson, tokenIdx, &objectElements));
    if (objectElements != 2) {
        return PARSER_JSON_INVALID;
    }

    CHECK_PARSER_ERR(object_get_value(parsedJson, tokenIdx, "type", keyTokenIdx));
    CHECK_PARSER_ERR(object_get_value(parsedJson, tokenIdx, "value", valueTokenIdx));

    if (parsedJson->tokens[*keyTokenIdx].type != JSMN_STRING) {
        return PARSER_UNEXPECTED_TYPE;
    }
    *valueJsonType = parsedJson->tokens[*valueTokenIdx].type;

    return PARSER_OK;
}

parser_error_t formatStrUInt8AsHex(const char *decStr, char *hexStr) {
    uint16_t decLen = strnlen(decStr, 5);
    if (decLen > 3 || decLen == 0) {
        return PARSER_UNEXPECTED_BUFFER_END;
    }

    uint16_t v = 0;
    uint16_t m = 1;
    for (int16_t i = decLen - 1; i >= 0; i--) {
        if (decStr[i] < '0' || decStr[i] > '9') {
            return PARSER_UNEXPECTED_VALUE;
        }
        v += (decStr[i] - '0') * m;
        m *= 10;
    }

    hexStr[0] = hexDigit(v / 16);
    hexStr[1] = hexDigit(v % 16);
    hexStr[2] = 0;
    return PARSER_OK;
}

parser_error_t _readScript(parser_context_t *c, flow_script_hash_t *s) {
    rlp_kind_e kind;
    parser_context_t script;
    uint32_t bytesConsumed;

    CHECK_PARSER_ERR(rlp_decode(c, &script, &kind, &bytesConsumed));
    CTX_CHECK_AND_ADVANCE(c, bytesConsumed)
    CHECK_KIND(kind, RLP_KIND_STRING)

    MEMZERO(s->digest, sizeof(s->digest));
    zxerr_t err = sha256(script.buffer, script.bufferLen, s->digest);
    if (err != zxerr_ok) {
        return PARSER_UNEXPECTED_ERROR;
    }

    return PARSER_OK;
}

parser_error_t _readArguments(parser_context_t *c, flow_argument_list_t *v) {
    rlp_kind_e kind;
    uint32_t bytesConsumed;

    MEMZERO(v, sizeof(flow_argument_list_t));

    // Consume external list
    CHECK_PARSER_ERR(rlp_decode(c, &v->ctx, &kind, &bytesConsumed));
    CTX_CHECK_AND_ADVANCE(c, bytesConsumed)
    CHECK_KIND(kind, RLP_KIND_LIST)

    v->argCount = 0;
    while (v->ctx.offset < v->ctx.bufferLen) {
        if (v->argCount >= PARSER_MAX_ARGCOUNT) {
            return PARSER_UNEXPECTED_NUMBER_ITEMS;
        }
        CHECK_PARSER_ERR(rlp_decode(&v->ctx, &v->argCtx[v->argCount], &kind, &bytesConsumed))
        CTX_CHECK_AND_ADVANCE(&v->ctx, bytesConsumed)
        CHECK_KIND(kind, RLP_KIND_STRING)
        v->argCount++;
    }
    v->ctx.offset = 0;

    return PARSER_OK;
}

parser_error_t _readReferenceBlockId(parser_context_t *c, flow_reference_block_id_t *v) {
    rlp_kind_e kind;
    uint32_t bytesConsumed;

    MEMZERO(v, sizeof(flow_reference_block_id_t));

    // Consume external list
    CHECK_PARSER_ERR(rlp_decode(c, &v->ctx, &kind, &bytesConsumed));
    CTX_CHECK_AND_ADVANCE(c, bytesConsumed)
    CHECK_KIND(kind, RLP_KIND_STRING)
    return PARSER_OK;
}

parser_error_t _readGasLimit(parser_context_t *c, flow_gaslimit_t *v) {
    rlp_kind_e kind;
    uint32_t bytesConsumed;
    parser_context_t ctx_local;

    MEMZERO(v, sizeof(flow_gaslimit_t));

    CHECK_PARSER_ERR(rlp_decode(c, &ctx_local, &kind, &bytesConsumed));
    CTX_CHECK_AND_ADVANCE(c, bytesConsumed)
    CHECK_KIND(kind, RLP_KIND_STRING)

    CHECK_PARSER_ERR(rlp_readUInt64(&ctx_local, kind, v))

    return PARSER_OK;
}

parser_error_t _readProposalKeyAddress(parser_context_t *c, flow_proposal_key_address_t *v) {
    rlp_kind_e kind;
    uint32_t bytesConsumed;

    MEMZERO(v, sizeof(flow_proposal_key_address_t));

    CHECK_PARSER_ERR(rlp_decode(c, &v->ctx, &kind, &bytesConsumed));
    CTX_CHECK_AND_ADVANCE(c, bytesConsumed)
    CHECK_KIND(kind, RLP_KIND_STRING)
    return PARSER_OK;
}

parser_error_t _readProposalKeyId(parser_context_t *c, flow_proposal_keyid_t *v) {
    rlp_kind_e kind;
    uint32_t bytesConsumed;
    parser_context_t ctx_local;

    MEMZERO(v, sizeof(flow_proposal_keyid_t));

    CHECK_PARSER_ERR(rlp_decode(c, &ctx_local, &kind, &bytesConsumed));
    CTX_CHECK_AND_ADVANCE(c, bytesConsumed)
    CHECK_KIND(kind, RLP_KIND_STRING)

    CHECK_PARSER_ERR(rlp_readUInt64(&ctx_local, kind, v))

    return PARSER_OK;
}

parser_error_t _readProposalKeySequenceNumber(parser_context_t *c,
                                              flow_proposal_key_sequence_number_t *v) {
    rlp_kind_e kind;
    uint32_t bytesConsumed;
    parser_context_t ctx_local;

    MEMZERO(v, sizeof(flow_proposal_key_sequence_number_t));

    CHECK_PARSER_ERR(rlp_decode(c, &ctx_local, &kind, &bytesConsumed));
    CTX_CHECK_AND_ADVANCE(c, bytesConsumed)
    CHECK_KIND(kind, RLP_KIND_STRING)

    CHECK_PARSER_ERR(rlp_readUInt64(&ctx_local, kind, v))

    return PARSER_OK;
}

parser_error_t _readPayer(parser_context_t *c, flow_payer_t *v) {
    rlp_kind_e kind;
    uint32_t bytesConsumed;

    MEMZERO(v, sizeof(flow_payer_t));

    CHECK_PARSER_ERR(rlp_decode(c, &v->ctx, &kind, &bytesConsumed));
    CTX_CHECK_AND_ADVANCE(c, bytesConsumed)
    CHECK_KIND(kind, RLP_KIND_STRING)
    return PARSER_OK;
}

parser_error_t _readProposalAuthorizer(parser_context_t *c, flow_proposal_authorizer_t *v) {
    rlp_kind_e kind;
    uint32_t bytesConsumed;

    MEMZERO(v, sizeof(flow_proposal_authorizer_t));

    CHECK_PARSER_ERR(rlp_decode(c, &v->ctx, &kind, &bytesConsumed));
    CTX_CHECK_AND_ADVANCE(c, bytesConsumed)
    CHECK_KIND(kind, RLP_KIND_STRING)

    return PARSER_OK;
}

parser_error_t _readProposalAuthorizers(parser_context_t *c, flow_proposal_authorizers_t *v) {
    rlp_kind_e kind;
    uint32_t bytesConsumed;

    MEMZERO(v, sizeof(flow_proposal_authorizers_t));

    CHECK_PARSER_ERR(rlp_decode(c, &v->ctx, &kind, &bytesConsumed));
    CTX_CHECK_AND_ADVANCE(c, bytesConsumed)
    CHECK_KIND(kind, RLP_KIND_LIST)

    while (v->ctx.offset < v->ctx.bufferLen) {
        if (v->authorizer_count >= 16) {
            return PARSER_UNEXPECTED_NUMBER_ITEMS;
        }

        CHECK_PARSER_ERR(_readProposalAuthorizer(&v->ctx, &v->authorizer[v->authorizer_count]))

        v->authorizer_count++;
    }
    v->ctx.offset = 0;

    return PARSER_OK;
}

parser_error_t _read(parser_context_t *c, parser_tx_t *v) {
    rlp_kind_e kind;
    uint32_t bytesConsumed;

    parser_context_t ctx_rootList;
    parser_context_t ctx_rootInnerList;

    // Consume external list
    CHECK_PARSER_ERR(rlp_decode(c, &ctx_rootList, &kind, &bytesConsumed))
    CTX_CHECK_AND_ADVANCE(c, bytesConsumed)
    CHECK_KIND(kind, RLP_KIND_LIST)
    if (bytesConsumed != c->bufferLen) {
        // root list should consume the complete buffer
        return PARSER_UNEXPECTED_BUFFER_END;
    }

    // Consume external list
    CHECK_PARSER_ERR(rlp_decode(&ctx_rootList, &ctx_rootInnerList, &kind, &bytesConsumed))
    CTX_CHECK_AND_ADVANCE(&ctx_rootList, bytesConsumed)
    CHECK_KIND(kind, RLP_KIND_LIST)

    // Go through the inner list
    CHECK_PARSER_ERR(_readScript(&ctx_rootInnerList, &v->hash))
    CHECK_PARSER_ERR(_readArguments(&ctx_rootInnerList, &v->arguments))
    CHECK_PARSER_ERR(_readReferenceBlockId(&ctx_rootInnerList, &v->referenceBlockId))
    CHECK_PARSER_ERR(_readGasLimit(&ctx_rootInnerList, &v->gasLimit))
    CHECK_PARSER_ERR(_readProposalKeyAddress(&ctx_rootInnerList, &v->proposalKeyAddress))
    CHECK_PARSER_ERR(_readProposalKeyId(&ctx_rootInnerList, &v->proposalKeyId))
    CHECK_PARSER_ERR(
        _readProposalKeySequenceNumber(&ctx_rootInnerList, &v->proposalKeySequenceNumber))
    CHECK_PARSER_ERR(_readPayer(&ctx_rootInnerList, &v->payer))
    CHECK_PARSER_ERR(_readProposalAuthorizers(&ctx_rootInnerList, &v->authorizers))

    if (ctx_rootInnerList.offset != ctx_rootInnerList.bufferLen) {
        // ctx_rootInnerList should be consumed completely
        return PARSER_UNEXPECTED_BUFFER_END;
    }

    return PARSER_OK;
}

parser_error_t _validateTx(__Z_UNUSED const parser_context_t *c, __Z_UNUSED const parser_tx_t *v) {
    // Placeholder to run any coin specific validation
    return PARSER_OK;
}

parser_error_t _countArgumentItems(const flow_argument_list_t *v,
                                   uint8_t argumentIndex,
                                   uint8_t min_number_of_items,
                                   uint8_t max_number_of_items,
                                   uint8_t *number_of_items) {
    *number_of_items = 0;
    parsed_json_t parsedJson = {false};

    if (argumentIndex >= v->argCount) {
        return PARSER_UNEXPECTED_FIELD;
    }

    const parser_context_t argCtx = v->argCtx[argumentIndex];
    CHECK_PARSER_ERR(json_parse(&parsedJson, (char *) argCtx.buffer, argCtx.bufferLen));

    // Get number of items
    uint16_t internalTokenElementIdx;
    CHECK_PARSER_ERR(
        json_matchKeyValue(&parsedJson, 0, (char *) "Array", JSMN_ARRAY, &internalTokenElementIdx));
    uint16_t arrayTokenCount;
    CHECK_PARSER_ERR(
        array_get_element_count(&parsedJson, internalTokenElementIdx, &arrayTokenCount));
    if (arrayTokenCount < min_number_of_items || arrayTokenCount > max_number_of_items) {
        return PARSER_UNEXPECTED_NUMBER_ITEMS;
    }

    *number_of_items = arrayTokenCount;
    return PARSER_OK;
}

void checkAddressUsedInTx() {
    addressUsedInTx = 0;
    uint16_t authCount = parser_tx_obj.authorizers.authorizer_count;
    for (uint16_t i = 0; i < (uint16_t)(authCount + 2); i++) {  //+2 for proposer and payer
        parser_context_t *ctx = NULL;
        if (i > authCount) ctx = &parser_tx_obj.payer.ctx;
        if (i == authCount) ctx = &parser_tx_obj.proposalKeyAddress.ctx;
        if (i < authCount) ctx = &parser_tx_obj.authorizers.authorizer[i].ctx;

        _Static_assert(sizeof(address_to_display) == ACCOUNT_SIZE, "Incorrect address length");
        if (ctx->bufferLen == ACCOUNT_SIZE) {
            if (!MEMCMP(ctx->buffer, &address_to_display, sizeof(address_to_display))) {
                addressUsedInTx = 1;
                break;
            }
        }
    }
}

parser_error_t parseMetadata() {
    MEMZERO(&parser_tx_obj.metadata, sizeof(parser_tx_obj.metadata));
    CHECK_PARSER_ERR(parseTxMetadata(parser_tx_obj.hash.digest, &parser_tx_obj.metadata));
    return PARSER_OK;
}
