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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "json/json_parser.h"
#include "parser_tx.h"

const char *token2 = "{\"type\":\"Optional\",\"value\":null}";
const char *token3 = "{\"type\":\"Optional\",\"value\":{\"type\":\"UFix64\",\"value\":\"545.77\"}}";

const char *token4 =
    "{\"type\":\"Optional\",\"value\":{\"type\": \"Array\",\"value\":"
    "[{\"type\":\"String\",\"value\":"
    "\"f845b8406e4f43f79d3c1d8cacb3d5f3e7aeedb29feaeb4559fdb71a97e2fd0438565310e87670035d83bc10fe67"
    "fe314dba5363c81654595d64884b1ecad1512a64e65e020164\"}]}}";
const char *token5 =
    "{\"type\":\"Optional\",\"value\":{\"type\": \"Array\",\"value\":"
    "[{\"type\":\"String\",\"value\":"
    "\"e845b8406e4f43f79d3c1d8cacb3d5f3e7aeedb29feaeb4559fdb71a97e2fd0438565310e87670035d83bc10fe67"
    "fe314dba5363c81654595d64884b1ecad1512a64e65e020164\"},"
    "{\"type\":\"String\",\"value\":"
    "\"d845b8406e4f43f79d3c1d8cacb3d5f3e7aeedb29feaeb4559fdb71a97e2fd0438565310e87670035d83bc10fe67"
    "fe314dba5363c81654595d64884b1ecad1512a64e65e020164\"}]}}";
const char *token6 = "{\"type\":\"UFix64\",\"value\":\"545.77\"}";
const char *token7 =
    "{\"type\": \"Array\",\"value\":"
    "[{\"type\":\"String\",\"value\":"
    "\"e845b8406e4f43f79d3c1d8cacb3d5f3e7aeedb29feaeb4559fdb71a97e2fd0438565310e87670035d83bc10fe67"
    "fe314dba5363c81654595d64884b1ecad1512a64e65e020164\"},"
    "{\"type\":\"String\",\"value\":"
    "\"d845b8406e4f43f79d3c1d8cacb3d5f3e7aeedb29feaeb4559fdb71a97e2fd0438565310e87670035d83bc10fe67"
    "fe314dba5363c81654595d64884b1ecad1512a64e65e020164\"}]}";

const char *token2b = "{\"value\":null,\"type\":\"Optional\"}";
const char *token3b =
    "{\"value\":{\"value\":\"545.77\",\"type\":\"UFix64\"},\"type\":\"Optional\"}";

const char *token4b =
    "{\"value\":{\"type\": \"Array\",\"value\":"
    "[{\"value\":"
    "\"f845b8406e4f43f79d3c1d8cacb3d5f3e7aeedb29feaeb4559fdb71a97e2fd0438565310e87670035d83bc10fe67"
    "fe314dba5363c81654595d64884b1ecad1512a64e65e020164\",\"type\":\"String\"}]},"
    "\"type\":\"Optional\"}";
const char *token5b =
    "{\"value\":{\"type\": \"Array\",\"value\":"
    "[{\"value\":"
    "\"e845b8406e4f43f79d3c1d8cacb3d5f3e7aeedb29feaeb4559fdb71a97e2fd0438565310e87670035d83bc10fe67"
    "fe314dba5363c81654595d64884b1ecad1512a64e65e020164\",\"type\":\"String\"},"
    "{\"value\":"
    "\"d845b8406e4f43f79d3c1d8cacb3d5f3e7aeedb29feaeb4559fdb71a97e2fd0438565310e87670035d83bc10fe67"
    "fe314dba5363c81654595d64884b1ecad1512a64e65e020164\",\"type\":\"String\"}]},"
    "\"type\":\"Optional\"}";
const char *token6b = "{\"value\":\"545.77\",\"type\":\"UFix64\"}";
const char *token7b =
    "{\"value\":"
    "[{\"type\":\"String\",\"value\":"
    "\"e845b8406e4f43f79d3c1d8cacb3d5f3e7aeedb29feaeb4559fdb71a97e2fd0438565310e87670035d83bc10fe67"
    "fe314dba5363c81654595d64884b1ecad1512a64e65e020164\"},"
    "{\"type\":\"String\",\"value\":"
    "\"d845b8406e4f43f79d3c1d8cacb3d5f3e7aeedb29feaeb4559fdb71a97e2fd0438565310e87670035d83bc10fe67"
    "fe314dba5363c81654595d64884b1ecad1512a64e65e020164\"}],"
    "\"type\": \"Array\"}";

const char *dummy = "";
const char *token2c = "{\"value\":\"1\",\"type\":\"UInt8\"}";
const char *token3c = "{\"value\":\"2\",\"type\":\"UInt8\"}";
const char *token4c = "{\"value\":\"3\",\"type\":\"UInt8\"}";
const char *token5c = "{\"value\":\"4\",\"type\":\"UInt8\"}";
const char *token6c = "{\"value\":\"5\",\"type\":\"UInt8\"}";
const char *token7c = "{\"value\":\"6\",\"type\":\"UInt8\"}";

flow_argument_list_t arg_list;
flow_argument_list_t arg_list_b;
flow_argument_list_t arg_list_c;

void createArgList() {
    const parser_context_t context0 = {(const uint8_t *) dummy, strlen(dummy), 0};
    const parser_context_t context2 = {(const uint8_t *) token2, strlen(token2), 0};
    const parser_context_t context3 = {(const uint8_t *) token3, strlen(token3), 0};
    const parser_context_t context4 = {(const uint8_t *) token4, strlen(token4), 0};
    const parser_context_t context5 = {(const uint8_t *) token5, strlen(token5), 0};
    const parser_context_t context6 = {(const uint8_t *) token6, strlen(token6), 0};
    const parser_context_t context7 = {(const uint8_t *) token7, strlen(token7), 0};
    flow_argument_list_t new_arg_list = {
        context0,
        {context2, context3, context4, context5, context6, context7},
        6};
    memcpy(&arg_list, &new_arg_list, sizeof(arg_list));

    const parser_context_t context0b = {(const uint8_t *) dummy, strlen(dummy), 0};
    const parser_context_t context2b = {(const uint8_t *) token2b, strlen(token2b), 0};
    const parser_context_t context3b = {(const uint8_t *) token3b, strlen(token3b), 0};
    const parser_context_t context4b = {(const uint8_t *) token4b, strlen(token4b), 0};
    const parser_context_t context5b = {(const uint8_t *) token5b, strlen(token5b), 0};
    const parser_context_t context6b = {(const uint8_t *) token6b, strlen(token6b), 0};
    const parser_context_t context7b = {(const uint8_t *) token7b, strlen(token7b), 0};
    flow_argument_list_t new_arg_list_b = {
        context0b,
        {context2b, context3b, context4b, context5b, context6b, context7b},
        6};
    memcpy(&arg_list_b, &new_arg_list_b, sizeof(arg_list_b));

    const parser_context_t context0c = {(const uint8_t *) dummy, strlen(dummy), 0};
    const parser_context_t context2c = {(const uint8_t *) token2c, strlen(token2c), 0};
    const parser_context_t context3c = {(const uint8_t *) token3c, strlen(token3c), 0};
    const parser_context_t context4c = {(const uint8_t *) token4c, strlen(token4c), 0};
    const parser_context_t context5c = {(const uint8_t *) token5c, strlen(token5c), 0};
    const parser_context_t context6c = {(const uint8_t *) token6c, strlen(token6c), 0};
    const parser_context_t context7c = {(const uint8_t *) token7c, strlen(token7c), 0};
    flow_argument_list_t new_arg_list_c = {
        context0c,
        {context2c, context3c, context4c, context5c, context6c, context7c},
        6};
    memcpy(&arg_list_c, &new_arg_list_c, sizeof(arg_list_c));
}

static void test_printArgument(void **state) {
    char outValBuf[40];
    uint8_t pageCountVar = 0;

    char ufix64[] = "UFix64";
    parser_error_t err =
        parser_printArgument(&arg_list, 4, ufix64, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "545.77");
    assert_int_equal(pageCountVar, 1);

    err =
        parser_printArgument(&arg_list_b, 4, ufix64, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "545.77");
    assert_int_equal(pageCountVar, 1);

    char optional[] = "Optional";
    err =
        parser_printArgument(&arg_list, 4, optional, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_UNEXPECTED_VALUE);

    err =
        parser_printArgument(&arg_list, 0, optional, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_JSON_INVALID);
}

static void test_printArgumentArray(void **state) {
    char outValBuf[40];
    uint8_t pageCountVar = 0;

    parser_error_t err = parser_printArgumentArray(&arg_list,
                                                   5,
                                                   0,
                                                   "String",
                                                   JSMN_STRING,
                                                   outValBuf,
                                                   40,
                                                   0,
                                                   &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_int_equal(pageCountVar, 4);
    assert_string_equal(outValBuf, "e845b8406e4f43f79d3c1d8cacb3d5f3e7aeedb");

    pageCountVar = 0;
    err = parser_printArgumentArray(&arg_list,
                                    5,
                                    0,
                                    "String",
                                    JSMN_STRING,
                                    outValBuf,
                                    40,
                                    1,
                                    &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_int_equal(pageCountVar, 4);
    assert_string_equal(outValBuf, "29feaeb4559fdb71a97e2fd0438565310e87670");

    pageCountVar = 0;
    err = parser_printArgumentArray(&arg_list,
                                    5,
                                    1,
                                    "String",
                                    JSMN_STRING,
                                    outValBuf,
                                    40,
                                    0,
                                    &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_int_equal(pageCountVar, 4);
    assert_string_equal(outValBuf, "d845b8406e4f43f79d3c1d8cacb3d5f3e7aeedb");

    err = parser_printArgumentArray(&arg_list,
                                    5,
                                    2,
                                    "String",
                                    JSMN_STRING,
                                    outValBuf,
                                    40,
                                    0,
                                    &pageCountVar);
    assert_int_equal(err, PARSER_UNEXPECTED_NUMBER_ITEMS);

    err = parser_printArgumentArray(&arg_list,
                                    5,
                                    1,
                                    "String",
                                    JSMN_STRING,
                                    outValBuf,
                                    40,
                                    6,
                                    &pageCountVar);
    assert_int_equal(err, PARSER_DISPLAY_PAGE_OUT_OF_RANGE);

    err = parser_printArgumentArray(&arg_list,
                                    2,
                                    0,
                                    "String",
                                    JSMN_STRING,
                                    outValBuf,
                                    40,
                                    0,
                                    &pageCountVar);
    assert_int_equal(err, PARSER_UNEXPECTED_VALUE);
}

static void test_printOptionalArgument(void **state) {
    char outValBuf[40];
    uint8_t pageCountVar = 0;

    char ufix64[] = "UFix64";
    parser_error_t err = parser_printOptionalArgument(&arg_list,
                                                      0,
                                                      ufix64,
                                                      JSMN_STRING,
                                                      outValBuf,
                                                      40,
                                                      0,
                                                      &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_int_equal(pageCountVar, 1);
    assert_string_equal(outValBuf, "None");

    err = parser_printOptionalArgument(&arg_list,
                                       1,
                                       ufix64,
                                       JSMN_STRING,
                                       outValBuf,
                                       40,
                                       0,
                                       &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "545.77");
    assert_int_equal(pageCountVar, 1);

    err = parser_printOptionalArgument(&arg_list_b,
                                       0,
                                       ufix64,
                                       JSMN_STRING,
                                       outValBuf,
                                       40,
                                       0,
                                       &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_int_equal(pageCountVar, 1);
    assert_string_equal(outValBuf, "None");

    err = parser_printOptionalArgument(&arg_list_b,
                                       1,
                                       ufix64,
                                       JSMN_STRING,
                                       outValBuf,
                                       40,
                                       0,
                                       &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "545.77");
    assert_int_equal(pageCountVar, 1);

    err = parser_printOptionalArgument(&arg_list,
                                       4,
                                       ufix64,
                                       JSMN_STRING,
                                       outValBuf,
                                       40,
                                       0,
                                       &pageCountVar);
    assert_int_equal(err, PARSER_UNEXPECTED_VALUE);
}

static void test_printEnums(void **state) {
    char outValBuf[40];
    uint8_t pageCountVar = 0;

    char uint8[] = "UInt8";
    parser_error_t err =
        parser_printHashAlgo(&arg_list_c, 0, uint8, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "SHA2 256");
    assert_int_equal(pageCountVar, 1);

    err = parser_printHashAlgo(&arg_list_c, 1, uint8, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "SHA2 384");
    assert_int_equal(pageCountVar, 1);

    err = parser_printHashAlgo(&arg_list_c, 2, uint8, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "SHA3 256");
    assert_int_equal(pageCountVar, 1);

    err = parser_printHashAlgo(&arg_list_c, 3, uint8, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "SHA3 384");
    assert_int_equal(pageCountVar, 1);

    err = parser_printHashAlgo(&arg_list_c, 4, uint8, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "KMAC128 BLS BLS12 381");
    assert_int_equal(pageCountVar, 1);

    err = parser_printHashAlgo(&arg_list_c, 5, uint8, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "KECCAK 256");
    assert_int_equal(pageCountVar, 1);

    err = parser_printSignatureAlgo(&arg_list_c,
                                    0,
                                    uint8,
                                    JSMN_STRING,
                                    outValBuf,
                                    40,
                                    0,
                                    &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "ECDSA P256");
    assert_int_equal(pageCountVar, 1);

    err = parser_printSignatureAlgo(&arg_list_c,
                                    1,
                                    uint8,
                                    JSMN_STRING,
                                    outValBuf,
                                    40,
                                    0,
                                    &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "ECDSA secp256k1");
    assert_int_equal(pageCountVar, 1);

    err = parser_printSignatureAlgo(&arg_list_c,
                                    2,
                                    uint8,
                                    JSMN_STRING,
                                    outValBuf,
                                    40,
                                    0,
                                    &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "BLS BLS12 381");
    assert_int_equal(pageCountVar, 1);

    err = parser_printNodeRole(&arg_list_c, 0, uint8, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "Collection");
    assert_int_equal(pageCountVar, 1);

    err = parser_printNodeRole(&arg_list_c, 1, uint8, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "Consensus");
    assert_int_equal(pageCountVar, 1);

    err = parser_printNodeRole(&arg_list_c, 2, uint8, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "Execution");
    assert_int_equal(pageCountVar, 1);

    err = parser_printNodeRole(&arg_list_c, 3, uint8, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "Verification");
    assert_int_equal(pageCountVar, 1);

    err = parser_printNodeRole(&arg_list_c, 4, uint8, JSMN_STRING, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outValBuf, "Access");
    assert_int_equal(pageCountVar, 1);
}

static void test_printArbitraryArgument(void **state) {
    char outKeyBuf[20];
    char outValBuf[40];
    uint8_t pageCountVar = 0;

    parser_error_t err =
        parser_printArbitraryArgument(&arg_list, 0, outKeyBuf, 40, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_int_equal(pageCountVar, 1);
    assert_string_equal(outKeyBuf, "1: Optional");
    assert_string_equal(outValBuf, "null");

    pageCountVar = 0;
    err = parser_printArbitraryArgument(&arg_list_b,
                                        1,
                                        outKeyBuf,
                                        40,
                                        outValBuf,
                                        40,
                                        0,
                                        &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_int_equal(pageCountVar, 1);
    assert_string_equal(outKeyBuf, "2: Optional");
    assert_string_equal(outValBuf, "{\"value\":\"545.77\",\"type\":\"UFix64\"}");

    pageCountVar = 0;
    err =
        parser_printArbitraryArgument(&arg_list, 2, outKeyBuf, 40, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outKeyBuf, "3: Optional");
    assert_string_equal(outValBuf, "{\"type\": \"Array\",\"value\":[{\"type\":\"Stri");

    err =
        parser_printArbitraryArgument(&arg_list, 2, outKeyBuf, 40, outValBuf, 40, 1, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outKeyBuf, "3: Optional");
    assert_string_equal(outValBuf, "ng\",\"value\":\"f845b8406e4f43f79d3c1d8cac");

    pageCountVar = 0;
    err =
        parser_printArbitraryArgument(&arg_list, 3, outKeyBuf, 40, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outKeyBuf, "4: Optional");
    assert_string_equal(outValBuf, "<Value too long>");

    pageCountVar = 0;
    err =
        parser_printArbitraryArgument(&arg_list, 4, outKeyBuf, 40, outValBuf, 40, 0, &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outKeyBuf, "5: UFix64");
    assert_string_equal(outValBuf, "545.77");

    pageCountVar = 0;
    err = parser_printArbitraryArgument(&arg_list_b,
                                        5,
                                        outKeyBuf,
                                        40,
                                        outValBuf,
                                        40,
                                        0,
                                        &pageCountVar);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(outKeyBuf, "6: Array");
    assert_string_equal(outValBuf, "<Value too long>");
}

int main() {
    createArgList();
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_printArgument),
                                       cmocka_unit_test(test_printOptionalArgument),
                                       cmocka_unit_test(test_printArgumentArray),
                                       cmocka_unit_test(test_printEnums),
                                       cmocka_unit_test(test_printArbitraryArgument)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
