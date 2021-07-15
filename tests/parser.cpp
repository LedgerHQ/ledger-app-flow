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

#include "gmock/gmock.h"
#include <iostream>
#include <stdlib.h>
#include <hexutils.h>
#include <json/json_parser.h>
#include <parser.h>
#include <string.h>


const auto token2 = "{\"type\":\"Optional\",\"value\":null}";
parser_context_t context2 = {(const uint8_t *)token2, strlen(token2), 0};
const auto token3 = "{\"type\":\"Optional\",\"value\":{\"type\":\"UFix64\",\"value\":\"545.77\"}}";
parser_context_t context3 = {(const uint8_t *)token3, strlen(token3), 0};

flow_argument_list_t arg_list = {{},{context2, context3},2};

TEST(parser, printOptional) {
    char outValBuf[40];
    uint8_t pageCountVar = 0;

    char ufix64[] = "UFix64";
    parser_error_t err = parser_printArgumentOptionalDelegatorID(&arg_list, 0, ufix64, JSMN_STRING,
                                               outValBuf, 40, 0, &pageCountVar);
    EXPECT_THAT(err, PARSER_OK);
    EXPECT_THAT(pageCountVar, 1);
    EXPECT_STREQ(outValBuf, "None");

    err = parser_printArgumentOptionalDelegatorID(&arg_list, 1, ufix64, JSMN_STRING,
                                               outValBuf, 40, 1, &pageCountVar);
    EXPECT_THAT(err, PARSER_OK);
    EXPECT_STREQ(outValBuf, "545.77");
    EXPECT_THAT(pageCountVar, 1);

}
