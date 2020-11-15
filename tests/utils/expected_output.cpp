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
#include <fmt/core.h>
#include <coin.h>
#include <crypto.h>
#include <parser_txdef.h>
#include <parser_impl.h>
#include <iomanip>
#include "testcases.h"
#include "zxmacros.h"

bool TestcaseIsValid(const Json::Value &) {
    return true;
}

std::string formatString(const std::string &data, uint8_t idx, uint8_t *pageCount) {
    char outBuffer[40];
    pageString(outBuffer, sizeof(outBuffer), data.c_str(), idx, pageCount);
    return std::string(outBuffer);
}

std::vector<std::string> formatStringParts(const Json::Value &v) {
    std::vector<std::string> answer;
    std::stringstream s;
    s << v.asString();

    uint8_t pageIdx = 0;
    uint8_t pageCount = 1;
    char outBuffer[40];

    while (pageIdx < pageCount) {
        pageString(outBuffer, sizeof(outBuffer), s.str().c_str(), pageIdx, &pageCount);
        answer.emplace_back(outBuffer);
        pageIdx++;
    }

    return answer;
}

template<typename S, typename... Args>
void addTo(std::vector<std::string> &answer, const S &format_str, Args &&... args) {
    answer.push_back(fmt::format(format_str, args...));
}

void addMultiStringArgumentTo(std::vector<std::string> &answer, const std::string &name, uint16_t item, const Json::Value &v) {
    auto chunks = formatStringParts(v);

    if (chunks.size() == 1) {
        addTo(answer, "{} | {} : {}", item, name, chunks[0]);
        return;
    }

    for (uint16_t j = 0; j < (uint16_t) chunks.size(); j++) {
        addTo(answer, "{} | {} [{}/{}] : {}", item, name, j + 1, chunks.size(), chunks[j]);
    }
}

std::vector<std::string> GenerateExpectedUIOutput(const testcaseData_t &tcd) {
    auto answer = std::vector<std::string>();

    if (!tcd.valid) {
        answer.emplace_back("Test case is not valid!");
        return answer;
    }

    uint8_t scriptHash[32];
    script_type_e scriptType = script_unknown;
    sha256((const uint8_t *) tcd.script.c_str(), tcd.script.length(), scriptHash);
    _matchScriptType(scriptHash, &scriptType);

    uint16_t item = 0;
    uint8_t dummy;

    switch (scriptType) {
        case script_unknown:
            addTo(answer, "{} | Type :Unknown", item++);
            break;
        case script_token_transfer: {
            addTo(answer, "{} | Type : Token Transfer", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            addTo(answer, "{} | Destination : {}", item++, tcd.arguments[1]["value"].asString());
            break;
        }
        case script_create_account: {
            addTo(answer, "{} | Type : Create Account", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            const auto pks = tcd.arguments[0]["value"];

            for (uint16_t i = 0; i < (uint16_t) pks.size(); i++) {
                addMultiStringArgumentTo(answer, fmt::format("Pub key {}", i + 1), item++, pks[i]["value"]);
            }
            break;
        }
        case script_add_new_key: {
            addTo(answer, "{} | Type : Add New Key", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addMultiStringArgumentTo(answer, "Pub key", item++, tcd.arguments[0]["value"]);
            break;
        }
        case script_th01_withdraw_unlocked_tokens: {
            addTo(answer, "{} | Type : Withdraw FLOW from Lockbox", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            break;
        }
        case script_th02_deposit_unlocked_tokens: {
            addTo(answer, "{} | Type : Deposit FLOW to Lockbox", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            break;
        }
        case script_th06_register_node: {
            addTo(answer, "{} | Type : Register Staked Node", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addMultiStringArgumentTo(answer, "Node ID", item++, tcd.arguments[0]["value"]);
            addTo(answer, "{} | Node Role : {}", item++, tcd.arguments[1]["value"].asString());
            addMultiStringArgumentTo(answer, "Networking Address", item++, tcd.arguments[2]["value"]);
            addMultiStringArgumentTo(answer, "Networking Key", item++, tcd.arguments[3]["value"]);
            addMultiStringArgumentTo(answer, "Staking Key", item++, tcd.arguments[4]["value"]);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[5]["value"].asString());
            break;
        }
        case script_th08_stake_new_tokens: {
            addTo(answer, "{} | Type : Stake FLOW from Lockbox", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            break;
        }
        case script_th09_restake_unstaked_tokens: {
            addTo(answer, "{} | Type : Restake Unstaked FLOW", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            break;
        }
        case script_th10_restake_rewarded_tokens: {
            addTo(answer, "{} | Type : Restake Rewarded FLOW", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            break;
        }
        case script_th11_unstake_tokens: {
            addTo(answer, "{} | Type : Unstake FLOW", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            break;
        }
        case script_th12_unstake_all_tokens: {
            addTo(answer, "{} | Type : Unstake All FLOW", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            break;
        }
        case script_th13_withdraw_unstaked_tokens: {
            addTo(answer, "{} | Type : Withdraw Unstaked FLOW to Lockbox", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            break;
        }
        case script_th14_withdraw_rewarded_tokens: {
            addTo(answer, "{} | Type : Withdraw Rewarded FLOW to Lockbox", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            break;
        }
        case script_th16_register_operator_node: {
            addTo(answer, "{} | Type : Register Operator Node", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Operator Address : {}", item++, tcd.arguments[0]["value"].asString());
            addMultiStringArgumentTo(answer, "Node ID", item++, tcd.arguments[1]["value"]);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[2]["value"].asString());
            break;
        }
        case script_th17_register_delegator: {
            addTo(answer, "{} | Type : Register Delegator", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addMultiStringArgumentTo(answer, "Node ID", item++, tcd.arguments[0]["value"]);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[1]["value"].asString());
            break;
        }
        case script_th19_delegate_new_tokens: {
            addTo(answer, "{} | Type : Delegate FLOW from Lockbox", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            break;
        }
        case script_th20_restake_unstaked_delegated_tokens: {
            addTo(answer, "{} | Type : Re-delegate Unstaked FLOW", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            break;
        }
        case script_th21_restake_rewarded_delegated_tokens: {
            addTo(answer, "{} | Type : Re-delegate Rewarded FLOW", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            break;
        }
        case script_th22_unstake_delegated_tokens: {
            addTo(answer, "{} | Type : Unstake Delegated FLOW", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            break;
        }
        case script_th23_withdraw_unstaked_delegated_tokens: {
            addTo(answer, "{} | Type : Withdraw Undelegated FLOW to Lockbox", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            break;
        }
        case script_th24_withdraw_rewarded_delegated_tokens: {
            addTo(answer, "{} | Type : Withdraw Delegate Rewards to Lockbox", item++);
            addTo(answer, "{} | ChainID : {}", item++, tcd.chainID);
            addTo(answer, "{} | Amount : {}", item++, tcd.arguments[0]["value"].asString());
            break;
        }
        default:
            addTo(answer, "{} | Type : ERROR", item++);
            break;
    }

    addTo(answer, "{} | Ref Block [1/2] : {}", item, formatString(tcd.refBlock, 0, &dummy));
    addTo(answer, "{} | Ref Block [2/2] : {}", item++, formatString(tcd.refBlock, 1, &dummy));
    addTo(answer, "{} | Gas Limit : {}", item++, tcd.gasLimit);
    addTo(answer, "{} | Prop Key Addr : {}", item++, formatString(tcd.proposalKeyAddress, 0, &dummy));
    addTo(answer, "{} | Prop Key Id : {}", item++, tcd.proposalKeyId);
    addTo(answer, "{} | Prop Key Seq Num : {}", item++, tcd.proposalKeySequenceNumber);
    addTo(answer, "{} | Payer : {}", item++, formatString(tcd.payer, 0, &dummy));

    for (uint16_t i = 0; i < (uint16_t) tcd.authorizers.size(); i++) {
        addTo(answer, "{} | Authorizer {} : {}", item++, i + 1, tcd.authorizers[i]);
    }

    return answer;
}
