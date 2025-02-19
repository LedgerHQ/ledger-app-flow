#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "tx_metadata.h"

const uint8_t TX_METADATA_ADD_NEW_KEY[] = {
    1, //number of hashes + hashes
    0x59, 0x5c, 0x86, 0x56, 0x14, 0x41, 0xb3, 0x2b, 0x2b, 0x91, 0xee, 0x03, 0xf9, 0xe1, 0x0c, 0xa6, 0xef, 0xa7, 0xb4, 0x1b, 0xcc, 0x99, 0x4f, 0x51, 0x31, 0x7e, 0xc0, 0xaa, 0x9d, 0x8f, 0x8a, 0x42,
    'A', 'd', 'd', ' ', 'N', 'e', 'w', ' ', 'K', 'e', 'y', 0,  //tx name (to display)
    1,  //number of arguments

    //Argument 1
    ARGUMENT_TYPE_NORMAL,
    'P', 'u', 'b', ' ', 'k', 'e', 'y', 0, //arg name (to display)
    0, //argument index
    'S','t', 'r', 'i', 'n', 'g',  0, //expected value type
    JSMN_STRING //expected value json token type
};

const uint8_t TX_METADATA_ADD_NEW_KEY_ERROR[] = {
    1, //number of hashes + hashes
    0x59, 0x5c, 0x86, 0x56, 0x14, 0x41, 0xb3, 0x2b, 0x2b, 0x91, 0xee, 0x03, 0xf9, 0xe1, 0x0c, 0xa6, 0xef, 0xa7, 0xb4, 0x1b, 0xcc, 0x99, 0x4f, 0x51, 0x31, 0x7e, 0xc0, 0xaa, 0x9d, 0x8f, 0x8a, 0x42,
    'A', 'd', 'd', ' ', 'N', 'e', 'w', ' ', 'K', 'e', 'y', 0,  //tx name (to display)
    1,  //number of arguments

    //Argument 1
    ARGUMENT_TYPE_NORMAL,
    'P', 'u', 'b', ' ', 'k', 'e', 'y', 0, //arg name (to display)
    0, //argument index
    'S','t', 'r', 'i', 'n', 'g',  0, //expected value type
    JSMN_STRING, //expected value json token type
    0 //extra errorous value
};

const uint8_t TX_METADATA_TOKEN_TRANSFER[] = {
    3, //number of hashes + hashes
    0xca, 0x80, 0xb6, 0x28, 0xd9, 0x85, 0xb3, 0x58, 0xae, 0x1c, 0xb1, 0x36, 0xbc, 0xd9, 0x76, 0x99, 0x7c, 0x94, 0x2f, 0xa1, 0x0d, 0xba, 0xbf, 0xea, 0xfb, 0x4e, 0x20, 0xfa, 0x66, 0xa5, 0xa5, 0xe2,
    0xd5, 0x6f, 0x4e, 0x1d, 0x23, 0x55, 0xcd, 0xcf, 0xac, 0xfd, 0x01, 0xe4, 0x71, 0x45, 0x9c, 0x6e, 0xf1, 0x68, 0xbf, 0xdf, 0x84, 0x37, 0x1a, 0x68, 0x5c, 0xcf, 0x31, 0xcf, 0x3c, 0xde, 0xdc, 0x2d,
    0x47, 0x85, 0x15, 0x86, 0xd9, 0x62, 0x33, 0x5e, 0x3f, 0x7d, 0x9e, 0x5d, 0x11, 0xa4, 0xc5, 0x27, 0xee, 0x4b, 0x5f, 0xd1, 0xc3, 0x89, 0x5e, 0x3c, 0xe1, 0xb9, 0xc2, 0x82, 0x1f, 0x60, 0xb1, 0x66,
    'T', 'o', 'k', 'e', 'n', ' ', 'T', 'r', 'a', 'n', 's', 'f', 'e', 'r', 0,  //tx name (to display)
    6,  //number of arguments

    //Argument 1
    ARGUMENT_TYPE_ARRAY, 5, 10,
    'A', 'm', 'o', 'u', 'n', 't', 0, //arg name (to display)
    0, //argument index
    'U','I', 'n', 't', '6', '4',  0, //expected value type
    JSMN_STRING, //expected value json token type

    //Argument 2
    ARGUMENT_TYPE_OPTIONAL,
    'D', 'e', 's', 't', 'i', 'n', 'a', 't', 'i', 'o', 'n', 0, //arg name (to display)
    1, //argument index
    'A','d', 'd', 'r', 'e', 's', 's', 0, //expected value type
    JSMN_STRING, //expected value json token type

    //Argument 3
    ARGUMENT_TYPE_STRING,
    'A', 'r', 'g', '3', 0, //arg name (to display)
    2, //argument index

    //Argument 4
    ARGUMENT_TYPE_HASH_ALGO,
    'A', 'r', 'g', '4', 0, //arg name (to display)
    3, //argument index

    //Argument 5
    ARGUMENT_TYPE_SIGNATURE_ALGO,
    'A', 'r', 'g', '5', 0, //arg name (to display)
    4, //argument index

    //Argument 6
    ARGUMENT_TYPE_NODE_ROLE,
    'A', 'r', 'g', '6', 0, //arg name (to display)
    5, //argument index
};

uint8_t hashAddNewKey[32]     = {0x59, 0x5c, 0x86, 0x56, 0x14, 0x41, 0xb3, 0x2b, 0x2b, 0x91, 0xee, 0x03, 0xf9, 0xe1, 0x0c, 0xa6, 0xef, 0xa7, 0xb4, 0x1b, 0xcc, 0x99, 0x4f, 0x51, 0x31, 0x7e, 0xc0, 0xaa, 0x9d, 0x8f, 0x8a, 0x42};
uint8_t hashTokenTranfer1[32] = {0xca, 0x80, 0xb6, 0x28, 0xd9, 0x85, 0xb3, 0x58, 0xae, 0x1c, 0xb1, 0x36, 0xbc, 0xd9, 0x76, 0x99, 0x7c, 0x94, 0x2f, 0xa1, 0x0d, 0xba, 0xbf, 0xea, 0xfb, 0x4e, 0x20, 0xfa, 0x66, 0xa5, 0xa5, 0xe2};
uint8_t hashTokenTranfer2[32] = {0xd5, 0x6f, 0x4e, 0x1d, 0x23, 0x55, 0xcd, 0xcf, 0xac, 0xfd, 0x01, 0xe4, 0x71, 0x45, 0x9c, 0x6e, 0xf1, 0x68, 0xbf, 0xdf, 0x84, 0x37, 0x1a, 0x68, 0x5c, 0xcf, 0x31, 0xcf, 0x3c, 0xde, 0xdc, 0x2d};
uint8_t hashTokenTranfer3[32] = {0x47, 0x85, 0x15, 0x86, 0xd9, 0x62, 0x33, 0x5e, 0x3f, 0x7d, 0x9e, 0x5d, 0x11, 0xa4, 0xc5, 0x27, 0xee, 0x4b, 0x5f, 0xd1, 0xc3, 0x89, 0x5e, 0x3c, 0xe1, 0xb9, 0xc2, 0x82, 0x1f, 0x60, 0xb1, 0x66};

static void test_validateScriptHash(void **state) {
    (void) state;    
    parser_error_t err;
    err = _validateScriptHash(hashAddNewKey, TX_METADATA_ADD_NEW_KEY, sizeof(TX_METADATA_ADD_NEW_KEY));
    assert_int_equal(err, PARSER_OK);

    err = _validateScriptHash(hashTokenTranfer1, TX_METADATA_ADD_NEW_KEY, sizeof(TX_METADATA_ADD_NEW_KEY));
    assert_int_equal(err, PARSER_UNEXPECTED_SCRIPT);

    err = _validateScriptHash(hashTokenTranfer1, TX_METADATA_TOKEN_TRANSFER, sizeof(TX_METADATA_TOKEN_TRANSFER));
    assert_int_equal(err, PARSER_OK);

    err = _validateScriptHash(hashTokenTranfer2, TX_METADATA_TOKEN_TRANSFER, sizeof(TX_METADATA_TOKEN_TRANSFER));
    assert_int_equal(err, PARSER_OK);

    err = _validateScriptHash(hashTokenTranfer3, TX_METADATA_TOKEN_TRANSFER, sizeof(TX_METADATA_TOKEN_TRANSFER));
    assert_int_equal(err, PARSER_OK);

    err = _validateScriptHash(hashAddNewKey, TX_METADATA_TOKEN_TRANSFER, sizeof(TX_METADATA_TOKEN_TRANSFER));
    assert_int_equal(err, PARSER_UNEXPECTED_SCRIPT);

    err = _validateScriptHash(hashTokenTranfer3, TX_METADATA_ADD_NEW_KEY, 0);
    assert_int_equal(err, PARSER_METADATA_ERROR);

    err = _validateScriptHash(hashTokenTranfer3, TX_METADATA_TOKEN_TRANSFER, 3*32);
    assert_int_equal(err, PARSER_METADATA_ERROR);

    err = _validateScriptHash(hashTokenTranfer3, TX_METADATA_TOKEN_TRANSFER, 3*32+1);
    assert_int_equal(err, PARSER_OK);
}


static void test_parseCompressedTxData(void **state) {
    parser_error_t err;
    parsed_tx_metadata_t result;
    err = _parseTxMetadata(hashTokenTranfer1, TX_METADATA_ADD_NEW_KEY, sizeof(TX_METADATA_ADD_NEW_KEY), &result);
    assert_int_equal(err, PARSER_UNEXPECTED_SCRIPT);
    
    err = _parseTxMetadata(hashAddNewKey, TX_METADATA_ADD_NEW_KEY, sizeof(TX_METADATA_ADD_NEW_KEY), &result);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(result.txName, "Add New Key");
    assert_int_equal(result.txNameLength, 11);
    assert_int_equal(result.argCount, 1);
    assert_int_equal(result.arguments[0].argumentType, ARGUMENT_TYPE_NORMAL);
    assert_string_equal(result.arguments[0].displayKey, "Pub key");
    assert_int_equal(result.arguments[0].displayKeyLength, 7);
    assert_int_equal(result.arguments[0].argumentIndex, 0);
    assert_string_equal(result.arguments[0].jsonExpectedType, "String");
    assert_int_equal(result.arguments[0].jsonExpectedTypeLength, 6);
    assert_int_equal(result.arguments[0].jsonExpectedKind, JSMN_STRING);

    err = _parseTxMetadata(hashTokenTranfer3, TX_METADATA_TOKEN_TRANSFER, sizeof(TX_METADATA_TOKEN_TRANSFER), &result);
    assert_int_equal(err, PARSER_OK);
    assert_string_equal(result.txName, "Token Transfer");
    assert_int_equal(result.txNameLength, 14);
    assert_int_equal(result.argCount, 6);

    assert_int_equal(result.arguments[0].argumentType, ARGUMENT_TYPE_ARRAY);
    assert_int_equal(result.arguments[0].arrayMinElements, 5);
    assert_int_equal(result.arguments[0].arrayMaxElements, 10);
    assert_string_equal(result.arguments[0].displayKey, "Amount");
    assert_int_equal(result.arguments[0].displayKeyLength, 6);
    assert_int_equal(result.arguments[0].argumentIndex, 0);
    assert_string_equal(result.arguments[0].jsonExpectedType, "UInt64");
    assert_int_equal(result.arguments[0].jsonExpectedTypeLength, 6);
    assert_int_equal(result.arguments[0].jsonExpectedKind, JSMN_STRING);

    assert_int_equal(result.arguments[1].argumentType, ARGUMENT_TYPE_OPTIONAL);
    assert_string_equal(result.arguments[1].displayKey, "Destination");
    assert_int_equal(result.arguments[1].displayKeyLength, 11);
    assert_int_equal(result.arguments[1].argumentIndex, 1);
    assert_string_equal(result.arguments[1].jsonExpectedType, "Address");
    assert_int_equal(result.arguments[1].jsonExpectedTypeLength, 7);
    assert_int_equal(result.arguments[1].jsonExpectedKind, JSMN_STRING);    

    assert_int_equal(result.arguments[2].argumentType, ARGUMENT_TYPE_STRING);
    assert_string_equal(result.arguments[2].displayKey, "Arg3");
    assert_int_equal(result.arguments[2].displayKeyLength, 4);
    assert_int_equal(result.arguments[2].argumentIndex, 2);
    assert_string_equal(result.arguments[2].jsonExpectedType, "String");
    assert_int_equal(result.arguments[2].jsonExpectedTypeLength, 6);
    assert_int_equal(result.arguments[2].jsonExpectedKind, JSMN_STRING);    

    assert_int_equal(result.arguments[3].argumentType, ARGUMENT_TYPE_HASH_ALGO);
    assert_string_equal(result.arguments[3].displayKey, "Arg4");
    assert_int_equal(result.arguments[3].displayKeyLength, 4);
    assert_int_equal(result.arguments[3].argumentIndex, 3);
    assert_string_equal(result.arguments[3].jsonExpectedType, "UInt8");
    assert_int_equal(result.arguments[3].jsonExpectedTypeLength, 5);
    assert_int_equal(result.arguments[3].jsonExpectedKind, JSMN_STRING);    

    assert_int_equal(result.arguments[4].argumentType, ARGUMENT_TYPE_SIGNATURE_ALGO);
    assert_string_equal(result.arguments[4].displayKey, "Arg5");
    assert_int_equal(result.arguments[4].displayKeyLength, 4);
    assert_int_equal(result.arguments[4].argumentIndex, 4);
    assert_string_equal(result.arguments[4].jsonExpectedType, "UInt8");
    assert_int_equal(result.arguments[4].jsonExpectedTypeLength, 5);
    assert_int_equal(result.arguments[4].jsonExpectedKind, JSMN_STRING);    

    assert_int_equal(result.arguments[5].argumentType, ARGUMENT_TYPE_NODE_ROLE);
    assert_string_equal(result.arguments[5].displayKey, "Arg6");
    assert_int_equal(result.arguments[5].displayKeyLength, 4);
    assert_int_equal(result.arguments[5].argumentIndex, 5);
    assert_string_equal(result.arguments[5].jsonExpectedType, "UInt8");
    assert_int_equal(result.arguments[5].jsonExpectedTypeLength, 5);
    assert_int_equal(result.arguments[5].jsonExpectedKind, JSMN_STRING);    

    err = _parseTxMetadata(hashAddNewKey, TX_METADATA_ADD_NEW_KEY, sizeof(TX_METADATA_ADD_NEW_KEY)-1, &result);
    assert_int_equal(err, PARSER_METADATA_ERROR);
    err = _parseTxMetadata(hashAddNewKey, TX_METADATA_ADD_NEW_KEY_ERROR, sizeof(TX_METADATA_ADD_NEW_KEY_ERROR), &result);
    assert_int_equal(err, PARSER_METADATA_ERROR);
}

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_validateScriptHash), cmocka_unit_test(test_parseCompressedTxData)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
