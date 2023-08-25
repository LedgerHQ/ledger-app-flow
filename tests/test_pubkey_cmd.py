import pytest

from application_client.flow_command_sender import FlowCommandSender, Errors, HashType
from application_client.flow_response_unpacker import unpack_get_public_key_response

from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.error import ExceptionRAPDU
from ragger.conftest.configuration import OPTIONAL

from utils import util_check_pub_key, util_set_slot, util_set_expert_mode, util_navigate


def test_get_public_key_no_confirm(backend):
    """ Check the GET_PUBLIC_KEY in non-confirmation mode """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)
    # Test parameters
    path_list = [
        "m/44'/539'/0'/0/0",
        "m/44'/539'/0'/0/2147483647",
        "m/44'/539'/2147483647'/0/0",
        "m/44'/539'/2147483647'/0/2147483647",
        "m/44'/539'/513'/0/0",
        "m/44'/539'/769'/0/0",
        "m/44'/1'/769/0/0",
        "m/44'/1'/769/0/2147483647",
    ]
    curve_list = [
        CurveChoice.Secp256k1,
        CurveChoice.Nist256p1,
    ]

    # Send the APDU and check the results
    for path in path_list:
        for curve in curve_list:
            _ = util_check_pub_key(client, path, curve)


def test_get_public_key_slot(firmware, backend, navigator, test_name):
    """ Check the GET_PUBLIC_KEY in non-confirmation mode with slot """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)
    # Test parameters
    slot = 0
    curve0 = CurveChoice.Secp256k1
    curve1 = CurveChoice.Nist256p1
    address = "e467b9dd11fa00de"
    path0 = "m/44'/539'/513'/0/0"
    path1 = "m/44'/539'/513'/0/1"

    # Send the APDU and check the results

    # Call get_public_key when slot is empty
    _ = util_check_pub_key(client, path0, curve0)

    # Set_slot to some other path
    util_set_slot(client, firmware, navigator, test_name, slot, curve0, HashType.HASH_SHA2, address, path1)

    # Call get_public_key for different path values
    path_list = [path0, path1]
    for path in path_list:
        _ = util_check_pub_key(client, path, curve0)

    # Call get_public_key for other path - but hashes do not match - does not matter
    _ = util_check_pub_key(client, path1, curve0, HashType.HASH_SHA3)

    # Call get_public_key for other path - but curves do not match - warning
    _ = util_check_pub_key(client, path1, curve1)

    # Clean Slot
    util_set_slot(client, firmware, navigator, test_name, slot)


def test_get_public_key_expert(firmware, backend, navigator, test_name):
    """ Check the GET_PUBLIC_KEY in non-confirmation mode with expert mode """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)
    # Test parameters
    test_cfg = [
        {
            "curve": CurveChoice.Secp256k1,
            "hash": HashType.HASH_SHA2,
        },
        {
            "curve": CurveChoice.Nist256p1,
            "hash": HashType.HASH_SHA3,
        },
    ]
    path = "m/44'/539'/513'/0/0"

    # Navigate in the main menu to change to expert mode
    util_set_expert_mode(firmware, navigator, test_name)

    # Send the APDU and check the results
    for cfg in test_cfg:
        _ = util_check_pub_key(client, path, cfg["curve"], cfg["hash"])


def test_get_public_key_confirm_accepted(firmware, backend, navigator, test_name):
    """ Check the GET_PUBLIC_KEY in confirmation mode when user accepts """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)
    # Test parameters
    path = "m/44'/539'/0'/0/0"
    curve = CurveChoice.Secp256k1
    hash_t = HashType.HASH_SHA2

    # Send the APDU (Asynchronous)
    with client.get_public_key_with_confirmation(path, curve, hash_t):
        util_navigate(firmware, navigator, test_name, "APPROVE")

    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response.status == Errors.SW_SUCCESS

    # Parse the response
    public_key = unpack_get_public_key_response(response.data)
    # Compute the reference data
    ref_public_key, _ = calculate_public_key_and_chaincode(curve, path, OPTIONAL.CUSTOM_SEED)
    # Check expected value
    assert public_key == ref_public_key


def test_get_public_key_confirm_refused(firmware, backend, navigator, test_name):
    """ Check the GET_PUBLIC_KEY in confirmation mode when user refuses """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)
    # Test parameters
    path = "m/44'/1'/0'/0/0"
    curve = CurveChoice.Secp256k1
    hash_t = HashType.HASH_SHA2

    # Send the APDU (Asynchronous)
    with pytest.raises(ExceptionRAPDU) as err:
        with client.get_public_key_with_confirmation(path, curve, hash_t):
            util_navigate(firmware, navigator, test_name, "REJECT")

        # Assert we have received a refusal
        assert err.value.status == Errors.SW_COMMAND_NOT_ALLOWED
        assert len(err.value.data) == 0
