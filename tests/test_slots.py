from pathlib import Path
from typing import Tuple
import pytest

from application_client.flow_command_sender import FlowCommandSender, Errors, HashType, MAX_SLOTS
from application_client.flow_response_unpacker import unpack_get_slot_response

from ragger.bip import CurveChoice
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator
from ragger.firmware import Firmware

from utils import util_set_slot, util_navigate


def _extract_option(option: bytes) -> Tuple[CurveChoice, HashType]:
    """ Extract curve and hash from options bytes array """

    hash_value = int(option[0:2])
    curve_value = int(option[2:4])

    if curve_value == 2:
        curve = CurveChoice.Nist256p1
    elif curve_value == 3:
        curve = CurveChoice.Secp256k1
    else:
        raise ValueError(f'Wrong Cruve "{curve_value}"')

    if hash_value == 1:
        hash_t = HashType.HASH_SHA2
    elif hash_value == 3:
        hash_t = HashType.HASH_SHA3
    else:
        raise ValueError(f'Wrong Hash "{hash_value}"')

    return curve, hash_t


def _set_slot_and_check(
        client: FlowCommandSender,
        firmware: Firmware,
        navigator: Navigator,
        test_name: Path,
        slot: int,
        curve: CurveChoice,
        hash_t: HashType,
        address: str,
        path: str,
) -> None:
    """ Set slot content, and check back """

    # Send the APDU - Set slot
    util_set_slot(client, firmware, navigator, test_name, slot, curve, hash_t, address, path)

    # Send the APDU - Slot status
    response = client.get_slot_status()
    assert response.status == Errors.SW_SUCCESS
    # Assert expected result
    assert response.data[slot] == 1

    # Send the APDU - Slot content
    response = client.get_slot(slot)
    assert response.status == Errors.SW_SUCCESS

    # Parse the response
    ret_address, ret_path, ret_option = unpack_get_slot_response(response.data)
    ret_curve, ret_hash = _extract_option(ret_option)
    print(f" Address: {ret_address}")
    print(f" Path: {ret_path}")
    print(f" Curve: {ret_curve}")
    print(f" Hash: {ret_hash}")

    # Check expected value
    assert address == ret_address
    assert curve == ret_curve


def test_get_slot_status(backend):
    """ Check slots status are all empty """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)

    # Send the APDU
    response = client.get_slot_status()
    assert response.status == Errors.SW_SUCCESS

    # Check expected values
    for slot in range(MAX_SLOTS):
        assert not response.data[slot]


def test_get_slot_empty(backend):
    """ Check empty slots """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)
    # Test parameters
    slot = 10

    with pytest.raises(ExceptionRAPDU) as err:
        # Send the APDU
        response = client.get_slot(slot)
        assert not response.data

    # Assert we have received a refusal
    assert err.value.status == Errors.SW_EMPTY_BUFFER
    assert len(err.value.data) == 0


def test_get_slot_accepted(firmware, backend, navigator, test_name):
    """ slot Test in confirmation mode """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)
    # Test parameters
    slot = 10
    hash_t = HashType.HASH_SHA2
    address = "e467b9dd11fa00df"
    path = "m/44'/539'/513'/0/0"
    curve = CurveChoice.Secp256k1

    # Send the APDU - Set slot
    part = 0
    _set_slot_and_check(
        client, firmware, navigator, f"{test_name}/part{part}", slot, curve, hash_t, address, path
    )

    # Send the APDU - Update slot
    address = "e467b9dd11fa00de"
    path = "m/44'/539'/513'/0/1"
    curve = CurveChoice.Nist256p1
    part += 1
    _set_slot_and_check(
        client, firmware, navigator, f"{test_name}/part{part}", slot, curve, hash_t, address, path
    )

    # Clean Slot
    part += 1
    util_set_slot(client, firmware, navigator, f"{test_name}/part{part}", slot)


def test_get_slot_refused(firmware, backend, navigator, test_name):
    """ Check slot in confirmation mode when user refuses """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)
    # Test parameters
    slot = 10
    address = "e467b9dd11fa00df"
    path = "m/44'/539'/513'/0/0"
    curve = CurveChoice.Secp256k1
    hash_t = HashType.HASH_SHA2

    # Send the APDU (Asynchronous)
    with pytest.raises(ExceptionRAPDU) as err:
        with client.set_slot(slot=slot, address=address, path=path, curve=curve, hash_t=hash_t):
            util_navigate(firmware, navigator, test_name, "REJECT_SLOT")

    # Assert we have received a refusal
    assert err.value.status == Errors.SW_COMMAND_NOT_ALLOWED
    assert len(err.value.data) == 0
