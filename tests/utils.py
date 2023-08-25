from pathlib import Path
from hashlib import sha256, sha3_256

from ecdsa.curves import Curve
from ecdsa.curves import SECP256k1, NIST256p
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der

from application_client.flow_command_sender import FlowCommandSender, Errors, HashType
from application_client.flow_response_unpacker import unpack_get_public_key_response

from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.conftest.configuration import OPTIONAL
from ragger.navigator import NavInsID, NavIns, Navigator
from ragger.firmware import Firmware

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()
TX_DOMAIN_TAG = "FLOW-V0.0-transaction"
DOMAIN_TAG_LENGTH = 32


def _init_header() -> bytes:
    """ Prepare the message Header (DOMAIN_TAG) """

    hdr = TX_DOMAIN_TAG.encode("utf-8").hex()
    pad_size = DOMAIN_TAG_LENGTH - len(TX_DOMAIN_TAG)
    hdr += bytearray([0] * pad_size).hex()
    return bytes.fromhex(hdr)


def util_check_signature(
        public_key: bytes,
        signature: bytes,
        message: bytes,
        curve: CurveChoice,
        hash_t: HashType,
) -> bool:
    """ Check if the signature of a given message is valid """

    # Convert curve value between bip to ecdsa
    ec_curve: Curve
    if curve == CurveChoice.Nist256p1:
        ec_curve = NIST256p
    elif curve == CurveChoice.Secp256k1:
        ec_curve = SECP256k1
    else:
        raise ValueError(f'Wrong Cruve "{curve}"')

    # Convert hash value to get the function
    if hash_t == HashType.HASH_SHA2:
        hashfunc = sha256
    elif hash_t == HashType.HASH_SHA3:
        hashfunc = sha3_256
    else:
        raise ValueError(f'Wrong Hash "{hash_t}"')

    key: VerifyingKey = VerifyingKey.from_string(public_key, ec_curve, hashfunc)

    # Prepare the message Header (DOMAIN_TAG)
    data = _init_header() + message

    assert key.verify(signature, data, hashfunc, sigdecode_der)


def util_check_pub_key(
        client: FlowCommandSender,
        path: str,
        curve: CurveChoice,
        hash_t: HashType = HashType.HASH_SHA2,
) -> None:
    """ Retrieve and check the public key """

    # Send the APDU (Asynchronous)
    response = client.get_public_key_no_confirmation(path, curve, hash_t)
    assert response.status == Errors.SW_SUCCESS

    # Parse the response (Asynchronous)
    public_key = unpack_get_public_key_response(response.data)
    # Compute the reference data
    ref_public_key, _ = calculate_public_key_and_chaincode(curve, path, OPTIONAL.CUSTOM_SEED)
    # Check expected value
    assert public_key == ref_public_key

    return bytes.fromhex(public_key)


def util_set_slot(
        client: FlowCommandSender,
        firmware: Firmware,
        navigator: Navigator,
        test_name: Path,
        slot: int,
        curve: CurveChoice = CurveChoice.Secp256k1,
        hash_t: HashType = HashType.HASH_SHA2,
        address: str = "0000000000000000", path: str = "m/0/0/0/0/0",
) -> None:
    """ Function to Set Slot parameters """

    # Send the APDU (Asynchronous)
    with client.set_slot(slot, address, path, curve, hash_t):
        util_navigate(firmware, navigator, test_name, "APPROVE", False)

    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response.status == Errors.SW_SUCCESS


def util_set_expert_mode(
        firmware: Firmware,
        navigator: Navigator,
        test_name: Path,
) -> None:
    """ Navigate in the menus to toggle Expert Mode """

    if firmware.device.startswith("nano"):
        instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.LEFT_CLICK,
        ]
    else:
        instructions = [
            NavInsID.USE_CASE_HOME_INFO,
            NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT
        ]
    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions,
                                   screen_change_before_first_instruction=False)


def util_navigate(
        firmware: Firmware,
        navigator: Navigator,
        test_name: Path,
        text: str = "",
        compare: bool = True,
        timeout: int = 300,
) -> None:
    """ Navigate in the menus with conditions """

    if firmware.device.startswith("nano"):
        if compare:
            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                    [NavInsID.BOTH_CLICK],
                                                    text,
                                                    ROOT_SCREENSHOT_PATH,
                                                    test_name,
                                                    timeout=timeout)
        else:
            navigator.navigate_until_text(NavInsID.RIGHT_CLICK,
                                        [NavInsID.BOTH_CLICK],
                                        text,
                                        timeout=timeout)
    else:
        if text == "APPROVE":
            instructions = [
                NavInsID.USE_CASE_REVIEW_TAP,
                NavIns(NavInsID.TOUCH, (200, 335)),
                NavInsID.USE_CASE_ADDRESS_CONFIRMATION_EXIT_QR,
                NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ]
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                        test_name,
                                        instructions,
                                        timeout=timeout)
        elif text == "REJECT":
            instructions_set = [
                [
                    NavInsID.USE_CASE_REVIEW_REJECT,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ],
                [
                    NavInsID.USE_CASE_REVIEW_TAP,
                    NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CANCEL,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ]
            ]
            for i, instructions in enumerate(instructions_set):
                navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                            test_name + f"/part{i}",
                                            instructions,
                                            timeout=timeout)
        else:
            navigator.navigate_until_text_and_compare(NavInsID.USE_CASE_REVIEW_TAP,
                                                    [NavInsID.USE_CASE_REVIEW_CONFIRM,
                                                    NavInsID.USE_CASE_STATUS_DISMISS],
                                                    text,
                                                    ROOT_SCREENSHOT_PATH,
                                                    test_name,
                                                    timeout=timeout)
