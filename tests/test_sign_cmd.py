from pathlib import Path
import json
import pytest

from application_client.flow_command_sender import FlowCommandSender, Errors, HashType
from application_client.flow_response_unpacker import unpack_sign_tx_response

from ragger.bip import CurveChoice
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator
from ragger.firmware import Firmware

from utils import ROOT_SCREENSHOT_PATH, util_check_signature, util_check_pub_key, util_set_slot, util_set_expert_mode, util_navigate


MANIFEST_FILE = f"{ROOT_SCREENSHOT_PATH}/testvectors/manifestEnvelopeCases.json"


# Note: Transactions are explained here: https://janezpodhostnik.github.io/flow-py-sdk/python_SDK_guide/#transactions


def _check_transaction(
        client: FlowCommandSender,
        firmware: Firmware,
        navigator: Navigator,
        test_name: Path,
        transaction: str,
        path: str,
        curve: CurveChoice,
        hash_t: HashType,
        timeout: int = 300,
) -> None:
    """ Check the transaction in confirmation mode when user accepts """

    # Retrieve and Check the public key
    public_key = util_check_pub_key(client, path, curve, hash_t)

    # Convert message to bytes
    message = bytes.fromhex(transaction)

    # Send the APDU (Asynchronous)
    with client.sign_tx(path, curve, message, hash_t):
        util_navigate(firmware, navigator, test_name, "APPROVE", False, timeout)

    # Send the APDU (Asynchronous)
    response = client.get_async_response()
    assert response.status == Errors.SW_SUCCESS

    # Parse the response
    _, der_sig = unpack_sign_tx_response(response.data)
    # Check the signature
    util_check_signature(public_key, der_sig, message, curve, hash_t)


def test_transaction_params(firmware, backend, navigator, test_name):
    """ Check transaction signing with different parameters """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)
    # Test parameters
    path: str = "m/44'/539'/513'/0/0"
    curve_list = [
        CurveChoice.Secp256k1,
        CurveChoice.Nist256p1,
    ]
    hash_list = [
        HashType.HASH_SHA2,
        HashType.HASH_SHA3,
    ]
    transactions = [
        "f9023ff9023bb90195696d706f72742046756e6769626c65546f6b656e2066726f6d203078656538323835366266323065326161360a7472616e73616374696f6e28616d6f756e743a205546697836342c20746f3a204164647265737329207b0a6c6574207661756c743a204046756e6769626c65546f6b656e2e5661756c740a70726570617265287369676e65723a20417574684163636f756e7429207b0a73656c662e7661756c74203c2d207369676e65720a2e626f72726f773c267b46756e6769626c65546f6b656e2e50726f76696465727d3e2866726f6d3a202f73746f726167652f666c6f77546f6b656e5661756c7429210a2e776974686472617728616d6f756e743a20616d6f756e74290a7d0a65786563757465207b0a6765744163636f756e7428746f290a2e6765744361706162696c697479282f7075626c69632f666c6f77546f6b656e526563656976657229210a2e626f72726f773c267b46756e6769626c65546f6b656e2e52656365697665727d3e2829210a2e6465706f7369742866726f6d3a203c2d73656c662e7661756c74290a7d0a7df861b07b2274797065223a22554669783634222c2276616c7565223a223138343436373434303733372e39353531363135227daf7b2274797065223a2241646472657373222c2276616c7565223a22307866386436653035383662306132306337227da0f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b2a88f8d6e0586b0a20c7040a88f8d6e0586b0a20c7c988f8d6e0586b0a20c7c0",
        "f90289f90261b8a97472616e73616374696f6e287075626c69634b6579733a205b537472696e675d29207b0a70726570617265287369676e65723a20417574684163636f756e7429207b0a6c65742061636374203d20417574684163636f756e742870617965723a207369676e6572290a666f72206b657920696e207075626c69634b657973207b0a616363742e6164645075626c69634b6579286b65792e6465636f64654865782829290a7d0a7d0a7df90173b901707b2274797065223a224172726179222c2276616c7565223a5b7b2274797065223a22537472696e67222c2276616c7565223a2266383435623834303934343838613739356130373730306336666238336530363663663537646664383766393263653730636263383163623362643366656132646637623637303733623730653336623434663335373862343364363464336661613265386534313565663663326235666534333930643561373865323338353831633665346263333033303330227d2c7b2274797065223a22537472696e67222c2276616c7565223a2266383435623834303934343838613739356130373730306336666238336530363663663537646664383766393263653730636263383163623362643366656132646637623637303733623730653336623434663335373862343364363464336661613265386534313565663663326235666534333930643561373865323338353831633665346263333033303331227d5d7da0f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b2a88f8d6e0586b0a20c7040a88f8d6e0586b0a20c7c988f8d6e0586b0a20c7e4e38004a0f7225388c1d69d57e6251c9fda50cbbf9e05131e5adb81e5aa0422402f048162",
        "f90186f9015eb86e7472616e73616374696f6e287075626c69634b65793a20537472696e6729207b0a70726570617265287369676e65723a20417574684163636f756e7429207b0a7369676e65722e6164645075626c69634b6579287075626c69634b65792e6465636f64654865782829290a7d0a7df8acb8aa7b2274797065223a22537472696e67222c2276616c7565223a2266383435623834303934343838613739356130373730306336666238336530363663663537646664383766393263653730636263383163623362643366656132646637623637303733623730653336623434663335373862343364363464336661613265386534313565663663326235666534333930643561373865323338353831633665346263333033303330227da0f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b2a88f8d6e0586b0a20c7040a88f8d6e0586b0a20c7c988f8d6e0586b0a20c7e4e38004a0f7225388c1d69d57e6251c9fda50cbbf9e05131e5adb81e5aa0422402f048162",
    ]

    # Send the APDU and check the results
    for transaction in transactions:
        for curve in curve_list:
            for hash_t in hash_list:
                _check_transaction(client, firmware, navigator, test_name, transaction, path, curve, hash_t)


def test_transaction_expert(firmware, backend, navigator, test_name):
    """ Check transaction signing with expert mode """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)
    # Test parameters
    path: str = "m/44'/539'/0'/0/0"
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
    transaction = "f9023ff9023bb90195696d706f72742046756e6769626c65546f6b656e2066726f6d203078656538323835366266323065326161360a7472616e73616374696f6e28616d6f756e743a205546697836342c20746f3a204164647265737329207b0a6c6574207661756c743a204046756e6769626c65546f6b656e2e5661756c740a70726570617265287369676e65723a20417574684163636f756e7429207b0a73656c662e7661756c74203c2d207369676e65720a2e626f72726f773c267b46756e6769626c65546f6b656e2e50726f76696465727d3e2866726f6d3a202f73746f726167652f666c6f77546f6b656e5661756c7429210a2e776974686472617728616d6f756e743a20616d6f756e74290a7d0a65786563757465207b0a6765744163636f756e7428746f290a2e6765744361706162696c697479282f7075626c69632f666c6f77546f6b656e526563656976657229210a2e626f72726f773c267b46756e6769626c65546f6b656e2e52656365697665727d3e2829210a2e6465706f7369742866726f6d3a203c2d73656c662e7661756c74290a7d0a7df861b07b2274797065223a22554669783634222c2276616c7565223a223138343436373434303733372e39353531363135227daf7b2274797065223a2241646472657373222c2276616c7565223a22307866386436653035383662306132306337227da0f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b2a88f8d6e0586b0a20c7040a88f8d6e0586b0a20c7c988f8d6e0586b0a20c7c0"

    # Navigate in the main menu to change to expert mode
    util_set_expert_mode(firmware, navigator, test_name)

    # Send the APDU and check the results
    for cfg in test_cfg:
        _check_transaction(client, firmware, navigator, test_name, transaction, path, cfg["curve"], cfg["hash"])


def test_transaction_slot(firmware, backend, navigator, test_name):
    """ Check transaction signing with slot """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)
    # Test parameters
    path: str = "m/44'/539'/771'/0/0"
    bad_path: str = "m/44'/539'/771'/0/1"
    curve: CurveChoice = CurveChoice.Nist256p1
    hash_t: HashType = HashType.HASH_SHA3
    bad_hash: HashType = HashType.HASH_SHA2
    slot = 0
    transaction = "f9023ff9023bb90195696d706f72742046756e6769626c65546f6b656e2066726f6d203078656538323835366266323065326161360a7472616e73616374696f6e28616d6f756e743a205546697836342c20746f3a204164647265737329207b0a6c6574207661756c743a204046756e6769626c65546f6b656e2e5661756c740a70726570617265287369676e65723a20417574684163636f756e7429207b0a73656c662e7661756c74203c2d207369676e65720a2e626f72726f773c267b46756e6769626c65546f6b656e2e50726f76696465727d3e2866726f6d3a202f73746f726167652f666c6f77546f6b656e5661756c7429210a2e776974686472617728616d6f756e743a20616d6f756e74290a7d0a65786563757465207b0a6765744163636f756e7428746f290a2e6765744361706162696c697479282f7075626c69632f666c6f77546f6b656e526563656976657229210a2e626f72726f773c267b46756e6769626c65546f6b656e2e52656365697665727d3e2829210a2e6465706f7369742866726f6d3a203c2d73656c662e7661756c74290a7d0a7df861b07b2274797065223a22554669783634222c2276616c7565223a223138343436373434303733372e39353531363135227daf7b2274797065223a2241646472657373222c2276616c7565223a22307866386436653035383662306132306337227da0f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b2a88f8d6e0586b0a20c7040a88f8d6e0586b0a20c7c988f8d6e0586b0a20c7c0"
    address = "f8d6e0586b0a20c7"

    # Send the APDU and check the results
    _check_transaction(client, firmware, navigator, test_name, transaction, path, curve, hash_t)

    # Set slot to correct path correct address,
    util_set_slot(client, firmware, navigator, test_name, slot, curve, hash_t, address, path)

    # Sign the Tx again - incorrect hd path
    _check_transaction(client, firmware, navigator, test_name, transaction, bad_path, curve, hash_t)

    # Sign the Tx again - correct path
    _check_transaction(client, firmware, navigator, test_name, transaction, path, curve, hash_t)

    # e467b9dd11fa00df - used as incorrect address; f8d6e0586b0a20c7 - correct one
    transactions = [
        # tx - no match single authorizer,
        "f9023ff9023bb90195696d706f72742046756e6769626c65546f6b656e2066726f6d203078656538323835366266323065326161360a7472616e73616374696f6e28616d6f756e743a205546697836342c20746f3a204164647265737329207b0a6c6574207661756c743a204046756e6769626c65546f6b656e2e5661756c740a70726570617265287369676e65723a20417574684163636f756e7429207b0a73656c662e7661756c74203c2d207369676e65720a2e626f72726f773c267b46756e6769626c65546f6b656e2e50726f76696465727d3e2866726f6d3a202f73746f726167652f666c6f77546f6b656e5661756c7429210a2e776974686472617728616d6f756e743a20616d6f756e74290a7d0a65786563757465207b0a6765744163636f756e7428746f290a2e6765744361706162696c697479282f7075626c69632f666c6f77546f6b656e526563656976657229210a2e626f72726f773c267b46756e6769626c65546f6b656e2e52656365697665727d3e2829210a2e6465706f7369742866726f6d3a203c2d73656c662e7661756c74290a7d0a7df861b07b2274797065223a22554669783634222c2276616c7565223a223138343436373434303733372e39353531363135227daf7b2274797065223a2241646472657373222c2276616c7565223a22307866386436653035383662306132306337227da0f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b2a88e467b9dd11fa00df040a88e467b9dd11fa00dfc988e467b9dd11fa00dfc0",
        # tx - address matches payer
        "f9023ff9023bb90195696d706f72742046756e6769626c65546f6b656e2066726f6d203078656538323835366266323065326161360a7472616e73616374696f6e28616d6f756e743a205546697836342c20746f3a204164647265737329207b0a6c6574207661756c743a204046756e6769626c65546f6b656e2e5661756c740a70726570617265287369676e65723a20417574684163636f756e7429207b0a73656c662e7661756c74203c2d207369676e65720a2e626f72726f773c267b46756e6769626c65546f6b656e2e50726f76696465727d3e2866726f6d3a202f73746f726167652f666c6f77546f6b656e5661756c7429210a2e776974686472617728616d6f756e743a20616d6f756e74290a7d0a65786563757465207b0a6765744163636f756e7428746f290a2e6765744361706162696c697479282f7075626c69632f666c6f77546f6b656e526563656976657229210a2e626f72726f773c267b46756e6769626c65546f6b656e2e52656365697665727d3e2829210a2e6465706f7369742866726f6d3a203c2d73656c662e7661756c74290a7d0a7df861b07b2274797065223a22554669783634222c2276616c7565223a223138343436373434303733372e39353531363135227daf7b2274797065223a2241646472657373222c2276616c7565223a22307866386436653035383662306132306337227da0f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b2a88e467b9dd11fa00df040a88f8d6e0586b0a20c7c988e467b9dd11fa00dfc0",
        # tx - address matches proposer
        "f9023ff9023bb90195696d706f72742046756e6769626c65546f6b656e2066726f6d203078656538323835366266323065326161360a7472616e73616374696f6e28616d6f756e743a205546697836342c20746f3a204164647265737329207b0a6c6574207661756c743a204046756e6769626c65546f6b656e2e5661756c740a70726570617265287369676e65723a20417574684163636f756e7429207b0a73656c662e7661756c74203c2d207369676e65720a2e626f72726f773c267b46756e6769626c65546f6b656e2e50726f76696465727d3e2866726f6d3a202f73746f726167652f666c6f77546f6b656e5661756c7429210a2e776974686472617728616d6f756e743a20616d6f756e74290a7d0a65786563757465207b0a6765744163636f756e7428746f290a2e6765744361706162696c697479282f7075626c69632f666c6f77546f6b656e526563656976657229210a2e626f72726f773c267b46756e6769626c65546f6b656e2e52656365697665727d3e2829210a2e6465706f7369742866726f6d3a203c2d73656c662e7661756c74290a7d0a7df861b07b2274797065223a22554669783634222c2276616c7565223a223138343436373434303733372e39353531363135227daf7b2274797065223a2241646472657373222c2276616c7565223a22307866386436653035383662306132306337227da0f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b2a88f8d6e0586b0a20c7040a88e467b9dd11fa00dfc988e467b9dd11fa00dfc0",
        # tx - address matches sole authorizer
        "f9023ff9023bb90195696d706f72742046756e6769626c65546f6b656e2066726f6d203078656538323835366266323065326161360a7472616e73616374696f6e28616d6f756e743a205546697836342c20746f3a204164647265737329207b0a6c6574207661756c743a204046756e6769626c65546f6b656e2e5661756c740a70726570617265287369676e65723a20417574684163636f756e7429207b0a73656c662e7661756c74203c2d207369676e65720a2e626f72726f773c267b46756e6769626c65546f6b656e2e50726f76696465727d3e2866726f6d3a202f73746f726167652f666c6f77546f6b656e5661756c7429210a2e776974686472617728616d6f756e743a20616d6f756e74290a7d0a65786563757465207b0a6765744163636f756e7428746f290a2e6765744361706162696c697479282f7075626c69632f666c6f77546f6b656e526563656976657229210a2e626f72726f773c267b46756e6769626c65546f6b656e2e52656365697665727d3e2829210a2e6465706f7369742866726f6d3a203c2d73656c662e7661756c74290a7d0a7df861b07b2274797065223a22554669783634222c2276616c7565223a223138343436373434303733372e39353531363135227daf7b2274797065223a2241646472657373222c2276616c7565223a22307866386436653035383662306132306337227da0f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b2a88e467b9dd11fa00df040a88e467b9dd11fa00dfc988f8d6e0586b0a20c7c0",
        # tx - no match multiple authorizers
        "f90251f9024db90195696d706f72742046756e6769626c65546f6b656e2066726f6d203078656538323835366266323065326161360a7472616e73616374696f6e28616d6f756e743a205546697836342c20746f3a204164647265737329207b0a6c6574207661756c743a204046756e6769626c65546f6b656e2e5661756c740a70726570617265287369676e65723a20417574684163636f756e7429207b0a73656c662e7661756c74203c2d207369676e65720a2e626f72726f773c267b46756e6769626c65546f6b656e2e50726f76696465727d3e2866726f6d3a202f73746f726167652f666c6f77546f6b656e5661756c7429210a2e776974686472617728616d6f756e743a20616d6f756e74290a7d0a65786563757465207b0a6765744163636f756e7428746f290a2e6765744361706162696c697479282f7075626c69632f666c6f77546f6b656e526563656976657229210a2e626f72726f773c267b46756e6769626c65546f6b656e2e52656365697665727d3e2829210a2e6465706f7369742866726f6d3a203c2d73656c662e7661756c74290a7d0a7df861b07b2274797065223a22554669783634222c2276616c7565223a223138343436373434303733372e39353531363135227daf7b2274797065223a2241646472657373222c2276616c7565223a22307866386436653035383662306132306337227da0f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b2a88e467b9dd11fa00df040a88e467b9dd11fa00dfdb88e467b9dd11fa00df88e467b9dd11fa00df88e467b9dd11fa00dfc0",
        # tx - address matches 3rd auhorizer out of three
        "f90251f9024db90195696d706f72742046756e6769626c65546f6b656e2066726f6d203078656538323835366266323065326161360a7472616e73616374696f6e28616d6f756e743a205546697836342c20746f3a204164647265737329207b0a6c6574207661756c743a204046756e6769626c65546f6b656e2e5661756c740a70726570617265287369676e65723a20417574684163636f756e7429207b0a73656c662e7661756c74203c2d207369676e65720a2e626f72726f773c267b46756e6769626c65546f6b656e2e50726f76696465727d3e2866726f6d3a202f73746f726167652f666c6f77546f6b656e5661756c7429210a2e776974686472617728616d6f756e743a20616d6f756e74290a7d0a65786563757465207b0a6765744163636f756e7428746f290a2e6765744361706162696c697479282f7075626c69632f666c6f77546f6b656e526563656976657229210a2e626f72726f773c267b46756e6769626c65546f6b656e2e52656365697665727d3e2829210a2e6465706f7369742866726f6d3a203c2d73656c662e7661756c74290a7d0a7df861b07b2274797065223a22554669783634222c2276616c7565223a223138343436373434303733372e39353531363135227daf7b2274797065223a2241646472657373222c2276616c7565223a22307866386436653035383662306132306337227da0f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b2a88e467b9dd11fa00df040a88e467b9dd11fa00dfdb88e467b9dd11fa00df88e467b9dd11fa00df88f8d6e0586b0a20c7c0",
    ]

    # Send the APDU and check the results
    for blob in transactions:
        _check_transaction(client, firmware, navigator, test_name, blob, path, curve, hash_t)

    # sign the Tx again - correct path - wrong hash
    _check_transaction(client, firmware, navigator, test_name, transaction, path, curve, bad_hash)

    # Now delete the slot so that the next test starts in a clean state
    util_set_slot(client, firmware, navigator, test_name, slot)


def test_transaction_invalid(firmware, backend, navigator, test_name):
    """ Check invalid transaction signing """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)
    # Test parameters
    path: str = "m/44'/539'/513'/0/0"
    curve: CurveChoice = CurveChoice.Secp256k1
    hash_t: HashType = HashType.HASH_SHA2
    # Prepare an invalid message
    bad_essage = "1234567890"
    transaction = bad_essage.encode("utf-8").hex()

    # Send the APDU and check the results
    try:
        _check_transaction(client, firmware, navigator, test_name, transaction, path, curve, hash_t, 5)
    except TimeoutError:
        pass


def test_transaction_refused(firmware, backend, navigator, test_name):
    """ Check transaction signing in confirmation mode when user refuses """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)
    # Test parameters
    path: str = "m/44'/539'/0'/0/0"
    curve: CurveChoice = CurveChoice.Nist256p1
    hash_t = HashType.HASH_SHA2
    transaction = "f9023ff9023bb90195696d706f72742046756e6769626c65546f6b656e2066726f6d203078656538323835366266323065326161360a7472616e73616374696f6e28616d6f756e743a205546697836342c20746f3a204164647265737329207b0a6c6574207661756c743a204046756e6769626c65546f6b656e2e5661756c740a70726570617265287369676e65723a20417574684163636f756e7429207b0a73656c662e7661756c74203c2d207369676e65720a2e626f72726f773c267b46756e6769626c65546f6b656e2e50726f76696465727d3e2866726f6d3a202f73746f726167652f666c6f77546f6b656e5661756c7429210a2e776974686472617728616d6f756e743a20616d6f756e74290a7d0a65786563757465207b0a6765744163636f756e7428746f290a2e6765744361706162696c697479282f7075626c69632f666c6f77546f6b656e526563656976657229210a2e626f72726f773c267b46756e6769626c65546f6b656e2e52656365697665727d3e2829210a2e6465706f7369742866726f6d3a203c2d73656c662e7661756c74290a7d0a7df861b07b2274797065223a22554669783634222c2276616c7565223a223138343436373434303733372e39353531363135227daf7b2274797065223a2241646472657373222c2276616c7565223a22307866386436653035383662306132306337227da0f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b2a88f8d6e0586b0a20c7040a88f8d6e0586b0a20c7c988f8d6e0586b0a20c7c0"

    # Convert message to bytes
    message = bytes.fromhex(transaction)

    # Send the APDU (Asynchronous)
    with pytest.raises(ExceptionRAPDU) as err:
        with client.sign_tx(path, curve, message, hash_t):
            util_navigate(firmware, navigator, test_name, "REJECT")

        # Assert we have received a refusal
        assert err.value.status == Errors.SW_COMMAND_NOT_ALLOWED
        assert len(err.value.data) == 0


def test_transaction_manifest(firmware, backend, navigator, test_name):
    """ Check transaction signing in confirmation mode when user refuses """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)
    # Test parameters
    path: str = "m/44'/539'/0'/0/0"
    curve: CurveChoice = CurveChoice.Nist256p1
    hash_t = HashType.HASH_SHA3

    try:
        with open(MANIFEST_FILE, "r", encoding="utf-8") as fcc_file:
            test_cases = json.load(fcc_file)
    except OSError as err:
        print(f"open() failed: {err}")

    for elt in test_cases:
        if elt["chainID"] == "Mainnet":
            print(f"Found: {elt['title']}")
            transaction = elt["encodedTransactionEnvelopeHex"]
            # Send the APDU and check the results
            _check_transaction(client, firmware, navigator, test_name, transaction, path, curve, hash_t)