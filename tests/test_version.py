from application_client.flow_command_sender import FlowCommandSender, Errors
from application_client.flow_response_unpacker import unpack_get_version_response, unpack_generic_response

from ragger.utils.misc import get_current_app_name_and_version


class TargetId():
    """ Target ID definitions """

    def __init__(self) -> None:
        self.data = {
            "nanos":  0x31100004,
            "nanosp": 0x33100004,
            "nanox":  0x33000004,
            "stax":   0x33200004,
        }

    def check(self, device: str, target_id: int) -> None:
        """ Check the provides Target ID versus the device name """

        assert target_id == self.data[device]


def test_check_name_version(backend):
    """ Check version and name """

    # Send the APDU
    app_name, version = get_current_app_name_and_version(backend)
    print(f" Name: {app_name}")
    print(f" Version: {version}")
    # Check expected value
    assert app_name == "app"
    assert version == "1.33.7"


def test_get_app_version(firmware, backend):
    """ Get the version of the current app """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)

    # Send the APDU
    response = client.get_app_version()
    assert response.status == Errors.SW_SUCCESS

    # Parse the response
    test, version, locked, device_id = unpack_get_version_response(response.data)
    print(f" TEST: {test}")
    print(f" VERSION: {version}")
    print(f" LOCKED: {locked}")
    print(f" device_id: {hex(device_id)}")

    # Check expected value
    TargetId().check(firmware.device, device_id)
    assert version == "0.11.0"


def test_get_generic(firmware, backend):
    """ Get generic info """

    # Use the app interface instead of raw interface
    client = FlowCommandSender(backend)

    # Send the APDU
    response = client.get_generic()
    assert response.status == Errors.SW_SUCCESS

    # Parse the response
    se_ver, flags, mcu_ver, device_id = unpack_generic_response(response.data)
    print(f" SE: {se_ver}")
    print(f" FLAGS: {flags}")
    print(f" MCU: {mcu_ver}")
    print(f" device_id: {hex(device_id)}")

    # Check expected value
    TargetId().check(firmware.device, device_id)
