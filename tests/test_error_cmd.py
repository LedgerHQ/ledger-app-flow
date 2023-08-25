import pytest

from application_client.flow_command_sender import ClaType, InsType, P1, P2, Errors

from ragger.error import ExceptionRAPDU


def test_bad_cla(backend):
    """ Ensure the app returns an error when a bad CLA is used """

    with pytest.raises(ExceptionRAPDU) as err:
        backend.exchange(cla=ClaType.CLA_APP + 1, ins=InsType.GET_VERSION)
    assert err.value.status == Errors.SW_CLA_NOT_SUPPORTED


def test_bad_ins(backend):
    """ Ensure the app returns an error when a bad INS is used """

    with pytest.raises(ExceptionRAPDU) as err:
        backend.exchange(cla=ClaType.CLA_APP, ins=0xff)
    assert err.value.status == Errors.SW_INS_NOT_SUPPORTED


def test_wrong_p1p2(backend):
    """ Ensure the app returns an error when a bad P1 or P2 is used """

    with pytest.raises(ExceptionRAPDU) as err:
        backend.exchange(cla=ClaType.CLA_APP, ins=InsType.SIGN, p1=P1.P1_LAST + 1, p2=P2.P2_MORE)
    assert err.value.status == Errors.SW_INVALIDP1P2


def test_wrong_data_length(backend):
    """ Ensure the app returns an error when a bad data length is used """

    data: bytes = bytes()
    data += int(ClaType.CLA_APP).to_bytes(1, byteorder='little')
    data += int(InsType.GET_PUBKEY).to_bytes(1, byteorder='little')
    data += bytes.fromhex("000001")
    with pytest.raises(ExceptionRAPDU) as err:
        backend.exchange_raw(data)
    assert err.value.status == Errors.SW_WRONG_LENGTH
