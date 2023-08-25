from typing import Tuple
from struct import unpack


def _pop_sized_buf_from_buffer(buffer:bytes, size:int) -> Tuple[bytes, bytes]:
    """ Parse buffer and returns: remainder, data[size] """

    return buffer[size:], buffer[0:size]


def _pop_size_prefixed_buf_from_buf(buffer:bytes) -> Tuple[bytes, int, bytes]:
    """ Parse buffer and returns: remainder, data_len, data """

    data_len = buffer[0]
    return buffer[1+data_len:], data_len, buffer[1:data_len+1]


def unpack_generic_response(response: bytes) -> Tuple[str, str, str, int]:
    """ Unpack response for 'generic' APDU:
            DEVICE_ID (4)
            SE_VER_len (1)
            SE_VER (var)
            FLAGS_len (1)
            FLAGS (var)
            MCU_VER_len (1)
            MCU_VER (var)
    """

    response, device_id = _pop_sized_buf_from_buffer(response, 4)
    response, _, se_ver = _pop_size_prefixed_buf_from_buf(response)
    response, _, flags = _pop_size_prefixed_buf_from_buf(response)
    response, _, mcu_ver = _pop_size_prefixed_buf_from_buf(response)

    d1, d2, d3, d4 = unpack("BBBB", device_id)
    dev_id = (d1 << 24) + (d2 << 16) + (d3 << 8) + d4

    return (se_ver.decode("ascii"), flags.decode("ascii"), mcu_ver.decode("ascii"), dev_id)


def unpack_get_version_response(response: bytes) -> Tuple[int, str, int, int]:
    """ Unpack response for 'get_version' APDU:
           TEST (1)
           MAJOR (1)
           MINOR (1)
           PATCH (1)
           LOCKED (1)
           DEVICE_ID (4)
    """

    assert len(response) == 9
    test, major, minor, patch, locked, d1, d2, d3, d4 = unpack("BBBBBBBBB", response)
    dev_id = (d1 << 24) + (d2 << 16) + (d3 << 8) + d4
    version = f"{major}.{minor}.{patch}"
    return (test, version, locked, dev_id)


def unpack_get_public_key_response(response: bytes) -> Tuple[bytes]:
    """ Unpack response for 'get_public_key' APDU:
           pub_key (65)
           pub_key_str (65 * 2)
    """

    data_len = 65
    assert len(response) == 3 * data_len

    pub_key = response[:data_len].hex()
    str_key = response[data_len:].hex()

    for index in range(data_len * 2):
        # Check Ascii code for each char
        pub_code = hex(ord(pub_key[index]))[2:]
        start = index * 2
        resp_str = str_key[start:start + 2]
        assert pub_code == resp_str

    return pub_key


def unpack_get_slot_response(response: bytes) -> Tuple[bytes, bytes, bytes]:
    """ Unpack response for 'get_slot' APDU:
           address (8)
           derivation_path (4 * 5)
           crypto_option (1 * 2)
    """

    assert len(response) == 8 + (4 * 5) + 2
    address = response[:8].hex()
    data_path = response[8:28].hex()
    option = response[28:30].hex()

    return address, data_path, option


def unpack_sign_tx_response(response: bytes) -> Tuple[int, bytes]:
    """ Unpack response for 'sign_tx' APDU:
           R_der_sig_len (1)
           R_der_sig (var)
           S_der_sig_len (1)
           S_der_sig (var)
           v (1)
           der_sig (var)
    """

    response, r = _pop_sized_buf_from_buffer(response, 32)
    response, s = _pop_sized_buf_from_buffer(response, 32)
    der_sig, v = _pop_sized_buf_from_buffer(response, 1)
    der_sig_len = len(der_sig)

    print(f"r[32] {r.hex()}")
    print(f"s[32] {s.hex()}")
    print(f"v[1]  {v.hex()}")
    print(f"der_sig [{der_sig_len}] {der_sig.hex()}")

    return der_sig_len, der_sig
