import ctypes
from pathlib import Path

_lib_path = Path(__file__).with_name("libhsm_tls.so")
_lib = ctypes.CDLL(str(_lib_path))

_lib.hsm_connect.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_lib.hsm_connect.restype = ctypes.c_int

_lib.hsm_send.argtypes = [ctypes.c_char_p, ctypes.c_int]
_lib.hsm_send.restype = ctypes.c_int

_lib.hsm_recv.argtypes = [ctypes.c_char_p, ctypes.c_int]
_lib.hsm_recv.restype = ctypes.c_int

_lib.hsm_close.argtypes = []
_lib.hsm_close.restype = None


class HSMTLSClient:
    def __init__(self, host, port, sni, psk):
        self.host = host
        self.port = str(port)
        self.sni = sni

        if isinstance(psk, bytes):
            self.psk_hex = psk.hex()
        else:
            self.psk_hex = str(psk)

    def connect(self):
        ret = _lib.hsm_connect(
            self.host.encode(),
            self.port.encode(),
            self.sni.encode(),
            self.psk_hex.encode(),
        )

        if ret != 0:
            raise ConnectionError("HSM TLS connection failed")

    def send(self, data):
        ret = _lib.hsm_send(data, len(data))

        if ret <= 0:
            raise ConnectionError("HSM TLS send failed")

        return ret

    def recv(self, size):
        buffer = ctypes.create_string_buffer(size)

        ret = _lib.hsm_recv(buffer, size)

        if ret <= 0:
            return b""

        return buffer.raw[:ret]

    def close(self):
        _lib.hsm_close()