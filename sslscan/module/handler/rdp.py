from socket import socket

from sslscan import modules
from sslscan.exception import StartTLSError
from sslscan.module.handler.tcp import TCP


class RDP(TCP):
    """
    Handle RDP-connections.
    """

    name = "rdp"

    config_options = TCP.config_options + [
        (
            "starttls", {
                "default": False,
                "help": "",
                "type": "bool"
            }
        )
    ]

    def __init__(self, **kwargs):
        self.port = 3389
        TCP.__init__(self, **kwargs)

    def connect(self):
        # ToDo: raise exception
        conn = TCP.connect(self)
        if not self.config.get_value("starttls"):
            return conn

        conn.send(b"\x03\x00\x00\x13\x0E\xE0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")

        buf = conn.recv(4)

        if not buf or len(buf) != 4 or buf[:2] != b"\x03\x00":
            raise StartTLSError()

        import struct
        packet_len = struct.unpack(">H", buf[2:])[0] - 4
        data = conn.recv(packet_len)
        if not data or len(data) != packet_len :
            raise StartTLSError()

        return conn

modules.register(RDP)
