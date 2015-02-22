from datetime import datetime

from sslscan import modules
from sslscan.module.scan import BaseScan

import flextls
from flextls.exception import NotEnoughData
from flextls.protocol.handshake import Handshake, ServerHello
from flextls.protocol.record import SSLv3Record
from flextls.protocol.alert import Alert
import six

if six.PY2:
    import socket
    ConnectionError = socket.error


class ServerSCSV(BaseScan):
    """
    Detect if the server supports the Signaling Cipher Suite Value (SCSV).
    """

    name = "server.scsv"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def _connect_with_scsv(self, protocol_version, cipher_suites):
        cipher_suites = cipher_suites[:]
        cipher_suites.append(0x5600)

        conn = self._scanner.handler.connect()
        conn.settimeout(2.0)

        record_tls_hello = self._build_tls_base_client_hello(
            protocol_version,
            cipher_suites
        )

        conn.send(record_tls_hello.encode())

        time_start = datetime.now()
        data = b""
        proto_version = (
            record_tls_hello.version.major,
            record_tls_hello.version.minor
        )
        while True:
            tmp_time = datetime.now() - time_start
            if tmp_time.total_seconds() > 5.0:
                conn.close()
                return None

            try:
                tmp_data = conn.recv(4096)
            except ConnectionError:
                conn.close()
                return None

            data += tmp_data
            while True:
                try:
                    (record, data) = SSLv3Record.decode(data)
                except NotEnoughData:
                    break

                if isinstance(record.payload, Handshake):
                    if isinstance(record.payload.payload, ServerHello):
                        conn.close()
                        if proto_version[0] == record.version.major \
                            and proto_version[1] == record.version.minor:
                            return False
                        return None

                elif isinstance(record.payload, Alert):
                    conn.close()
                    if record.payload.level == 2 and \
                        record.payload.description == 86:
                            return True
                    return None

    def run(self):
        kb = self._scanner.get_knowledge_base()
        protocol_versions = self._scanner.get_enabled_versions()
        protocol_versions.reverse()
        scsv_status = None
        kb.set("server.security.scsv", None)
        for protocol_version in protocol_versions:
            if protocol_version != flextls.registry.version.SSLv2:
                cipher_suites = flextls.registry.tls.cipher_suites.get_ids()
                scsv_cur_status = None
                try:
                    scsv_cur_status = self._connect_with_scsv(
                        protocol_version,
                        cipher_suites
                    )
                except Timeout:
                    continue

                if scsv_cur_status is None:
                    continue
                
                if scsv_cur_status is True:
                    kb.set("server.security.scsv", True)
                    break

                if scsv_status is False and  scsv_cur_status is False:
                    kb.set("server.security.scsv", False)
                    break

                scsv_status = scsv_cur_status


modules.register(ServerSCSV)
