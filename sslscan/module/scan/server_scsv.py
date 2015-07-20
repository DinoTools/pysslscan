from datetime import datetime

from sslscan import modules
from sslscan.module.scan import BaseScan

import flextls
from flextls.exception import NotEnoughData
from flextls.field import CipherSuiteField
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
        def hook_cipher_suites(record):
            cipher_suites = flextls.registry.tls.cipher_suites[:]
            for cipher_suite in cipher_suites:
                cipher = CipherSuiteField()
                cipher.value = cipher_suite.id
                record.payload.cipher_suites.append(cipher)

            cipher = CipherSuiteField()
            cipher.value = 0x5600
            record.payload.cipher_suites.append(cipher)

            return record

        def stop_condition(record, records):
            return isinstance(record, Handshake) and \
                   isinstance(record.payload, ServerHello)

        ver_major, ver_minor = flextls.helper.get_tls_version(protocol_version)

        records = self.connect(
            protocol_version,
            stop_condition=stop_condition
        )

        if records is None:
            return None
            server_hello = None

        for record in records:
            if isinstance(record, Handshake):
                if isinstance(record.payload, ServerHello):
                    if record.version.major == ver_major and \
                            record.version.minor == ver_minor:
                        return False
            elif isinstance(record.payload, Alert):
                if record.payload.level == 2 and \
                        record.payload.description == 86:
                    return True

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
