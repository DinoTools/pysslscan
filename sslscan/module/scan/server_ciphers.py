from datetime import datetime

import flextls
from flextls.exception import NotEnoughData
from flextls.field import CipherSuiteField, CompressionMethodField
from flextls.field import SSLv2CipherSuiteField
from flextls.protocol.handshake import ClientHello, Handshake, ServerHello
from flextls.protocol.handshake import SSLv2ClientHello, SSLv2ServerHello
from flextls.protocol.handshake.extension import EllipticCurves, SignatureAlgorithms, Extension, SessionTicketTLS
from flextls.protocol.record import RecordSSLv2, RecordSSLv3

from sslscan import modules
from sslscan.exception import Timeout
from sslscan.kb import CipherResult
from sslscan.module.scan import BaseScan


class ServerCiphers(BaseScan):
    """
    Test a server for provided ciphers.
    """

    name = "server.ciphers"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def _scan_ssl2(self, protocol_version):
        kb = self._scanner.get_knowledge_base()
        cipher_suites = flextls.registry.sslv2.cipher_suites.get_ids()

        conn = self._scanner.handler.connect()

        hello = SSLv2ClientHello()
        hello.version.major = 0
        hello.version.minor = 2
        hello.challenge = b"A"*16

        for i in cipher_suites:
            cipher = SSLv2CipherSuiteField()
            cipher.value = i
            hello.cipher_suites.append(cipher)

        msg_hello = RecordSSLv2() + hello

        conn.send(msg_hello.encode())

        time_start = datetime.now()
        data = b""
        while True:
            tmp_time = datetime.now() - time_start
            if tmp_time.total_seconds() > 5.0:
                raise Timeout()

            tmp_data = conn.recv(4096)
            if len(tmp_data) == 0:
                raise Timeout()

            data += tmp_data

            try:
                (record, data) = RecordSSLv2.decode(data)
            except NotEnoughData:
                continue

            if isinstance(record.payload, SSLv2ServerHello):
                for i in record.payload.cipher_suites:
                    cipher_suite = flextls.registry.sslv2.cipher_suites.get(i.value)
                    kb.append(
                        'server.ciphers',
                        CipherResult(
                            protocol_version=protocol_version,
                            cipher_suite=cipher_suite,
                            status=1,
                        )
                    )
                break

    def run(self):
        kb = self._scanner.get_knowledge_base()
        for protocol_version in self._scanner.get_enabled_versions():
            if protocol_version == flextls.registry.version.SSLv2:
                try:
                    self._scan_ssl2(protocol_version)
                except Timeout:
                    pass
            else:
                cipher_suites = flextls.registry.tls.cipher_suites.get_ids()
                try:
                    detected_ciphers = self._scan_cipher_suites_tls(protocol_version, cipher_suites)
                except Timeout:
                    continue
                for cipher_id in detected_ciphers:
                    cipher_suite = flextls.registry.tls.cipher_suites.get(
                        cipher_id
                    )
                    kb.append(
                        'server.ciphers',
                        CipherResult(
                            protocol_version=protocol_version,
                            cipher_suite=cipher_suite,
                            status=1,
                        )
                    )

modules.register(ServerCiphers)
