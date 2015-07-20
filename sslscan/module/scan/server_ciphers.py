from datetime import datetime

import flextls
from flextls.exception import NotEnoughData
from flextls.field import CipherSuiteField, CompressionMethodField
from flextls.field import SSLv2CipherSuiteField
from flextls.protocol.handshake import ClientHello, Handshake, ServerHello, DTLSv10Handshake
from flextls.protocol.handshake import SSLv2ClientHello, SSLv2ServerHello
from flextls.protocol.handshake.extension import EllipticCurves, SignatureAlgorithms, Extension, SessionTicketTLS
from flextls.protocol.record import SSLv2Record, SSLv3Record

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

    def _scan_cipher_suites(self, protocol_version, cipher_suites, limit=False):
        def hook_cipher_suites(record, cipher_suites=None):
            for i in cipher_suites:
                cipher = CipherSuiteField()
                cipher.value = i
                record.payload.cipher_suites.append(cipher)
            return record

        def stop_condition(record, records):
            return isinstance(record, (Handshake, DTLSv10Handshake)) and \
                isinstance(record.payload, ServerHello)


        is_dtls = False
        if protocol_version & flextls.registry.version.DTLS != 0:
            is_dtls = True

        # Get IDs of allowed cipher suites
        tmp = []
        for cipher_suite in cipher_suites:
            if not is_dtls or (is_dtls and cipher_suite.dtls):
                tmp.append(cipher_suite.id)
        cipher_suites = tmp

        if is_dtls:
            self.build_dtls_client_hello_hooks.connect(
                hook_cipher_suites,
                name="cipher_suites",
                args={
                    "cipher_suites": cipher_suites
                }
            )
        else:
            self.build_tls_client_hello_hooks.connect(
                hook_cipher_suites,
                name="cipher_suites",
                args={
                    "cipher_suites": cipher_suites
                }
            )

        detected_ciphers = []
        count = 0
        while True:
            records = self.connect(
                protocol_version,
                stop_condition=stop_condition
            )
            if records is None:
                return detected_ciphers

            server_hello = None
            for record in records:
                if isinstance(record, (Handshake, DTLSv10Handshake)):
                    if isinstance(record.payload, ServerHello):
                        server_hello = record.payload

            if server_hello is None:
                return detected_ciphers

            detected_ciphers.append(server_hello.cipher_suite)
            cipher_suites.remove(server_hello.cipher_suite)

            count += 1
            if limit is not False and limit <= count:
                return detected_ciphers

        return detected_ciphers

    def run(self):
        kb = self._scanner.get_knowledge_base()
        for protocol_version in self._scanner.get_enabled_versions():
            if protocol_version == flextls.registry.version.SSLv2:
                cipher_suites = flextls.registry.sslv2.cipher_suites.get_ids()
                detected_ciphers = []
                try:
                    detected_ciphers = self._scan_ssl2_cipher_suites(
                        protocol_version,
                        cipher_suites
                    )
                except Timeout:
                    continue

                for cipher_id in detected_ciphers:
                    cipher_suite = flextls.registry.sslv2.cipher_suites.get(
                        cipher_id
                    )
                    kb.append(
                        "server.ciphers",
                        CipherResult(
                            protocol_version=protocol_version,
                            cipher_suite=cipher_suite,
                            status=1,
                        )
                    )
            else:
                cipher_suites = flextls.registry.tls.cipher_suites[:]
                detected_ciphers = []
                try:
                    detected_ciphers = self._scan_cipher_suites(
                        protocol_version,
                        cipher_suites
                    )
                except Timeout:
                    continue
                for cipher_id in detected_ciphers:
                    cipher_suite = flextls.registry.tls.cipher_suites.get(
                        cipher_id
                    )
                    kb.append(
                        "server.ciphers",
                        CipherResult(
                            protocol_version=protocol_version,
                            cipher_suite=cipher_suite,
                            status=1,
                        )
                    )


modules.register(ServerCiphers)