from datetime import datetime

import flextls
from flextls.exception import NotEnoughData
from flextls.field import CipherSuiteField, CompressionMethodField
from flextls.field import SSLv2CipherSuiteField
from flextls.protocol.handshake import ClientHello, Handshake, ServerHello
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
