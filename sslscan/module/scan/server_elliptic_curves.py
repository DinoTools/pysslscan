import flextls
from flextls.protocol.handshake.extension import EllipticCurves

from sslscan import modules
from sslscan.exception import Timeout
from sslscan.kb import ECResult
from sslscan.module.scan import BaseScan


class EllipticCurves(BaseScan):
    """
    Scan for supported elliptic curves.
    """

    name = "server.elliptic_curves"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def run(self):
        kb = self._scanner.get_knowledge_base()
        for protocol_version in self._scanner.get_enabled_versions():
            if protocol_version == flextls.registry.version.SSLv2:
                continue

            cipher_suites = []
            for cipher_suite in flextls.registry.tls.cipher_suites[:]:
                if cipher_suite.key_exchange.startswith("ECD"):
                    cipher_suites.append(cipher_suite)

            elliptic_curves = flextls.registry.ec.named_curves[:]
            try:
                detected_elliptic_curves = self._scan_elliptic_curves(
                    protocol_version,
                    cipher_suites,
                    elliptic_curves=elliptic_curves
                )
            except Timeout:
                continue

            for ec_id in detected_elliptic_curves:
                elliptic_curve = flextls.registry.ec.named_curves.get(
                    ec_id
                )
                kb.append(
                    "server.ec.named_curves",
                    ECResult(
                        protocol_version=protocol_version,
                        elliptic_curve=elliptic_curve
                    )
                )

modules.register(EllipticCurves)
