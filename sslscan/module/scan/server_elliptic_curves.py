import flextls
from flextls.field import ServerECDHParamsField, ECParametersNamedCurveField
from flextls.protocol.handshake import Handshake, ServerKeyExchange, ServerKeyExchangeECDSA, DTLSv10Handshake
from flextls.protocol.handshake.extension import EllipticCurves, Extension

from sslscan import modules
from sslscan.exception import Timeout
from sslscan.kb import ECResult
from sslscan.module.scan import BaseScan


class ServerEllipticCurves(BaseScan):
    """
    Scan for supported elliptic curves.
    """

    name = "server.elliptic_curves"
    alias = ("elliptic_curves",)

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def _scan_elliptic_curves(self, protocol_version, elliptic_curves, limit=False):
        """
        Scan for supported elliptic curves

        :param protocol_version:
        :param elliptic_curves: List of elliptic curves
        :param limit:
        :return: List of supported elliptic curve IDs
        """
        def hook_elliptic_curves(record, elliptic_curves=None):
            ext_elliptic_curves = EllipticCurves()
            a = ext_elliptic_curves.get_field("elliptic_curve_list")
            for i in elliptic_curves:
                v = a.item_class("unnamed", None)
                v.value = i
                a.value.append(v)

            record.payload.extensions.append(Extension() + ext_elliptic_curves)
            return record

        def stop_condition(record, records):
            return isinstance(record, (Handshake, DTLSv10Handshake)) and \
                isinstance(record.payload, ServerKeyExchange)

        is_dtls = False
        if protocol_version & flextls.registry.version.DTLS != 0:
            is_dtls = True

        tmp = []
        for elliptic_curve in elliptic_curves:
            tmp.append(elliptic_curve.id)
        elliptic_curves = tmp

        if is_dtls:
            self.build_dtls_client_hello_hooks.connect(
                hook_elliptic_curves,
                name="elliptic_curves",
                args={
                    "elliptic_curves": elliptic_curves
                }
            )
        else:
            self.build_tls_client_hello_hooks.connect(
                hook_elliptic_curves,
                name="elliptic_curves",
                args={
                    "elliptic_curves": elliptic_curves
                }
            )

        detected_elliptic_curves = []
        count = 0
        while True:
            records = self.connect(
                protocol_version,
                stop_condition=stop_condition
            )

            if records is None:
                return detected_elliptic_curves

            server_key_exchange = None
            for record in records:
                if isinstance(record, (Handshake, DTLSv10Handshake)):
                    if isinstance(record.payload, ServerKeyExchange):
                        server_key_exchange = record.payload

            if server_key_exchange is None:
                return detected_elliptic_curves

            # try to extract the ec id
            tmp_ec_id = None
            if isinstance(server_key_exchange.payload, ServerKeyExchangeECDSA):
                tmp_params = server_key_exchange.payload.params
                print(tmp_params)
                if isinstance(tmp_params, ServerECDHParamsField):
                    if isinstance(tmp_params.curve_params, ECParametersNamedCurveField):
                        tmp_ec_id = tmp_params.curve_params.namedcurve

            if tmp_ec_id is None:
                return detected_elliptic_curves

            # stop if we get an unexpected ec id
            if tmp_ec_id not in elliptic_curves:
                return detected_elliptic_curves

            detected_elliptic_curves.append(tmp_ec_id)
            elliptic_curves.remove(tmp_ec_id)

            count += 1
            if limit is not False and limit <= count:
                return detected_elliptic_curves

        return detected_elliptic_curves

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

modules.register(ServerEllipticCurves)
