openssl_enabled = False
try:
    from OpenSSL import crypto

    openssl_enabled = True
except:
    pass

import flextls
from flextls.protocol.handshake import Handshake, ServerCertificate, DTLSv10Handshake

from sslscan import modules
from sslscan.exception import Timeout
from sslscan.module.scan import BaseScan


class ScanServerCertificate(BaseScan):
    """
    Extract certificate information.
    """

    name = "server.certificate"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def _scan_certificate(self):
        def stop_condition(record, records):
            return isinstance(record, (Handshake, DTLSv10Handshake)) and \
                isinstance(record.payload, ServerCertificate)

        kb = self._scanner.get_knowledge_base()
        for protocol_version in self._scanner.get_enabled_versions():
            if protocol_version == flextls.registry.version.SSLv2:
                continue

            self.connect(
                protocol_version,
                stop_condition=stop_condition
            )

            raw_certs = kb.get("server.certificate.raw")
            if raw_certs is not None:
                return raw_certs

    def run(self):
        kb = self._scanner.get_knowledge_base()
        raw_certs = kb.get("server.certificate.raw")
        if raw_certs is None:
            raw_certs = self._scan_certificate()

        if type(raw_certs) != list:
            return

        cert_chain = kb.get("server.certificate_chain")
        if cert_chain is not None:
            return

        cert_chain = []
        for raw_cert in raw_certs:
            try:
                cert = crypto.load_certificate(
                    crypto.FILETYPE_ASN1,
                    raw_cert
                )
                cert_chain.append(cert)
            except:
                continue

        if len(cert_chain) > 0:
            kb.set("server.certificate", cert_chain[0])
        kb.set("server.certificate_chain", cert_chain)


if openssl_enabled is True:
    modules.register(ScanServerCertificate)
