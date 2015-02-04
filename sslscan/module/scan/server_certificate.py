openssl_enabled = False
try:
    from OpenSSL import crypto
    openssl_enabled = True
except:
    pass


import flextls

from sslscan import modules
from sslscan.exception import Timeout
from sslscan.module.scan import BaseScan


class ServerCertificate(BaseScan):
    """
    Extract certificate information.
    """

    name = "server.certificate"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def run(self):
        kb = self._scanner.get_knowledge_base()

        raw_certs = kb.get("server.certificate.raw")
        if raw_certs is None:
            for protocol_version in self._scanner.get_enabled_versions():
                if protocol_version == flextls.registry.version.SSLv2:
                    continue
                else:
                    cipher_suites = flextls.registry.tls.cipher_suites[:]
                    try:
                        self._scan_cipher_suites(
                            protocol_version,
                            cipher_suites,
                            limit=1
                        )
                    except Timeout:
                        continue

                raw_certs = kb.get("server.certificate.raw")
                if raw_certs is not None:
                    break

        if type(raw_certs) != list:
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
    modules.register(ServerCertificate)
