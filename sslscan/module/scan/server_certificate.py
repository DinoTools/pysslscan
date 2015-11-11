import flextls
from flextls.protocol.handshake import Handshake, ServerCertificate, DTLSv10Handshake

from sslscan import modules
from sslscan._helper.openssl import version_openssl, version_pyopenssl
from sslscan.module import STATUS_OK, STATUS_ERROR
from sslscan.module.scan import BaseScan

openssl_enabled = False
version_info = []
try:
    from OpenSSL import crypto

    openssl_enabled = True
    if version_pyopenssl:
        version_info.append("pyOpenSSL version {}".format(version_pyopenssl))
    if version_openssl:
        version_info.append("OpenSSL version {}".format(version_openssl))
except ImportError:
    pass


class ScanServerCertificate(BaseScan):
    """
    Extract certificate information.
    """

    name = "server.certificate"
    alias = ("certificate",)
    status = STATUS_OK if openssl_enabled else STATUS_ERROR
    status_messages = ["OpenSSL is {}".format("available" if openssl_enabled else "missing")] + version_info

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


modules.register(ScanServerCertificate)
