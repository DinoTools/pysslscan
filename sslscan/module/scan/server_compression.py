import flextls

from sslscan import modules
from sslscan.exception import Timeout
from sslscan.module.scan import BaseScan


class ServerCompression(BaseScan):
    """
    Detect if compression is supported by the server.
    """

    name = "server.compression"

    def run(self):
        kb = self._scanner.get_knowledge_base()

        if kb.get("server.session.compression") is not None:
            return

        protocol_versions = self._scanner.get_enabled_versions()
        protocol_versions.reverse()

        for protocol_version in protocol_versions:
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

            if kb.get("server.session.compression") is not None:
                return


modules.register(ServerCompression)
