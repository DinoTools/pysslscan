import flextls

from sslscan import modules
from sslscan.exception import Timeout
from sslscan.kb import CipherResult
from sslscan.module.scan import BaseScan


class ServerPreferredCiphers(BaseScan):
    """
    Detect preferred server ciphers.
    """

    name="server.preferred_ciphers"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)


    def run(self):
        kb = self._scanner.get_knowledge_base()

        for protocol_version in self._scanner.get_enabled_versions():
            if protocol_version == flextls.registry.version.SSLv2:
                continue
            else:
                cipher_suites = flextls.registry.tls.cipher_suites[:]
                try:
                    tmp1 = self._scan_cipher_suites(protocol_version, cipher_suites, limit=2)
                except Timeout:
                    continue

                if len(tmp1) == 0:
                    kb.append(
                        "server.preferred_ciphers",
                        CipherResult(
                            protocol_version=protocol_version,
                            cipher_suite=None,
                            status=0,
                        )
                    )
                    continue

                cipher_suites.reverse()
                try:
                    tmp2 = self._scan_cipher_suites(protocol_version, cipher_suites, limit=1)
                except Timeout:
                    continue

                if tmp1[0] == tmp2[0]:
                    cipher_suite = flextls.registry.tls.cipher_suites.get(
                        tmp1[0]
                    )
                else:
                    cipher_suite = False

                kb.append(
                    "server.preferred_ciphers",
                    CipherResult(
                        protocol_version=protocol_version,
                        cipher_suite=cipher_suite,
                        status=1,
                    )
                )


modules.register(ServerPreferredCiphers)
