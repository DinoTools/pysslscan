import flextls

from sslscan import modules
from sslscan.exception import Timeout
from sslscan.kb import CipherResult
from sslscan.module.scan import BaseScan
from sslscan.module.scan.server_ciphers import ServerCiphers


class ServerPreferredCiphers(ServerCiphers):
    """
    Detect preferred server ciphers.
    """

    name = "server.preferred_ciphers"
    alias = ("preferred_ciphers",)

    def _add_cipher_to_kb(self, protocol_version, cipher_suite, status):
        kb = self._scanner.get_knowledge_base()
        kb.append(
            "server.preferred_ciphers",
            CipherResult(
                protocol_version=protocol_version,
                cipher_suite=cipher_suite,
                status=status
            )
        )

    def _scan_preferred_ciphers(self, protocol_version, cipher_suites, limit=None):
            try:
                detected_ciphers = self._scan_cipher_suites(protocol_version, cipher_suites, limit=limit)
            except Timeout:
                return None

            if len(detected_ciphers) == 0:
                self._add_cipher_to_kb(
                    protocol_version=protocol_version,
                    cipher_suite=None,
                    status=0
                )
                return None
            return detected_ciphers

    def run(self):
        for protocol_version in self._scanner.get_enabled_versions():
            if protocol_version == flextls.registry.version.SSLv2:
                continue

            cipher_suites = flextls.registry.tls.cipher_suites[:]
            detected_ciphers1 = self._scan_preferred_ciphers(protocol_version, cipher_suites, limit=2)
            if detected_ciphers1 is None:
                continue

            # Continue with next version if only one cipher suite detected
            if len(detected_ciphers1) == 1:
                self._add_cipher_to_kb(
                    protocol_version=protocol_version,
                    cipher_suite=flextls.registry.tls.cipher_suites.get(detected_ciphers1[0]),
                    status=1
                )
                continue

            # Check ciphers from first test in reverse order to identify preference
            reversed_ciphers = []
            for cipher_id in reversed(detected_ciphers1):
                reversed_ciphers.append(flextls.registry.tls.cipher_suites.get(cipher_id))

            detected_ciphers2 = self._scan_preferred_ciphers(protocol_version, reversed_ciphers, limit=1)
            if detected_ciphers2 is None:
                continue

            if detected_ciphers1[0] == detected_ciphers2[0]:
                cipher_suite = flextls.registry.tls.cipher_suites.get(detected_ciphers1[0])
            else:
                cipher_suite = False

            self._add_cipher_to_kb(
                protocol_version=protocol_version,
                cipher_suite=cipher_suite,
                status=1
            )


modules.register(ServerPreferredCiphers)
