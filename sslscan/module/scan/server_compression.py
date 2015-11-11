import flextls
from flextls.protocol.handshake import Handshake, ServerHello, DTLSv10Handshake

from sslscan import modules
from sslscan.exception import Timeout
from sslscan.module.scan import BaseScan


class ServerCompression(BaseScan):
    """
    Detect if compression is supported by the server.
    """

    name = "server.compression"
    alias = ("compression",)

    def run(self):
        def stop_condition(record, records):
            return isinstance(record, (Handshake, DTLSv10Handshake)) and \
                isinstance(record.payload, ServerHello)

        kb = self._scanner.get_knowledge_base()

        if kb.get("server.session.compression") is not None:
            return

        protocol_versions = self._scanner.get_enabled_versions()
        protocol_versions.reverse()

        for protocol_version in protocol_versions:
            if protocol_version == flextls.registry.version.SSLv2:
                continue
            else:
                try:
                    self.connect(
                        protocol_version,
                        stop_condition=stop_condition
                    )
                except Timeout:
                    continue

            if kb.get("server.session.compression") is not None:
                return


modules.register(ServerCompression)
