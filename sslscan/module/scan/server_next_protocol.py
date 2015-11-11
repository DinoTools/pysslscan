import flextls
from flextls.protocol.handshake import Handshake, ServerHello
from flextls.protocol.handshake.extension import Extension, NextProtocolNegotiation
from flextls.field import VectorUInt8Field

from sslscan import modules
from sslscan.exception import Timeout
from sslscan.module.scan import BaseScan


class ServerNextProtocolNegotiation(BaseScan):
    """
    Detect if the Next Protocol Negotiation is supported by the server.
    """

    name = "server.next_protocol"
    alias = ("next_protocol",)

    def _scan_next_protocol_tls(self, protocol_version):
        def hook_next_protocol(record):
            record.payload.extensions.append(Extension() + NextProtocolNegotiation())

            return record

        def stop_condition(record, records):
            return isinstance(record, Handshake) and \
                isinstance(record.payload, ServerHello)

        self.build_tls_client_hello_hooks.connect(
            hook_next_protocol,
            name="next_protocol2"
        )

        records = self.connect(
            protocol_version=protocol_version,
            stop_condition=stop_condition
        )
        if records is None:
            return None

        server_hello = None
        for record in records:
            if isinstance(record, Handshake):
                if isinstance(record.payload, ServerHello):
                    server_hello = record.payload
                    break

        if server_hello is None:
            return None

        next_protocol_ext = None
        for extension in server_hello.extensions:
            if isinstance(extension.payload, NextProtocolNegotiation):
                next_protocol_ext = extension.payload

        if next_protocol_ext is None:
            return None

        detected_protocols = []
        for protocol in next_protocol_ext.payload:
            detected_protocols.append(protocol.value)

        return detected_protocols

    def run(self):
        kb = self._scanner.get_knowledge_base()

        if kb.get("server.extension.next_protocol_negotiation") is not None:
            return

        protocol_versions = self._scanner.get_enabled_versions()
        protocol_versions.reverse()

        detected_protocols = None
        for protocol_version in protocol_versions:
            if protocol_version == flextls.registry.version.SSLv2:
                continue

            try:
                detected_protocols = self._scan_next_protocol_tls(protocol_version)
            except Timeout:
                continue

            if detected_protocols is not None:
                break

        if detected_protocols is None or len(detected_protocols) == 0:
            kb.set("server.extension.next_protocol_negotiation", False)
        else:
            tmp_proto = []
            for protocol in detected_protocols:
                tmp_proto.append(flextls.registry.tls.alpn_protocols.get(protocol))

            kb.set("server.extension.next_protocol_negotiation", tmp_proto)


modules.register(ServerNextProtocolNegotiation)
