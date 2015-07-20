import flextls
from flextls.protocol.handshake import Handshake, ServerHello
from flextls.protocol.handshake.extension import Extension, ApplicationLayerProtocolNegotiation
from flextls.field import VectorUInt8Field

from sslscan import modules
from sslscan.exception import Timeout
from sslscan.module.scan import BaseScan


class ServerApplicationLayerProtocolNegotiation(BaseScan):
    """
    Detect if the Application Layer Protocol Negotiation is supported by the server.
    """

    name = "server.alpn"

    def _scan_alpn_tls(self, protocol_version):
        def hook_alpn(record, protocols=None):
            tmp = ApplicationLayerProtocolNegotiation()
            for protocol in protocols:
                v = VectorUInt8Field(None)
                v.value = protocol
                tmp.protocol_name_list.append(v)
            record.payload.extensions.append(Extension() + tmp)

            return record

        def stop_condition(record, records):
            return isinstance(record, Handshake) and \
                isinstance(record.payload, ServerHello)

        available_protocols = flextls.registry.tls.alpn_protocols[:]
        tmp = []
        for protocol in available_protocols:
            tmp.append(protocol.id)
        available_protocols = tmp

        self.build_tls_client_hello_hooks.connect(
            hook_alpn,
            name="alpn",
            args={
                "protocols": available_protocols
            }
        )

        detected_protocols = []
        while True:
            records = self.connect(
                protocol_version=protocol_version,
                stop_condition=stop_condition
            )
            if records is None:
                return detected_protocols

            server_hello = None
            for record in records:
                if isinstance(record, Handshake):
                    if isinstance(record.payload, ServerHello):
                        server_hello = record.payload
                        break

            if server_hello is None:
                return detected_protocols

            detected_protocol = None
            for extension in server_hello.extensions:
                if isinstance(extension.payload, ApplicationLayerProtocolNegotiation):
                    if len(extension.payload.protocol_name_list) > 0:
                        detected_protocol = extension.payload.protocol_name_list[0].value

            if detected_protocol is None:
                return detected_protocols

            detected_protocols.append(detected_protocol)
            available_protocols.remove(detected_protocol)

        return detected_protocols

    def run(self):
        kb = self._scanner.get_knowledge_base()

        if kb.get("server.extension.alpn") is not None:
            return

        protocol_versions = self._scanner.get_enabled_versions()
        protocol_versions.reverse()

        detected_protocols = None
        for protocol_version in protocol_versions:
            if protocol_version == flextls.registry.version.SSLv2:
                continue

            try:
                detected_protocols = self._scan_alpn_tls(protocol_version)
            except Timeout:
                continue

            if detected_protocols is not None:
                break

        if detected_protocols is None or len(detected_protocols) == 0:
            kb.set("server.extension.alpn", False)
        else:
            tmp_proto = []
            for protocol in detected_protocols:
                tmp_proto.append(flextls.registry.tls.alpn_protocols.get(protocol))

            kb.set("server.extension.alpn", tmp_proto)


modules.register(ServerApplicationLayerProtocolNegotiation)
