import flextls
from flextls.field import CipherSuiteField, CompressionMethodField
from flextls.field import SSLv2CipherSuiteField
from flextls.protocol.handshake import ClientHello, Handshake, ServerHello
from flextls.protocol.handshake import SSLv2ClientHello, SSLv2ServerHello
from flextls.protocol.handshake.extension import EllipticCurves, SignatureAlgorithms, Extension, SessionTicketTLS
from flextls.protocol.record import RecordSSLv2, RecordSSLv3

from sslscan import modules
from sslscan.kb import CipherResult
from sslscan.module.scan import BaseScan


class ServerCiphers(BaseScan):
    """
    Test a server for provided ciphers.
    """

    name = "server.ciphers"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def _scan_ssl2(self, protocol_version):
        kb = self._scanner.get_knowledge_base()
        cipher_suites = flextls.registry.sslv2.cipher_suites.get_ids()

        conn = self._scanner.handler.connect()

        hello = SSLv2ClientHello()
        hello.version.major = 0
        hello.version.minor = 2
        hello.challenge = b"A"*16

        for i in cipher_suites:
            cipher = SSLv2CipherSuiteField()
            cipher.value = i
            hello.cipher_suites.append(cipher)

        msg_hello = RecordSSLv2() + hello

        conn.send(msg_hello.encode())
        data = conn.recv(4096)
        (record, data) = RecordSSLv2.decode(data)
        if isinstance(record.payload, SSLv2ServerHello):
            for i in record.payload.cipher_suites:
                cipher_suite = flextls.registry.sslv2.cipher_suites.get(i.value)
                kb.append(
                    'server.ciphers',
                    CipherResult(
                        protocol_version=protocol_version,
                        cipher_suite=cipher_suite,
                        status=1,
                    )
                )

    def _scan_ssl3(self, protocol_version):
        kb = self._scanner.get_knowledge_base()

        ver_major = 3
        if protocol_version == flextls.registry.version.SSLv3:
            ver_minor = 0
        elif protocol_version == flextls.registry.version.TLSv10:
            ver_minor = 1
        elif protocol_version == flextls.registry.version.TLSv11:
            ver_minor = 2
        elif protocol_version == flextls.registry.version.TLSv12:
            ver_minor = 3

        cipher_suites = flextls.registry.tls.cipher_suites.get_ids()
        #cipher_suites = [i for i in range(0, 0x1000)]
        while True:
            conn = self._scanner.handler.connect()

            hello = ClientHello()

            for i in cipher_suites:
                cipher = CipherSuiteField()
                cipher.value = i
                hello.cipher_suites.append(cipher)

            comp = CompressionMethodField()
            comp.value = 0

            hello.compression_methods.append(comp)
            ext_elliptic_curves = EllipticCurves()
            a = ext_elliptic_curves.get_field("elliptic_curve_list")
            for i in range(1, 25):
                v = a.item_class("unnamed", None)
                v.value = i
                a.value.append(v)

            hello.extensions.append(Extension() + ext_elliptic_curves)

            ext_signature_algorithm = SignatureAlgorithms()
            a = ext_signature_algorithm.get_field("supported_signature_algorithms")
            for i in range(0, 7):
                for j in range(0, 4):
                    v = a.item_class("unnamed")
                    v.hash = i
                    v.signature = j
                    a.value.append(v)

            hello.extensions.append(Extension() + ext_signature_algorithm)

            hello.extensions.append(Extension() + SessionTicketTLS())

            msg_hello = RecordSSLv3() + (Handshake() + hello)
            msg_hello.payload.payload.random.random_bytes = b"A"*32
            msg_hello.version.minor = ver_minor
            msg_hello.payload.payload.version.minor = ver_minor
            conn.send(msg_hello.encode())
            data = conn.recv(4096)
            (record, data) = RecordSSLv3.decode(data)
            if isinstance(record.payload.payload, ServerHello):
                server_hello = record.payload.payload
                cipher_suite = flextls.registry.tls.cipher_suites.get(
                    server_hello.cipher_suite
                )
                kb.append(
                    'server.ciphers',
                    CipherResult(
                        protocol_version=protocol_version,
                        cipher_suite=cipher_suite,
                        status=1,
                    )
                )
                cipher_suites.remove(server_hello.cipher_suite)
            else:
                break

    def run(self):
        for protocol_version in self._scanner.get_enabled_versions():
            if protocol_version == flextls.registry.version.SSLv2:
                self._scan_ssl2(protocol_version)
            else:
                self._scan_ssl3(protocol_version)


modules.register(ServerCiphers)
