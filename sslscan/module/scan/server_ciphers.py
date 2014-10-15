from flextls.field import CipherSuiteField, CompressionMethodField
from flextls.protocol.handshake import ClientHello, Handshake, ServerHello
from flextls.protocol.handshake.extension import EllipticCurves, SignatureAlgorithms, Extension, SessionTicketTLS
from flextls.protocol.record import RecordSSLv3

from sslscan import modules
from sslscan.kb import Cipher
from sslscan.module.scan import BaseScan


class ServerCiphers(BaseScan):
    """
    Test a server for provided ciphers.
    """

    name = "server.ciphers"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def run(self):
        kb = self._scanner.get_knowledge_base()

        versions = []
        if self._scanner.config.get_value('ssl2'):
            versions.append((2, 0))
        if self._scanner.config.get_value('ssl3'):
            versions.append((3, 0))
        if self._scanner.config.get_value('tls10'):
            versions.append((3, 1))
        if self._scanner.config.get_value('tls11'):
            versions.append((3, 2))
        if self._scanner.config.get_value('tls12'):
            versions.append((3, 3))

        for ver_major, ver_minor in versions:
            cipher_suites = [i for i in range(0, 0x1000)]
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
                    kb.append(
                        'server.ciphers',
                        Cipher(
                            bits=0,
                            method="TLS %d.%d" % (ver_major, ver_minor),
                            name=server_hello.cipher_suite,
                            status=1
                        )
                    )
                    cipher_suites.remove(server_hello.cipher_suite)
                else:
                    break


modules.register(ServerCiphers)
