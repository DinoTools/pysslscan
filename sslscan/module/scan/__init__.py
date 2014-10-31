from datetime import datetime

import flextls
from flextls.exception import NotEnoughData
from flextls.field import CipherSuiteField, CompressionMethodField
from flextls.field import SSLv2CipherSuiteField
from flextls.field import ServerNameField, HostNameField
from flextls.protocol.handshake import ClientHello, Handshake, ServerHello, ServerCertificate
from flextls.protocol.handshake import SSLv2ClientHello, SSLv2ServerHello
from flextls.protocol.handshake.extension import EllipticCurves, SignatureAlgorithms, Extension, SessionTicketTLS
from flextls.protocol.handshake.extension import ServerNameIndication
from flextls.protocol.record import RecordSSLv2, RecordSSLv3
from flextls.protocol.alert import Alert

from sslscan.exception import Timeout
from sslscan.module import BaseModule

class BaseScan(BaseModule):
    def __init__(self, **kwargs):
        BaseModule.__init__(self, **kwargs)

    def _build_tls_base_client_hello(self, protocol_version, cipher_suites):

        ver_major = 3
        if protocol_version == flextls.registry.version.SSLv3:
            ver_minor = 0
        elif protocol_version == flextls.registry.version.TLSv10:
            ver_minor = 1
        elif protocol_version == flextls.registry.version.TLSv11:
            ver_minor = 2
        elif protocol_version == flextls.registry.version.TLSv12:
            ver_minor = 3

        hash_algorithms = flextls.registry.tls.hash_algorithms.get_ids()
        sign_algorithms = flextls.registry.tls.signature_algorithms.get_ids()
        comp_methods = flextls.registry.tls.compression_methods.get_ids()

        hello = ClientHello()

        for i in cipher_suites:
            cipher = CipherSuiteField()
            cipher.value = i
            hello.cipher_suites.append(cipher)

        for comp_id in comp_methods:
            comp = CompressionMethodField()
            comp.value = comp_id
            hello.compression_methods.append(comp)

        server_name = ServerNameField()
        server_name.payload = HostNameField("")
        server_name.payload.value = self._scanner.handler.hostname.encode("utf-8")
        tmp_sni = ServerNameIndication()
        tmp_sni.server_name_list.append(server_name)
        tmp_ext_sni = Extension() + tmp_sni
        hello.extensions.append(tmp_ext_sni)

        ext_elliptic_curves = EllipticCurves()
        a = ext_elliptic_curves.get_field("elliptic_curve_list")
        for i in flextls.registry.ec.named_curves.get_ids():
            v = a.item_class("unnamed", None)
            v.value = i
            a.value.append(v)

        hello.extensions.append(Extension() + ext_elliptic_curves)

        ext_signature_algorithm = SignatureAlgorithms()
        a = ext_signature_algorithm.get_field("supported_signature_algorithms")
        for i in hash_algorithms:
            for j in sign_algorithms:
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
        return msg_hello


    def _scan_cipher_suites_tls(self, protocol_version, cipher_suites, limit=False):
        kb = self._scanner.get_knowledge_base()

        cipher_suites = cipher_suites[:]

        detected_ciphers = []
        count = 0

        while True:
            conn = self._scanner.handler.connect()
            conn.settimeout(2.0)

            record_tls = self._build_tls_base_client_hello(
                protocol_version,
                cipher_suites
            )

            conn.send(record_tls.encode())

            time_start = datetime.now()
            server_hello = None
            data = b""
            raw_certs = kb.get("server.certificate.raw")
            while server_hello is None or raw_certs is None:
                tmp_time = datetime.now() - time_start
                if tmp_time.total_seconds() > 5.0:
                    return detected_ciphers

                tmp_data = conn.recv(4096)

                data += tmp_data
                while True:
                    try:
                        (record, data) = RecordSSLv3.decode(data)
                    except NotEnoughData:
                        break

                    if isinstance(record.payload, Handshake):
                        if isinstance(record.payload.payload, ServerHello):
                            server_hello = record.payload.payload

                        if raw_certs is None and isinstance(record.payload.payload, ServerCertificate):
                            raw_certs = []
                            for raw_cert in record.payload.payload.certificate_list:
                                raw_certs.append(raw_cert.value)
                            kb.set("server.certificate.raw", raw_certs)
                    elif isinstance(record.payload, Alert):
                        if record.payload.level == 2:
                            return detected_ciphers

            conn.close()
            if server_hello is None:
                break

            # get compression method
            if kb.get("server.session.compression") is None:
                comp_method = flextls.registry.tls.compression_methods.get(
                    server_hello.compression_method
                )
                kb.set("server.session.compression", comp_method)

            detected_ciphers.append(server_hello.cipher_suite)
            cipher_suites.remove(server_hello.cipher_suite)
            count = count + 1
            if limit != False and limit <= count:
                break

        return detected_ciphers
