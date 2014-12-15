from datetime import datetime
import os

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
import six

openssl_enabled = False
try:
    from OpenSSL import SSL, _util
    openssl_enabled = True
except:
    pass


from sslscan.module import BaseModule

if six.PY2:
    import socket
    ConnectionError = socket.error


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
        msg_hello.payload.payload.random.random_bytes = os.urandom(32)
        msg_hello.version.minor = ver_minor
        msg_hello.payload.payload.version.minor = ver_minor
        return msg_hello

    def _scan_ssl2_cipher_suites(self, protocol_version, cipher_suites):
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

        time_start = datetime.now()
        detected_ciphers = []
        data = b""
        while True:
            tmp_time = datetime.now() - time_start
            if tmp_time.total_seconds() > 5.0:
                return detected_ciphers

            try:
                tmp_data = conn.recv(4096)
            except ConnectionError:
                return detected_ciphers

            data += tmp_data

            try:
                (record, data) = RecordSSLv2.decode(data)
            except NotEnoughData:
                continue

            if isinstance(record.payload, SSLv2ServerHello):
                for i in record.payload.cipher_suites:
                    detected_ciphers.append(i.value)

                break

        conn.close()
        return detected_ciphers

    def _scan_tls_cipher_suites(self, protocol_version, cipher_suites, limit=False):
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

                try:
                    tmp_data = conn.recv(4096)
                except ConnectionError:
                    return detected_ciphers

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
            if limit is not False and limit <= count:
                break

        return detected_ciphers


class BaseInfoScan(BaseScan):
    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def _get_server_info(self):
        server_info = self._scanner.handler.get_server_info()

        if server_info is not None:
            return server_info

        conn_ssl = self._connect_auto()
        if conn_ssl is None:
            return None

        server_info = self._scanner.handler.get_server_info(conn_ssl)
        conn_ssl.close()
        if server_info is not None:
            return server_info

        return None

    def _connect_auto(self):
        conn_ssl = self._connect_openssl()
        if conn_ssl is not None:
            return conn_ssl

        conn_ssl = self._connect_internal_ssl()
        if conn_ssl is not None:
            return conn_ssl

        return None

    def _connect_internal_ssl(self, protocol_versions=None):
        import ssl
        from sslscan._helper.int_ssl import convert_versions2methods

        if protocol_versions is None:
            protocol_versions = self._scanner.get_enabled_versions()

        methods = convert_versions2methods(protocol_versions)
        methods.reverse()

        for method in methods:
            try:
                ctx = ssl.SSLContext(method)
            except:
                # ToDo:
                continue

            ctx.set_ciphers("ALL:COMPLEMENT")
            ctx.verify_mode = ssl.VERIFY_DEFAULT
            conn = self._scanner.handler.connect()
            conn_ssl = ctx.wrap_socket(
                conn,
                server_hostname=self._scanner.handler.hostname.encode("utf-8")
            )
            return conn_ssl

        return None

    def _connect_openssl(self, protocol_versions=None):
        if openssl_enabled == False:
            return None
        from sslscan._helper.openssl import convert_versions2methods

        if protocol_versions is None:
            protocol_versions = self._scanner.get_enabled_versions()

        methods = convert_versions2methods(protocol_versions)
        methods.reverse()

        for method in methods:
            try:
                ctx = SSL.Context(method)
            except:
                # ToDo:
                continue

            ctx.set_cipher_list("ALL:COMPLEMENT")
            conn = self._scanner.handler.connect()
            conn_ssl = SSL.Connection(ctx, conn)
            conn_ssl.set_tlsext_host_name(
                self._scanner.handler.hostname.encode("utf-8")
            )
            conn_ssl.set_connect_state()
            try:
                conn_ssl.do_handshake()
            except Exception as e:
                print(e)
                conn_ssl.close()
                continue
            return conn_ssl

        return None
