from datetime import datetime
import os

import flextls
from flextls.connection import DTLSv10Connection, SSLv30Connection
from flextls.exception import NotEnoughData, WrongProtocolVersion
from flextls.field import CipherSuiteField, CompressionMethodField
from flextls.field import SSLv2CipherSuiteField
from flextls.field import ServerNameField, HostNameField
from flextls.field import ServerECDHParamsField, ECParametersNamedCurveField
from flextls.protocol.handshake import ClientHello, Handshake, ServerHello, ServerCertificate, ServerKeyExchange
from flextls.protocol.handshake import ServerKeyExchangeECDSA
from flextls.protocol.handshake import DTLSv10ClientHello, DTLSv10Handshake, DTLSv10HelloVerifyRequest
from flextls.protocol.handshake import SSLv2ClientHello, SSLv2ServerHello
from flextls.protocol.handshake.extension import EllipticCurves, SignatureAlgorithms, Extension, SessionTicketTLS
from flextls.protocol.handshake.extension import ServerNameIndication, Heartbeat as HeartbeatExt, EcPointFormats
from flextls.protocol.record import SSLv2Record
from flextls.protocol.alert import Alert
import six

openssl_enabled = False
try:
    from OpenSSL import SSL, _util
    openssl_enabled = True
except:
    pass


from sslscan.module import BaseModule

import socket
if six.PY2:
    ConnectionError = socket.error


class BaseScan(BaseModule):
    def __init__(self, **kwargs):
        BaseModule.__init__(self, **kwargs)

    def _build_dtls_base_client_hello(self, protocol_version, cipher_suites, elliptic_curves=None):
        ver_major, ver_minor = flextls.helper.get_tls_version(protocol_version)

        hash_algorithms = flextls.registry.tls.hash_algorithms.get_ids()
        sign_algorithms = flextls.registry.tls.signature_algorithms.get_ids()
        comp_methods = flextls.registry.tls.compression_methods.get_ids()

        hello = DTLSv10ClientHello()

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
        if elliptic_curves is None:
            elliptic_curves = flextls.registry.ec.named_curves.get_ids()
        for i in elliptic_curves:
            v = a.item_class("unnamed", None)
            v.value = i
            a.value.append(v)

        hello.extensions.append(Extension() + ext_elliptic_curves)

        ext_ec_point_formats = EcPointFormats()
        a = ext_ec_point_formats.get_field("point_format_list")
        for tmp_pf in flextls.registry.ec.point_formats:
            v = a.item_class("unnamed", tmp_pf.id)
            a.value.append(v)

        hello.extensions.append(Extension() + ext_ec_point_formats)

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
        hb_ext = HeartbeatExt()
        hb_ext.mode = 1
        hello.extensions.append(Extension() + hb_ext)

        hello.random = os.urandom(32)
        hello.version.major = ver_major
        hello.version.minor = ver_minor
        msg_handshake = DTLSv10Handshake()
        msg_handshake.set_payload(hello)

        return msg_handshake

    def _build_tls_base_client_hello(self, protocol_version, cipher_suites, elliptic_curves=None):

        ver_major, ver_minor = flextls.helper.get_tls_version(protocol_version)

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
        if elliptic_curves is None:
            elliptic_curves = flextls.registry.ec.named_curves.get_ids()
        for i in elliptic_curves:
            v = a.item_class("unnamed", None)
            v.value = i
            a.value.append(v)

        hello.extensions.append(Extension() + ext_elliptic_curves)

        ext_ec_point_formats = EcPointFormats()
        a = ext_ec_point_formats.get_field("point_format_list")
        for tmp_pf in flextls.registry.ec.point_formats:
            v = a.item_class("unnamed", tmp_pf.id)
            a.value.append(v)

        hello.extensions.append(Extension() + ext_ec_point_formats)

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

        hello.random = os.urandom(32)
        hello.version.major = ver_major
        hello.version.minor = ver_minor
        msg_handshake = Handshake()
        msg_handshake.set_payload(hello)
        return msg_handshake

    def _scan_cipher_suites(self, protocol_version, cipher_suites, limit=False):
        if protocol_version & flextls.registry.version.DTLS != 0:
            return self._scan_dtls_cipher_suites(protocol_version, cipher_suites, limit=limit)

        return self._scan_tls_cipher_suites(protocol_version, cipher_suites, limit=limit)

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

        msg_hello = SSLv2Record() + hello

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
                (record, data) = SSLv2Record.decode(data)
            except NotEnoughData:
                continue

            if isinstance(record.payload, SSLv2ServerHello):
                for i in record.payload.cipher_suites:
                    detected_ciphers.append(i.value)

                break

        conn.close()
        return detected_ciphers

    def _scan_dtls_cipher_suites(self, protocol_version, cipher_suites, limit=False):
        kb = self._scanner.get_knowledge_base()

        # Get IDs of allowed cipher suites
        tmp = []
        for cipher_suite in cipher_suites:
            if cipher_suite.dtls is True:
                tmp.append(cipher_suite.id)
        cipher_suites = tmp

        detected_ciphers = []
        count = 0

        while True:
            conn = self._scanner.handler.connect()
            conn.settimeout(2.0)
            conn_dtls = DTLSv10Connection(protocol_version=protocol_version)

            record_handshake = self._build_dtls_base_client_hello(
                protocol_version,
                cipher_suites
            )

            conn.send_list(conn_dtls.encode(record_handshake))
            time_start = datetime.now()
            verify_request = None

            while verify_request is None:
                tmp_time = datetime.now() - time_start
                if tmp_time.total_seconds() > 5.0:
                    return detected_ciphers

                try:
                    data = conn.recv(4096)
                except ConnectionError:
                    return detected_ciphers

                try:
                    conn_dtls.decode(data)
                except WrongProtocolVersion:
                    # Send alert to stop communication
                    record_alert = Alert()
                    record_alert.level = "fatal"
                    record_alert.description = "protocol_version"
                    conn.send_list(conn_dtls.encode(record_alert))
                    conn.close()
                    return detected_ciphers

                if not conn_dtls.is_empty():
                    record = conn_dtls.pop_record()
                    if isinstance(record, DTLSv10Handshake):
                        if isinstance(record.payload, DTLSv10HelloVerifyRequest):
                            verify_request = record.payload
                            break
                    elif isinstance(record, Alert):
                        if record.level == 2:
                            conn.close()
                            return detected_ciphers

            if verify_request is None:
                return

            record_handshake.payload.cookie = verify_request.cookie
            conn.send_list(conn_dtls.encode(record_handshake))

            time_start = datetime.now()
            server_hello = None
            raw_certs = kb.get("server.certificate.raw")
            while server_hello is None or raw_certs is None:
                tmp_time = datetime.now() - time_start
                if tmp_time.total_seconds() > 5.0:
                    return detected_ciphers

                try:
                    data = conn.recv(4096)
                except ConnectionError:
                    return detected_ciphers

                try:
                    conn_dtls.decode(data)
                except WrongProtocolVersion:
                    # Send alert to stop communication
                    record_alert = Alert()
                    record_alert.level = "fatal"
                    record_alert.description = "protocol_version"
                    conn.send_list(conn_dtls.encode(record_alert))
                    conn.close()
                    return detected_ciphers

                while not conn_dtls.is_empty():
                    record = conn_dtls.pop_record()

                    if isinstance(record, DTLSv10Handshake):
                        if isinstance(record.payload, ServerHello):
                            server_hello = record.payload
                        if raw_certs is None and isinstance(record.payload, ServerCertificate):
                            raw_certs = []
                            for raw_cert in record.payload.certificate_list:
                                raw_certs.append(raw_cert.value)
                            kb.set("server.certificate.raw", raw_certs)

                    elif isinstance(record, Alert):
                        if record.level == 2:
                            return detected_ciphers

            record_alert = Alert()
            record_alert.level = 1
            record_alert.description = 0
            conn.send_list(conn_dtls.encode(record_alert))
            conn.close()
            if server_hello is None:
                break

            # get compression method
            if kb.get("server.session.compression") is None:
                comp_method = flextls.registry.tls.compression_methods.get(
                    server_hello.compression_method
                )
                kb.set("server.session.compression", comp_method)

            for extension in server_hello.extensions:
                if isinstance(extension.payload, EcPointFormats):
                    tmp_formats = []
                    for format_id in extension.payload.point_format_list:
                        tmp_format = flextls.registry.ec.point_formats.get(format_id.value)
                        tmp_formats.append(tmp_format)

                    if kb.get("server.ec.point_formats") is None:
                        kb.set("server.ec.point_formats", tmp_formats)

            detected_ciphers.append(server_hello.cipher_suite)
            cipher_suites.remove(server_hello.cipher_suite)
            count = count + 1
            if limit is not False and limit <= count:
                break

        return detected_ciphers

    def _scan_tls_cipher_suites(self, protocol_version, cipher_suites, limit=False):
        kb = self._scanner.get_knowledge_base()

        # Get IDs of allowed cipher suites
        tmp = []
        for cipher_suite in cipher_suites:
            tmp.append(cipher_suite.id)
        cipher_suites = tmp

        detected_ciphers = []
        count = 0

        while True:
            conn = self._scanner.handler.connect()
            conn.settimeout(2.0)

            conn_tls = SSLv30Connection(
                protocol_version=protocol_version
            )

            record_handshake = self._build_tls_base_client_hello(
                protocol_version,
                cipher_suites
            )

            conn.send_list(conn_tls.encode(record_handshake))

            time_start = datetime.now()
            server_hello = None

            raw_certs = kb.get("server.certificate.raw")
            while server_hello is None or raw_certs is None:
                tmp_time = datetime.now() - time_start
                if tmp_time.total_seconds() > 5.0:
                    return detected_ciphers

                try:
                    data = conn.recv(4096)
                except ConnectionError:
                    return detected_ciphers
                except socket.timeout:
                    conn.close()
                    return detected_ciphers

                try:
                    conn_tls.decode(data)
                except WrongProtocolVersion:
                    # Send alert and close socket
                    record_alert = Alert()
                    record_alert.level = "fatal"
                    record_alert.description = "protocol_version"
                    conn.send_list(conn_tls.encode(record_alert))
                    conn.close()
                    return detected_ciphers

                while not conn_tls.is_empty():
                    record = conn_tls.pop_record()

                    if isinstance(record, Handshake):
                        if isinstance(record.payload, ServerHello):
                            server_hello = record.payload
                        elif raw_certs is None and isinstance(record.payload, ServerCertificate):
                            raw_certs = []
                            for raw_cert in record.payload.certificate_list:
                                raw_certs.append(raw_cert.value)
                            kb.set("server.certificate.raw", raw_certs)
                    elif isinstance(record, Alert):
                        if record.level == 2:
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

            for extension in server_hello.extensions:
                if isinstance(extension.payload, EcPointFormats):
                    tmp_formats = []
                    for format_id in extension.payload.point_format_list:
                        tmp_format = flextls.registry.ec.point_formats.get(format_id.value)
                        tmp_formats.append(tmp_format)

                    if kb.get("server.ec.point_formats") is None:
                        kb.set("server.ec.point_formats", tmp_formats)

            detected_ciphers.append(server_hello.cipher_suite)
            cipher_suites.remove(server_hello.cipher_suite)
            count = count + 1
            if limit is not False and limit <= count:
                break

        return detected_ciphers

    def _scan_elliptic_curves(self, protocol_version, cipher_suites, elliptic_curves, limit=False):
        if protocol_version & flextls.registry.version.DTLS != 0:
            return self._scan_elliptic_curves_dtls(protocol_version, cipher_suites, elliptic_curves, limit=limit)

        return self._scan_elliptic_curves_tls(protocol_version, cipher_suites, elliptic_curves, limit=limit)

    def _scan_elliptic_curves_dtls(self, protocol_version, cipher_suites, elliptic_curves, limit=False):
        """
        Scan for supported elliptic curves

        :param protocol_version:
        :param cipher_suites: List of cipher suites.
        :param elliptic_curves: List of elliptic curves
        :param limit:
        :return: List of supported elliptic curve IDs
        """
        # Get IDs of allowed cipher suites
        tmp = []
        for cipher_suite in cipher_suites:
            if cipher_suite.dtls is True:
                tmp.append(cipher_suite.id)
        cipher_suites = tmp

        tmp = []
        for elliptic_curve in elliptic_curves:
            tmp.append(elliptic_curve.id)
        elliptic_curves = tmp

        detected_elliptic_curves = []
        count = 0

        while True:
            conn = self._scanner.handler.connect()
            conn.settimeout(2.0)
            conn_dtls = DTLSv10Connection(
                protocol_version=protocol_version
            )

            record_handshake = self._build_dtls_base_client_hello(
                protocol_version,
                cipher_suites,
                elliptic_curves=elliptic_curves
            )

            conn.send_list(conn_dtls.encode(record_handshake))
            time_start = datetime.now()
            verify_request = None

            while verify_request is None:
                tmp_time = datetime.now() - time_start
                if tmp_time.total_seconds() > 5.0:
                    return detected_elliptic_curves

                try:
                    data = conn.recv(4096)
                except ConnectionError:
                    return detected_elliptic_curves

                try:
                    conn_dtls.decode(data)
                except WrongProtocolVersion:
                    # Send alert to stop communication
                    record_alert = Alert()
                    record_alert.level = "fatal"
                    record_alert.description = "protocol_version"
                    conn.send_list(conn_dtls.encode(record_alert))
                    conn.close()
                    return detected_elliptic_curves

                if not conn_dtls.is_empty():
                    record = conn_dtls.pop_record()
                    if isinstance(record, DTLSv10Handshake):
                        if isinstance(record.payload, DTLSv10HelloVerifyRequest):
                            verify_request = record.payload
                            break
                    elif isinstance(record, Alert):
                        if record.level == 2:
                            conn.close()
                            return detected_elliptic_curves

            if verify_request is None:
                return detected_elliptic_curves

            record_handshake.payload.cookie = verify_request.cookie
            conn.send_list(conn_dtls.encode(record_handshake))

            time_start = datetime.now()
            server_key_exchange = None
            while server_key_exchange is None:
                tmp_time = datetime.now() - time_start
                if tmp_time.total_seconds() > 5.0:
                    return detected_elliptic_curves

                try:
                    data = conn.recv(4096)
                except ConnectionError:
                    return detected_elliptic_curves

                try:
                    conn_dtls.decode(data)
                except WrongProtocolVersion:
                    # Send alert to stop communication
                    record_alert = Alert()
                    record_alert.level = "fatal"
                    record_alert.description = "protocol_version"
                    conn.send_list(conn_dtls.encode(record_alert))
                    conn.close()
                    return detected_elliptic_curves

                while not conn_dtls.is_empty():
                    record = conn_dtls.pop_record()

                    if isinstance(record, DTLSv10Handshake):
                        if isinstance(record.payload, ServerKeyExchange):
                            server_key_exchange = record.payload

                    elif isinstance(record, Alert):
                        if record.level == 2:
                            return detected_elliptic_curves

            record_alert = Alert()
            record_alert.level = 1
            record_alert.description = 0
            conn.send_list(conn_dtls.encode(record_alert))
            conn.close()
            if server_key_exchange is None:
                break

            # try to extract the ec id
            tmp_ec_id = None
            if isinstance(server_key_exchange.payload, ServerKeyExchangeECDSA):
                tmp_params = server_key_exchange.payload.params
                if isinstance(tmp_params, ServerECDHParamsField):
                    if isinstance(tmp_params.curve_params, ECParametersNamedCurveField):
                        tmp_ec_id = tmp_params.curve_params.namedcurve

            if tmp_ec_id is None:
                return detected_elliptic_curves

            # stop if we get an unexpected ec id
            if tmp_ec_id not in elliptic_curves:
                return detected_elliptic_curves
            detected_elliptic_curves.append(tmp_ec_id)
            elliptic_curves.remove(tmp_ec_id)

            count += 1
            if limit is not False and limit <= count:
                break

        return detected_elliptic_curves

    def _scan_elliptic_curves_tls(self, protocol_version, cipher_suites, elliptic_curves, limit=False):
        """
        Scan for supported elliptic curves

        :param protocol_version:
        :param cipher_suites: List of cipher suites.
        :param elliptic_curves: List of elliptic curves
        :param limit:
        :return: List of supported elliptic curve IDs
        """
        # Get IDs of allowed cipher suites
        tmp = []
        for cipher_suite in cipher_suites:
            tmp.append(cipher_suite.id)
        cipher_suites = tmp

        tmp = []
        for elliptic_curve in elliptic_curves:
            tmp.append(elliptic_curve.id)
        elliptic_curves = tmp

        detected_elliptic_curves = []
        count = 0

        while True:
            conn = self._scanner.handler.connect()
            conn.settimeout(2.0)

            conn_tls = SSLv30Connection(
                protocol_version=protocol_version
            )

            record_handshake = self._build_tls_base_client_hello(
                protocol_version,
                cipher_suites,
                elliptic_curves=elliptic_curves
            )

            conn.send_list(conn_tls.encode(record_handshake))

            time_start = datetime.now()
            server_key_exchange = None

            while server_key_exchange is None:
                tmp_time = datetime.now() - time_start
                if tmp_time.total_seconds() > 5.0:
                    return detected_elliptic_curves

                try:
                    data = conn.recv(4096)
                except ConnectionError:
                    return detected_elliptic_curves
                except socket.timeout:
                    conn.close()
                    return detected_elliptic_curves

                try:
                    conn_tls.decode(data)
                except WrongProtocolVersion:
                    # Send alert and close socket
                    record_alert = Alert()
                    record_alert.level = "fatal"
                    record_alert.description = "protocol_version"
                    conn.send_list(conn_tls.encode(record_alert))
                    conn.close()
                    return detected_elliptic_curves

                while not conn_tls.is_empty():
                    record = conn_tls.pop_record()
                    if isinstance(record, Handshake):
                        if isinstance(record.payload, ServerKeyExchange):
                            server_key_exchange = record.payload
                    elif isinstance(record, Alert):
                        if record.level == 2:
                            return detected_elliptic_curves

            conn.close()
            # stop if no ServerKeyExchange was sent
            if server_key_exchange is None:
                break

            # try to extract the ec id
            tmp_ec_id = None
            if isinstance(server_key_exchange.payload, ServerKeyExchangeECDSA):
                tmp_params = server_key_exchange.payload.params
                if isinstance(tmp_params, ServerECDHParamsField):
                    if isinstance(tmp_params.curve_params, ECParametersNamedCurveField):
                        tmp_ec_id = tmp_params.curve_params.namedcurve

            if tmp_ec_id is None:
                return detected_elliptic_curves

            # stop if we get an unexpected ec id
            if tmp_ec_id not in elliptic_curves:
                return detected_elliptic_curves
            detected_elliptic_curves.append(tmp_ec_id)
            elliptic_curves.remove(tmp_ec_id)

            count += 1
            if limit is not False and limit <= count:
                break

        return detected_elliptic_curves


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
                conn._socket,
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
            conn_ssl = SSL.Connection(ctx, conn._socket)
            conn_ssl.set_tlsext_host_name(
                self._scanner.handler.hostname.encode("utf-8")
            )
            conn_ssl.set_connect_state()
            try:
                conn_ssl.do_handshake()
            except Exception as e:
                # ToDo:
                # print(e)
                conn_ssl.close()
                continue
            return conn_ssl

        return None
