from datetime import datetime
import os

import flextls
from flextls.connection import DTLSv10Connection, SSLv30Connection
from flextls.exception import NotEnoughData, WrongProtocolVersion
from flextls.field import CipherSuiteField, CompressionMethodField
from flextls.field import SSLv2CipherSuiteField
from flextls.field import ServerNameField, HostNameField
from flextls.field import ServerECDHParamsField, ECParametersNamedCurveField
from flextls.protocol.handshake import ClientHello, Handshake, ServerHello, ServerCertificate, ServerKeyExchange, ServerHelloDone
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


class BaseHookAction(object):
    def __init__(self, func, func_args=None):
        self.func = func
        self.args = func_args

    def __call__(self, *args, **kwargs):
        if self.args:
            tmp_args = dict(self.args.items())
            tmp_args.update(kwargs)
        else:
            tmp_args = kwargs
        return self.func(*args, **tmp_args)


class BaseHook(object):
    def __init__(self):
        self._signals = {}

    def call(self, **kwargs):
        raise NotImplementedError

    def connect(self, func, name=None, args=None):
        if name is None:
            # ToDo: better ways to do this?
            name = os.urandom(10)
        self._signals[name] = BaseHookAction(
            func=func,
            func_args=args
        )

    def remove(self):
        pass


class RecordHook(BaseHook):
    def call(self, record, **kwargs):
        for signal in self._signals.values():
            tmp_record = signal(record, **kwargs)
            if tmp_record:
                record = tmp_record

        return record


class BaseScan(BaseModule):
    def __init__(self, **kwargs):
        BaseModule.__init__(self, **kwargs)
        self.build_dtls_client_hello_hooks = RecordHook()
        self.parse_dtls_server_records_hooks = RecordHook()
        self.build_tls_client_hello_hooks = RecordHook()
        self.parse_tls_server_records_hooks = RecordHook()

        self.build_dtls_client_hello_hooks.connect(
            self._hook_dtls_client_hello_cipher_suites,
            "cipher_suites"
        )
        self.build_dtls_client_hello_hooks.connect(
            self._hook_dtls_client_hello_compression,
            name="compression"
        )
        self.build_dtls_client_hello_hooks.connect(
            self._hook_dtls_client_hello_ec_point_formats,
            name="ec_point_formats"
        )
        self.build_dtls_client_hello_hooks.connect(
            self._hook_dtls_client_hello_elliptic_curves,
            name="elliptic_curves"
        )
        self.build_dtls_client_hello_hooks.connect(
            self._hook_dtls_client_hello_heartbeat,
            name="heartbeat"
        )
        self.build_dtls_client_hello_hooks.connect(
            self._hook_dtls_client_hello_session_ticket,
            "session_ticket"
        )
        self.build_dtls_client_hello_hooks.connect(
            self._hook_dtls_client_hello_signature_algorithms,
            name="signature_algorithms"
        )
        self.build_dtls_client_hello_hooks.connect(
            self._hook_dtls_client_hello_sni,
            name="sni"
        )

        self.parse_dtls_server_records_hooks.connect(
            self._hook_parse_dtls_server_hello_certificate,
            name="certificate"
        )
        self.parse_dtls_server_records_hooks.connect(
            self._hook_parse_dtls_server_hello_compression,
            name="compression"
        )
        self.parse_dtls_server_records_hooks.connect(
            self._hook_parse_dtls_server_hello_point_formats,
            name="point_formats"
        )

        self.build_tls_client_hello_hooks.connect(
            self._hook_tls_client_hello_cipher_suites,
            "cipher_suites"
        )
        self.build_tls_client_hello_hooks.connect(
            self._hook_tls_client_hello_compression,
            name="compression"
        )
        self.build_tls_client_hello_hooks.connect(
            self._hook_tls_client_hello_ec_point_formats,
            name="ec_point_formats"
        )
        self.build_tls_client_hello_hooks.connect(
            self._hook_tls_client_hello_elliptic_curves,
            name="elliptic_curves"
        )
        self.build_tls_client_hello_hooks.connect(
            self._hook_tls_client_hello_heartbeat,
            name="heartbeat"
        )
        self.build_tls_client_hello_hooks.connect(
            self._hook_tls_client_hello_session_ticket,
            "session_ticket"
        )
        self.build_tls_client_hello_hooks.connect(
            self._hook_tls_client_hello_signature_algorithms,
            name="signature_algorithms"
        )
        self.build_tls_client_hello_hooks.connect(
            self._hook_tls_client_hello_sni,
            name="sni"
        )

        self.parse_tls_server_records_hooks.connect(
            self._hook_parse_tls_server_hello_certificate,
            name="certificate"
        )
        self.parse_tls_server_records_hooks.connect(
            self._hook_parse_tls_server_hello_compression,
            name="compression"
        )
        self.parse_tls_server_records_hooks.connect(
            self._hook_parse_tls_server_hello_point_formats,
            name="point_formats"
        )

    def _hook_parse_dtls_server_hello_certificate(self, record):
        kb = self._scanner.get_knowledge_base()
        raw_cert = kb.get("server.certificate.raw")
        if raw_cert is not None:
            return

        if not isinstance(record, DTLSv10Handshake) or not isinstance(record.payload, ServerCertificate):
            return

        raw_certs = []
        for raw_cert in record.payload.certificate_list:
            raw_certs.append(raw_cert.value)
        kb.set("server.certificate.raw", raw_certs)

    def _hook_parse_dtls_server_hello_compression(self, record):
        # get compression method
        kb = self._scanner.get_knowledge_base()
        if kb.get("server.session.compression"):
            return

        if not (isinstance(record, DTLSv10Handshake) and isinstance(record.payload, ServerHello)):
            return

        comp_method = flextls.registry.tls.compression_methods.get(
            record.payload.compression_method
        )
        kb.set("server.session.compression", comp_method)

    def _hook_parse_dtls_server_hello_point_formats(self, record):
        kb = self._scanner.get_knowledge_base()
        if kb.get("server.ec.point_formats"):
            return

        if not (isinstance(record, DTLSv10Handshake) and isinstance(record.payload, ServerHello)):
            return

        for extension in record.payload.extensions:
            if isinstance(extension.payload, EcPointFormats):
                tmp_formats = []
                for format_id in extension.payload.point_format_list:
                    tmp_format = flextls.registry.ec.point_formats.get(format_id.value)
                    tmp_formats.append(tmp_format)

                kb.set("server.ec.point_formats", tmp_formats)
                return

    def _hook_parse_tls_server_hello_certificate(self, record):
        kb = self._scanner.get_knowledge_base()
        raw_cert = kb.get("server.certificate.raw")
        if raw_cert is not None:
            return

        if not isinstance(record, Handshake) or not isinstance(record.payload, ServerCertificate):
            return

        raw_certs = []
        for raw_cert in record.payload.certificate_list:
            raw_certs.append(raw_cert.value)
        kb.set("server.certificate.raw", raw_certs)

    def _hook_parse_tls_server_hello_compression(self, record):
        # get compression method
        kb = self._scanner.get_knowledge_base()
        if kb.get("server.session.compression"):
            return

        if not (isinstance(record, Handshake) and isinstance(record.payload, ServerHello)):
            return

        comp_method = flextls.registry.tls.compression_methods.get(
            record.payload.compression_method
        )
        kb.set("server.session.compression", comp_method)

    def _hook_parse_tls_server_hello_point_formats(self, record):
        kb = self._scanner.get_knowledge_base()
        if kb.get("server.ec.point_formats"):
            return

        if not (isinstance(record, Handshake) and isinstance(record.payload, ServerHello)):
            return

        for extension in record.payload.extensions:
            if isinstance(extension.payload, EcPointFormats):
                tmp_formats = []
                for format_id in extension.payload.point_format_list:
                    tmp_format = flextls.registry.ec.point_formats.get(format_id.value)
                    tmp_formats.append(tmp_format)

                kb.set("server.ec.point_formats", tmp_formats)
                return

    def _hook_dtls_client_hello_cipher_suites(self, record):
        cipher_suites = flextls.registry.tls.cipher_suites[:]
        for cipher_suite in cipher_suites:
            if cipher_suite.dtls is True:
                cipher = CipherSuiteField()
                cipher.value = cipher_suite.id
                record.payload.cipher_suites.append(cipher)
        return record

    def _hook_dtls_client_hello_compression(self, record):
        comp_methods = flextls.registry.tls.compression_methods.get_ids()
        for comp_id in comp_methods:
            comp = CompressionMethodField()
            comp.value = comp_id
            record.payload.compression_methods.append(comp)
        return record

    def _hook_dtls_client_hello_ec_point_formats(self, record):
        ext_ec_point_formats = EcPointFormats()
        a = ext_ec_point_formats.get_field("point_format_list")
        for tmp_pf in flextls.registry.ec.point_formats:
            v = a.item_class("unnamed", tmp_pf.id)
            a.value.append(v)

        record.payload.extensions.append(Extension() + ext_ec_point_formats)
        return record

    def _hook_dtls_client_hello_elliptic_curves(self, record):
        ext_elliptic_curves = EllipticCurves()
        a = ext_elliptic_curves.get_field("elliptic_curve_list")
        elliptic_curves = flextls.registry.ec.named_curves.get_ids()
        for i in elliptic_curves:
            v = a.item_class("unnamed", None)
            v.value = i
            a.value.append(v)

        record.payload.extensions.append(Extension() + ext_elliptic_curves)
        return record

    def _hook_dtls_client_hello_heartbeat(self, record):
        hb_ext = HeartbeatExt()
        hb_ext.mode = 1
        record.payload.extensions.append(Extension() + hb_ext)
        return record

    def _hook_dtls_client_hello_signature_algorithms(self, record):
        ext_signature_algorithm = SignatureAlgorithms()
        a = ext_signature_algorithm.get_field("supported_signature_algorithms")

        hash_algorithms = flextls.registry.tls.hash_algorithms.get_ids()
        sign_algorithms = flextls.registry.tls.signature_algorithms.get_ids()
        for i in hash_algorithms:
            for j in sign_algorithms:
                v = a.item_class("unnamed")
                v.hash = i
                v.signature = j
                a.value.append(v)

        record.payload.extensions.append(Extension() + ext_signature_algorithm)
        return record

    def _hook_dtls_client_hello_session_ticket(self, record):
        record.payload.extensions.append(Extension() + SessionTicketTLS())
        return record

    def _hook_dtls_client_hello_sni(self, record):
        server_name = ServerNameField()
        server_name.payload = HostNameField("")
        server_name.payload.value = self._scanner.handler.hostname.encode("utf-8")
        tmp_sni = ServerNameIndication()
        tmp_sni.server_name_list.append(server_name)
        tmp_ext_sni = Extension() + tmp_sni
        record.payload.extensions.append(tmp_ext_sni)

        return record

    def _hook_tls_client_hello_cipher_suites(self, record):
        cipher_suites = flextls.registry.tls.cipher_suites[:]
        for cipher_suite in cipher_suites:
            cipher = CipherSuiteField()
            cipher.value = cipher_suite.id
            record.payload.cipher_suites.append(cipher)
        return record

    def _hook_tls_client_hello_compression(self, record):
        comp_methods = flextls.registry.tls.compression_methods.get_ids()
        for comp_id in comp_methods:
            comp = CompressionMethodField()
            comp.value = comp_id
            record.payload.compression_methods.append(comp)
        return record

    def _hook_tls_client_hello_ec_point_formats(self, record):
        ext_ec_point_formats = EcPointFormats()
        a = ext_ec_point_formats.get_field("point_format_list")
        for tmp_pf in flextls.registry.ec.point_formats:
            v = a.item_class("unnamed", tmp_pf.id)
            a.value.append(v)

        record.payload.extensions.append(Extension() + ext_ec_point_formats)
        return record

    def _hook_tls_client_hello_elliptic_curves(self, record):
        ext_elliptic_curves = EllipticCurves()
        a = ext_elliptic_curves.get_field("elliptic_curve_list")
        elliptic_curves = flextls.registry.ec.named_curves.get_ids()
        for i in elliptic_curves:
            v = a.item_class("unnamed", None)
            v.value = i
            a.value.append(v)

        record.payload.extensions.append(Extension() + ext_elliptic_curves)
        return record

    def _hook_tls_client_hello_heartbeat(self, record):
        hb_ext = HeartbeatExt()
        hb_ext.mode = 1
        record.payload.extensions.append(Extension() + hb_ext)
        return record

    def _hook_tls_client_hello_session_ticket(self, record):
        record.payload.extensions.append(Extension() + SessionTicketTLS())
        return record

    def _hook_tls_client_hello_signature_algorithms(self, record):
        ext_signature_algorithm = SignatureAlgorithms()
        a = ext_signature_algorithm.get_field("supported_signature_algorithms")

        hash_algorithms = flextls.registry.tls.hash_algorithms.get_ids()
        sign_algorithms = flextls.registry.tls.signature_algorithms.get_ids()
        for i in hash_algorithms:
            for j in sign_algorithms:
                v = a.item_class("unnamed")
                v.hash = i
                v.signature = j
                a.value.append(v)

        record.payload.extensions.append(Extension() + ext_signature_algorithm)
        return record

    def _hook_tls_client_hello_sni(self, record):
        server_name = ServerNameField()
        server_name.payload = HostNameField("")
        server_name.payload.value = self._scanner.handler.hostname.encode("utf-8")
        tmp_sni = ServerNameIndication()
        tmp_sni.server_name_list.append(server_name)
        tmp_ext_sni = Extension() + tmp_sni
        record.payload.extensions.append(tmp_ext_sni)

        return record

    def build_dtls_client_hello(self, protocol_version):
        ver_major, ver_minor = flextls.helper.get_tls_version(protocol_version)

        hello = DTLSv10ClientHello()
        hello.random = os.urandom(32)
        hello.version.major = ver_major
        hello.version.minor = ver_minor

        msg_handshake = DTLSv10Handshake()
        msg_handshake.set_payload(hello)

        return self.build_dtls_client_hello_hooks.call(msg_handshake)

    def build_tls_client_hello(self, protocol_version):
        ver_major, ver_minor = flextls.helper.get_tls_version(protocol_version)

        hello = ClientHello()
        hello.random = os.urandom(32)
        hello.version.major = ver_major
        hello.version.minor = ver_minor

        msg_handshake = Handshake()
        msg_handshake.set_payload(hello)

        return self.build_tls_client_hello_hooks.call(msg_handshake)

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

    def connect(self, protocol_version, stop_condition=None):
        if protocol_version & flextls.registry.version.DTLS != 0:
            return self.connect_dtls(
                protocol_version,
                stop_condition=stop_condition
            )

        return self.connect_tls(
            protocol_version,
            stop_condition=stop_condition
        )

    def connect_dtls(self, protocol_version, stop_condition=None):
        def _default_stop_condition(record, records):
            return isinstance(record, DTLSv10Handshake) and \
                isinstance(record.payload, ServerHelloDone)

        if stop_condition is None:
            stop_condition = _default_stop_condition

        conn = self._scanner.handler.connect()
        conn.settimeout(2.0)

        conn_dtls = DTLSv10Connection(
            protocol_version=protocol_version
        )

        record_handshake = self.build_dtls_client_hello(
            protocol_version
        )

        conn.send_list(conn_dtls.encode(record_handshake))
        time_start = datetime.now()
        verify_request = None
        records = []
        while verify_request is None:
            tmp_time = datetime.now() - time_start
            if tmp_time.total_seconds() > 5.0:
                return records

            try:
                data = conn.recv(4096)
            except ConnectionError:
                return records

            try:
                conn_dtls.decode(data)
            except WrongProtocolVersion:
                # Send alert to stop communication
                record_alert = Alert()
                record_alert.level = "fatal"
                record_alert.description = "protocol_version"
                conn.send_list(conn_dtls.encode(record_alert))
                conn.close()
                return records

            if not conn_dtls.is_empty():
                record = conn_dtls.pop_record()
                self.parse_dtls_server_records_hooks.call(record)
                records.append(record)
                if isinstance(record, DTLSv10Handshake):
                    if isinstance(record.payload, DTLSv10HelloVerifyRequest):
                        verify_request = record.payload
                        break
                elif isinstance(record, Alert):
                    if record.level == 2:
                        conn.close()
                        return records

        if verify_request is None:
            return records

        record_handshake.payload.cookie = verify_request.cookie
        conn.send_list(conn_dtls.encode(record_handshake))

        time_start = datetime.now()
        run = True
        while run:
            tmp_time = datetime.now() - time_start
            if tmp_time.total_seconds() > 5.0:
                return records

            try:
                data = conn.recv(4096)
            except ConnectionError:
                return records
            except socket.timeout:
                conn.close()
                return records

            try:
                conn_dtls.decode(data)
            except WrongProtocolVersion:
                # Send alert and close socket
                record_alert = Alert()
                record_alert.level = "fatal"
                record_alert.description = "protocol_version"
                conn.send_list(conn_dtls.encode(record_alert))
                conn.close()
                return None

            while not conn_dtls.is_empty():
                record = conn_dtls.pop_record()
                self.parse_dtls_server_records_hooks.call(record)
                records.append(record)

                if isinstance(record, Alert):
                    if record.level == 2:
                        return records

                if stop_condition(record, records):
                    run = False

        record_alert = Alert()
        record_alert.level = 1
        record_alert.description = 0
        conn.send_list(conn_dtls.encode(record_alert))
        conn.close()
        return records

    def connect_tls(self, protocol_version, stop_condition=None):
        def _default_stop_condition(record, records):
            return isinstance(record, Handshake) and \
                isinstance(record.payload, ServerHelloDone)

        if stop_condition is None:
            stop_condition = _default_stop_condition

        conn = self._scanner.handler.connect()
        conn.settimeout(2.0)

        conn_tls = SSLv30Connection(
            protocol_version=protocol_version
        )

        record_handshake = self.build_tls_client_hello(
            protocol_version
        )

        conn.send_list(conn_tls.encode(record_handshake))

        time_start = datetime.now()

        records = []
        run = True
        while run:
            tmp_time = datetime.now() - time_start
            if tmp_time.total_seconds() > 5.0:
                return records

            try:
                data = conn.recv(4096)
            except ConnectionError:
                return records
            except socket.timeout:
                conn.close()
                return records

            try:
                conn_tls.decode(data)
            except WrongProtocolVersion:
                # Send alert and close socket
                record_alert = Alert()
                record_alert.level = "fatal"
                record_alert.description = "protocol_version"
                conn.send_list(conn_tls.encode(record_alert))
                conn.close()
                return None

            while not conn_tls.is_empty():
                record = conn_tls.pop_record()
                self.parse_tls_server_records_hooks.call(record)

                if isinstance(record, Alert):
                    if record.level == 2:
                        return records

                records.append(record)
                if stop_condition(record, records):
                    run = False

        conn.close()
        return records


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
