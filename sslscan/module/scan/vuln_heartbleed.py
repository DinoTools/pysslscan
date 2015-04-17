# https://tools.ietf.org/html/rfc6520

import binascii
from datetime import datetime

from sslscan import modules
from sslscan.kb import ResultGroup, ResultValue
from sslscan.module.scan import BaseScan

import flextls
from flextls.exception import NotEnoughData
from flextls.protocol.handshake import Handshake, ServerHello, ServerHelloDone
from flextls.protocol.handshake.extension import Extension, Heartbeat as HeartbeatExtension
from flextls.protocol.record import SSLv3Record
from flextls.protocol.heartbeat import Heartbeat
from flextls.protocol.alert import Alert


class VulnerabilityHeartbleed(BaseScan):
    """
    Test if server is vulnerable.

    Test if the heartbleed bug can be used to extract additional server
    information.
    """

    name = "vuln.heartbleed"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def _send_heartbeat(self, protocol_version, cipher_suites):

        record_tls = self._build_tls_base_client_hello(
            protocol_version,
            cipher_suites
        )

        ext_hb = HeartbeatExtension()
        ext_hb.mode = 1
        record_client_hello = record_tls.payload
        record_client_hello.extensions.append(Extension() + ext_hb)

        conn = self._scanner.handler.connect()
        conn.settimeout(2.0)

        conn.send(record_tls.encode())

        time_start = datetime.now()
        server_hello_done = False
        heartbeat_supported = False
        data = b""
        while server_hello_done is False:
            tmp_time = datetime.now() - time_start
            if tmp_time.total_seconds() > 5.0:
                return False

            try:
                tmp_data = conn.recv(4096)
            except:
                return None

            data += tmp_data
            while True:
                try:
                    (record, data) = SSLv3Record.decode(data)
                except NotEnoughData:
                    break

                if isinstance(record.payload, Handshake):
                    if isinstance(record.payload.payload, ServerHello):
                        server_hello = record.payload.payload
                        for ext in server_hello.extensions:
                            if isinstance(ext.payload, HeartbeatExtension):
                                heartbeat_supported = True

                    if isinstance(record.payload.payload, ServerHelloDone):
                        server_hello_done = True

                elif isinstance(record.payload, Alert):
                    if record.payload.level == 2:
                        return None

        # ToDo: use connection state
        if protocol_version == flextls.registry.version.SSLv3:
            ver_minor = 0
        elif protocol_version == flextls.registry.version.TLSv10:
            ver_minor = 1
        elif protocol_version == flextls.registry.version.TLSv11:
            ver_minor = 2
        elif protocol_version == flextls.registry.version.TLSv12:
            ver_minor = 3

        record = SSLv3Record()
        record.version.major = 3
        record.version.minor = ver_minor

        record.payload = binascii.unhexlify(b"014000")
        record.length = 3
        record.content_type = 24

        conn.send(record.encode())
        time_start = datetime.now()
        record_with_heartbeat = None
        data = b""
        while record_with_heartbeat is None:
            tmp_time = datetime.now() - time_start
            if tmp_time.total_seconds() > 5.0:
                return heartbeat_supported

            try:
                tmp_data = conn.recv(4096)
            except:
                return heartbeat_supported

            data += tmp_data
            while True:
                try:
                    (record, data) = SSLv3Record.decode(
                        data,
                        payload_auto_decode=False
                    )
                except NotEnoughData:
                    break

                if record.content_type == record.get_payload_pattern(Heartbeat):
                    record_with_heartbeat = record

                elif isinstance(record.payload, Alert):
                    if record.payload.level == 2:
                        return heartbeat_supported

        return record_with_heartbeat

    def run(self):
        kb = self._scanner.get_knowledge_base()

        kb.set(
            "vulnerability.custom.heartbleed",
            ResultGroup(
                label="Heartbleed(Vulnerability)"
            )
        )

        result_heartbeat = None
        for protocol_version in self._scanner.get_enabled_versions():
            if protocol_version != flextls.registry.version.SSLv2:
                cipher_suites = flextls.registry.tls.cipher_suites.get_ids()
                result_heartbeat = self._send_heartbeat(protocol_version, cipher_suites)
                if result_heartbeat is not None:
                    break

        if result_heartbeat is None:
            return

        kb_supported = None
        kb_vulnerable = None
        if result_heartbeat is False:
            kb_supported = False
            kb_vulnerable = False
        elif result_heartbeat is True:
            kb_supported = True
            kb_vulnerable = False
        else:
            kb_supported = True
            kb_vulnerable = True

        #print(hb.payload.payload)
        kb.set(
            "vulnerability.custom.heartbleed.extension_present",
            ResultValue(
                label="Heartbeat Extension present",
                value=kb_supported
            )
        )

        kb.set(
            "vulnerability.custom.heartbleed.vulnerable",
            ResultValue(
                label="Vulnerable",
                value=kb_vulnerable
            )
        )

        if kb_vulnerable is True:
            payload = result_heartbeat.payload
            # Remove 3-byte Heartbeat header from payload data
            if len(payload) < 3:
                payload = b""
            else:
                payload = payload[3:]

            kb.set(
                "vulnerability.custom.heartbleed.payload.length",
                ResultValue(
                    label="Payload-Length",
                    value=len(payload)
                )
            )


modules.register(VulnerabilityHeartbleed)
