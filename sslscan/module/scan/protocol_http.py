from OpenSSL import SSL

from sslscan import modules
from sslscan.kb import ResultGroup, ResultValue
from sslscan.module.scan import BaseScan


class ProtocolHTTP(BaseScan):
    """
    Extract additional information.

    Perform a HTTP-request and extract additional information.
    """

    name = "protocol.http"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def run(self):
        kb = self.scanner.get_knowledge_base()

        methods = self.scanner.get_enabled_methods()
        methods.reverse()
        for method in methods:
            try:
                ctx = SSL.Context(method)
            except:
                # ToDo:
                continue

            ctx.set_cipher_list("ALL:COMPLEMENT")
            conn = self.scanner.handler.connect()
            conn_ssl = SSL.Connection(ctx, conn)
            conn_ssl.set_tlsext_host_name(
                self.scanner.handler.hostname.encode("utf-8")
            )
            conn_ssl.set_connect_state()
            try:
                conn_ssl.do_handshake()
            except Exception as e:
                print(e)
                conn_ssl.close()
                continue

            req_res = self.scanner.handler.request(conn_ssl)
            conn_ssl.close()

            if req_res is None:
                return

            kb.set(
                "server.custom.protocol.http",
                ResultGroup(
                    label="HTTP Information"
                )
            )

            kb.set(
                "server.custom.protocol.http.status.code",
                ResultValue(
                    label="Status-Code",
                    value=req_res.get("code")
                )
            )

            kb.set(
                "server.custom.protocol.http.status.message",
                ResultValue(
                    label="Status-Message",
                    value=req_res.get("message")
                )
            )

            kb.set(
                "server.custom.protocol.http.version",
                ResultValue(
                    label="Version",
                    value=req_res.get("version")
                )
            )

            hsts = None
            for name, value in req_res.get("headers"):
                if name.lower() == "strict-transport-security":
                    hsts = value
                elif name.lower() == "server":
                    kb.set(
                        "server.custom.protocol.http.header.server",
                        ResultValue(
                            label="Server",
                            value=value
                        )
                    )

            res_hsts = ResultValue(
                label="Strict-Transport-Security"
            )

            if hsts is not None:
                res_hsts.value = True
            else:
                res_hsts.value = False

            kb.set("server.custom.protocol.http.hsts", res_hsts)

            return

modules.register(ProtocolHTTP)
