from OpenSSL import SSL

from sslscan import modules
from sslscan.kb import ResultGroup, ResultValue
from sslscan.module.scan import BaseScan


class ProtocolSMTP(BaseScan):
    """
    Extract additional information.

    Perform a SMTP request and extract additional information.
    """

    name = "protocol.smtp"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def run(self):
        if self._scanner.handler.name != "smtp":
            return

        kb = self._scanner.get_knowledge_base()

        methods = self._scanner.get_enabled_methods()
        methods.reverse()
        for method in methods:
            try:
                ctx = SSL.Context(method)
            except:
                # ToDo:
                continue

            server_info = self._scanner.handler.get_server_info()
            if server_info is None:
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
    
                server_info = self._scanner.handler.get_server_info(conn_ssl)
                conn_ssl.close()

            if server_info is None:
                return

            kb.set(
                "server.custom.protocol.smtp",
                ResultGroup(
                    label="SMTP Information"
                )
            )

            kb.set(
                "server.custom.protocol.smtp.banner",
                ResultValue(
                    label="Server banner",
                    value=server_info.get("banner")
                )
            )


modules.register(ProtocolSMTP)
