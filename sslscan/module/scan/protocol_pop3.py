from sslscan import modules
from sslscan.kb import ResultGroup, ResultValue
from sslscan.module.scan import BaseInfoScan


class ProtocolPOP3(BaseInfoScan):
    """
    Extract additional information.

    Perform a POP3 request and extract additional information.
    """

    name = "protocol.pop3"

    def run(self):
        if self._scanner.handler.name != "pop3":
            return

        kb = self._scanner.get_knowledge_base()

        server_info = self._get_server_info()
        if server_info is None:
            return

        kb.set(
            "server.custom.protocol.pop3",
            ResultGroup(
                label="POP3 Information"
            )
        )

        hostname = server_info.get("hostname")
        if hostname is not None:
            kb.set(
                "server.custom.protocol.pop3.hostname",
                ResultValue(
                    label="Provided hostname",
                    value=hostname
                )
            )


modules.register(ProtocolPOP3)
