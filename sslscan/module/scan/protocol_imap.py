from sslscan import modules
from sslscan.kb import ResultGroup, ResultValue
from sslscan.module.scan import BaseInfoScan


class ProtocolIMAP(BaseInfoScan):
    """
    Extract additional information.

    Perform a IMAP request and extract additional information.
    """

    name = "protocol.imap"

    def run(self):
        if self._scanner.handler.name != "imap":
            return

        kb = self._scanner.get_knowledge_base()

        server_info = self._get_server_info()
        if server_info is None:
            return

        kb.set(
            "server.custom.protocol.imap",
            ResultGroup(
                label="IMAP Information"
            )
        )

        banner = server_info.get("banner")
        if banner is not None:
            kb.set(
                "server.custom.protocol.imap.banner",
                ResultValue(
                    label="Server banner",
                    value=banner
                )
            )


modules.register(ProtocolIMAP)
