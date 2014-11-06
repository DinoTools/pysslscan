from sslscan import modules
from sslscan.kb import ResultGroup, ResultValue
from sslscan.module.scan import BaseInfoScan


class ProtocolSMTP(BaseInfoScan):
    """
    Extract additional information.

    Perform a SMTP request and extract additional information.
    """

    name = "protocol.smtp"

    def run(self):
        if self._scanner.handler.name != "smtp":
            return

        kb = self._scanner.get_knowledge_base()

        server_info = self._get_server_info()
        if server_info is None:
            return

        kb.set(
            "server.custom.protocol.smtp",
            ResultGroup(
                label="SMTP Information"
            )
        )

        banner = server_info.get("banner")
        if banner is not None:
            kb.set(
                "server.custom.protocol.smtp.banner",
                ResultValue(
                    label="Server banner",
                    value=banner
                )
            )


modules.register(ProtocolSMTP)
