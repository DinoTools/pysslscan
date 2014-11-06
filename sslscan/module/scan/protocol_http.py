from sslscan import modules
from sslscan.kb import ResultGroup, ResultValue
from sslscan.module.scan import BaseInfoScan


class ProtocolHTTP(BaseInfoScan):
    """
    Extract additional information.

    Perform a HTTP-request and extract additional information.
    """

    name = "protocol.http"

    def run(self):
        if self._scanner.handler.name != "http":
            return

        kb = self._scanner.get_knowledge_base()


        server_info = self._get_server_info()
        if server_info is None:
            return

        if server_info is None:
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
                value=server_info.get("code")
            )
        )

        kb.set(
            "server.custom.protocol.http.status.message",
            ResultValue(
                label="Status-Message",
                value=server_info.get("message")
            )
        )

        kb.set(
            "server.custom.protocol.http.version",
            ResultValue(
                label="Version",
                value=server_info.get("version")
            )
        )

        hsts = False
        for name, value in server_info.get("headers"):
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


        if hsts is not False:
            hsts = True

        kb.set(
            "server.custom.protocol.http.hsts",
            ResultValue(
                label="Strict-Transport-Security",
                value=hsts
            )
        )


modules.register(ProtocolHTTP)
