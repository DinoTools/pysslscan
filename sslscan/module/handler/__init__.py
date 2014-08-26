from sslscan.module import BaseModule

class BaseHandler(BaseModule):
    config_options = BaseModule.config_options + [
        (
            "hostname", {
                "default": None,
                "help": ""
            }
        ),

    ]
    def __init__(self, host=None, port=None, **kwargs):
        self.host = "127.0.0.1"
        self._server_info = None
        BaseModule.__init__(self, **kwargs)
        if host is not None:
            self.host = host
        if port is not None:
            self.port = port

    def connect(self):
        return None

    def get_server_info(self, conn=None):
        if self._server_info is None and conn is not None:
           self.request(conn)
        return self._server_info

    @property
    def hostname(self):
        hostname = self.config.get_value("hostname")
        if hostname is not None:
            return hostname
        return self.host

    def request(self, conn):
        return None
