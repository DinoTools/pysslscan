from socket import socket

from sslscan import modules
from sslscan.module.handler import BaseHandler


class TCP(BaseHandler):
    """
    Handle raw TCP-connections.
    """

    name = "tcp"

    def __init__(self, **kwargs):
        self.port = 443
        BaseHandler.__init__(self, **kwargs)

    def connect(self):
        conn = socket()
        conn.connect((self.host, self.port))

        return conn


modules.register(TCP)
