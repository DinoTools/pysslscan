import socket

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

    def close(self, conn, *args, **kwargs):
        return conn.close(*args, **kwargs)

    def connect(self):
        raise NotImplementedError

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

    def recv(self, conn, *args, **kwargs):
        return conn.recv(*args, **kwargs)

    def request(self, conn):
        return None

    def send(self, conn, *args, **kwargs):
        return conn.send(*args, **kwargs)


class Connection(object):
    def __init__(self, handler, sock):
        self._handler = handler
        self._socket = sock
        self._count_connect()

    def _count_connect(self):
        kb = self._handler.get_scanner().get_knowledge_base()
        kb.add('server.connection.count', 1)

    def _count_connection_close(self):
        kb = self._handler.get_scanner().get_knowledge_base()
        kb.add('server.connection.closed', 1)

    def _count_connection_timeout(self):
        kb = self._handler.get_scanner().get_knowledge_base()
        kb.add('server.connection.timeout', 1)

    def close(self, *args, **kwargs):
        self._count_connection_close()
        return self._handler.close(self._socket, *args, **kwargs)

    def recv(self, *args, **kwargs):
        try:
            return self._handler.recv(self._socket, *args, **kwargs)
        except socket.error as e:
            self._count_connection_timeout()
            raise e

    def send(self, *args, **kwargs):
        return self._handler.send(self._socket, *args, **kwargs)

    def send_list(self, pkgs, *args, **kwargs):
        for pkg in pkgs:
            self._handler.send(self._socket, pkg, *args, **kwargs)

    def settimeout(self, *args, **kwargs):
        return self._socket.settimeout(*args, **kwargs)