from datetime import datetime
import logging
from socket import socket
from time import sleep

from sslscan import modules
from sslscan.module.handler import BaseHandler, Connection


logger = logging.getLogger(__name__)


class TCP(BaseHandler):
    """
    Handle raw TCP-connections.
    """

    name = "tcp"

    config_options = BaseHandler.config_options + [
        (
            "delay", {
                "default": 0.1,
                "help": "Time to wait between connection attempts. This helps to avoid DoS detection. Default: 0.1s = 10 connections/second.",
                "type": "float",
            }
        )
    ]

    def __init__(self, **kwargs):
        if getattr(self, "port", None) is None:
            self.port = 443
        self.time_last_connect = None
        BaseHandler.__init__(self, **kwargs)

    def connect(self):
        time_delay = self.config.get_value("delay")

        if self.time_last_connect is not None:
            while True:
                tmp = datetime.now() - self.time_last_connect
                time_delta = tmp.total_seconds()
                time_sleep = time_delay - time_delta
                logger.debug(
                    "Time delta: {0:.2f}s -> Time to sleep: {1:.2f}s".format(
                        time_delta,
                        time_sleep
                    )
                )
                if time_delta > time_delay:
                    break
                sleep(time_sleep)

        self.time_last_connect = datetime.now()

        sock = socket()
        sock.connect((self.host, self.port))
        return Connection(
            handler=self,
            sock=sock
        )

modules.register(TCP)
