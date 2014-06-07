from smtplib import SMTP as PySMTP
from socket import socket

from sslscan import modules
from sslscan.module.handler.tcp import TCP


class SMTP(TCP):
    """
    Handle SMTP-connections.
    """

    name = "smtp"

    config_options = TCP.config_options + [
        (
            "starttls", {
                "default": False,
                "help": "",
                "type": "bool"
            }
        )
    ]

    def __init__(self, **kwargs):
        self.port = 25
        TCP.__init__(self, **kwargs)

    def connect(self):
        conn = socket()
        conn.connect((self.host, self.port))

        conn_smtp = PySMTP()
        conn_smtp.sock = conn
        conn_smtp.getreply()
        conn_smtp.ehlo_or_helo_if_needed()
        if self.config.get_value("starttls"):
            print("starttls enabled")
            if not conn_smtp.has_extn("starttls"):
                print("no starttls")
                return False
            (resp, reply) = conn_smtp.docmd("STARTTLS")
            print(resp)
            print(reply)
            if resp != "220":
                return False

        return conn


modules.register(SMTP)
