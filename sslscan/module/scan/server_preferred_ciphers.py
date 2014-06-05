from socket import socket

from OpenSSL import SSL, _util

from sslscan import modules
from sslscan.kb import Cipher
from sslscan.module.scan import BaseScan


class ServerPreferredCiphers(BaseScan):
    """
    Detect preferred server ciphers.
    """

    name="server.preferred_ciphers"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def run(self):
        kb = self.scanner.get_knowledge_base()

        for method in self.scanner.get_enabled_methods():
            try:
                ctx = SSL.Context(method)
            except:
                # ToDo:
                continue

            ctx.set_cipher_list("ALL:COMPLEMENT")
            conn = self.scanner.handler.connect()
            conn_ssl = SSL.Connection(ctx, conn)
            conn_ssl.set_connect_state()

            cipher_status = _util.lib.SSL_do_handshake(conn_ssl._ssl)

            cipher_ssl = _util.lib.SSL_get_current_cipher(conn_ssl._ssl)

            cipher = Cipher(
                bits=_util.lib.SSL_CIPHER_get_bits(cipher_ssl, _util.ffi.NULL),
                method=method,
                name=_util.ffi.string(_util.lib.SSL_CIPHER_get_name(cipher_ssl))
            )

            if cipher_status < 0:
                cipher.status = -1
            elif cipher_status == 0:
                cipher.status = 0
            elif cipher_status == 1:
                cipher.status = 1

            kb.append("server.preferred_ciphers", cipher)


            conn_ssl.close()


modules.register(ServerPreferredCiphers)
