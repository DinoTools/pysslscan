from socket import socket

from OpenSSL import SSL, _util

from sslscan import modules
from sslscan.kb import Cipher
from sslscan.module.scan import BaseScan


class ServerCiphers(BaseScan):
    """
    Test a server for provided ciphers.
    """

    name="server.ciphers"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def run(self):
        ciphers = []
        for method in self.scanner.get_enabled_methods():
            try:
                ctx = SSL.Context(method)
            except:
                # ToDo:
                continue
            conn = SSL.Connection(ctx)
            ctx.set_cipher_list("ALL:COMPLEMENT")
            cipher_ptr = _util.lib.SSL_get_ciphers(conn._ssl)
            for i in range(_util.lib.sk_SSL_CIPHER_num(cipher_ptr)):
                cipher = _util.lib.sk_SSL_CIPHER_value(cipher_ptr, i)
                ciphers.append(
                    Cipher(
                        bits=_util.lib.SSL_CIPHER_get_bits(cipher, _util.ffi.NULL),
                        method=method,
                        name=_util.ffi.string(_util.lib.SSL_CIPHER_get_name(cipher))
                    )
                )

        kb = self.scanner.get_knowledge_base()

        for cipher in ciphers:
            conn = self.scanner.handler.connect()
            # ToDo: error handling
            ctx = SSL.Context(cipher.method)
            ctx.set_cipher_list(cipher.name)
            conn_ssl = SSL.Connection(ctx, conn)
            #print(conn_ssl.get_cipher_list())
            conn_ssl.set_connect_state()

            cipher_status = _util.lib.SSL_do_handshake(conn_ssl._ssl)

            if cipher_status < 0:
                cipher.status = -1
            elif cipher_status == 0:
                cipher.status = 0
            elif cipher_status == 1:
                cipher.status = 1

            # ToDo: handle alerts

            kb.append('server.ciphers', cipher)

            conn_ssl.close()


modules.register(ServerCiphers)
