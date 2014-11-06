# ToDo: This module has been disabled
# Should we list ciphers from the flextls registry instead?
# from OpenSSL import SSL, _util

from sslscan import modules
# from sslscan.kb import Cipher
from sslscan.module.scan import BaseScan


class ClientCiphers(BaseScan):
    """
    List all client ciphers.

    This module lists all ciphers available on the client.
    """

    name = "client.ciphers"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def run(self):
        kb = self._scanner.get_knowledge_base()

        for method in self._scanner.get_enabled_methods():
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
                kb.append(
                    'client.ciphers',
                    Cipher(
                        bits=_util.lib.SSL_CIPHER_get_bits(cipher, _util.ffi.NULL),
                        method=method,
                        name=_util.ffi.string(_util.lib.SSL_CIPHER_get_name(cipher))
                    )
                )


# modules.register(ClientCiphers)
