from OpenSSL import SSL, _util

from sslscan import modules
from sslscan.module.scan import BaseScan


class ServerCertificate(BaseScan):
    """
    Extract certificate information.
    """

    name = "server.certificate"

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def run(self):
        methods = self.scanner.get_enabled_methods()
        methods.reverse()
        for method in methods:
            try:
                ctx = SSL.Context(method)
            except:
                # ToDo:
                continue

            ctx.set_cipher_list("ALL:COMPLEMENT")
            conn = self.scanner.handler.connect()
            conn_ssl = SSL.Connection(ctx, conn)
            conn_ssl.set_tlsext_host_name(
                self.scanner.handler.hostname.encode("utf-8")
            )
            conn_ssl.set_connect_state()
            try:
                conn_ssl.do_handshake()
            except Exception as e:
                print(e)
                conn_ssl.close()
                continue

            cert = conn_ssl.get_peer_certificate()
            kb = self.scanner.get_knowledge_base()
            print(cert)
            kb.set("server.certificate", cert)

            compression_ssl = _util.lib.SSL_get_current_compression(conn_ssl._ssl)
            compression = _util.lib.SSL_COMP_get_name(compression_ssl)
            if compression == _util.ffi.NULL:
                kb.set("server.session.compression", False)
            else:
                kb.set("server.session.compression", _util.ffi.string(compression))

            expansion_ssl = _util.lib.SSL_get_current_expansion(conn_ssl._ssl)
            expansion = _util.lib.SSL_COMP_get_name(expansion_ssl)
            if expansion == _util.ffi.NULL:
                kb.set("server.session.expansion", False)
            else:
                kb.set("server.session.expansion", _util.ffi.string(compression))

            return


modules.register(ServerCertificate)
