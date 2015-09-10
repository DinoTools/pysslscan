from sslscan import modules
from sslscan._helper.openssl import version_openssl, version_pyopenssl, convert_versions2methods
from sslscan.module import STATUS_OK, STATUS_ERROR
from sslscan.module.scan import BaseScan

openssl_enabled = False
version_info = []
try:
    from OpenSSL import SSL, _util

    openssl_enabled = True
    if version_pyopenssl:
        version_info.append("pyOpenSSL version {}".format(version_pyopenssl))
    if version_openssl:
        version_info.append("OpenSSL version {}".format(version_openssl))
except ImportError:
    pass


class ServerRenegotiation(BaseScan):
    """
    Test if renegotiation is supported by the server.
    """

    name = "server.renegotiation"
    status = STATUS_OK if openssl_enabled else STATUS_ERROR
    status_messages = ["OpenSSL is {}".format("available" if openssl_enabled else "missing")] + version_info

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def run(self):
        kb = self._scanner.get_knowledge_base()

        protocol_versions = self._scanner.get_enabled_versions()

        methods = convert_versions2methods(protocol_versions)
        methods.reverse()

        for method in methods:
            try:
                ctx = SSL.Context(method)
            except:
                # ToDo:
                continue

            ctx.set_cipher_list("ALL:COMPLEMENT")
            ctx.set_options(_util.lib.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)
            conn = self._scanner.handler.connect()
            conn_ssl = SSL.Connection(ctx, conn._socket)
            conn_ssl.set_tlsext_host_name(
                self._scanner.handler.hostname.encode("utf-8")
            )
            conn_ssl.set_connect_state()
            try:
                conn_ssl.do_handshake()
            except Exception as e:
                # ToDo:
                # print(e)
                conn_ssl.close()
                continue

            kb.set("server.renegotiation.support", False)
            if _util.lib.SSL_get_secure_renegotiation_support(conn_ssl._ssl) == 1:
                kb.set("server.renegotiation.secure", True)
                kb.set("server.renegotiation.support", True)
            else:
                kb.set("server.renegotiation.secure", False)
                kb.set("server.renegotiation.support", False)
                cipher_status = _util.lib.SSL_do_handshake(conn_ssl._ssl)
                if cipher_status == 1:
                    if _util.lib.SSL_get_state(conn_ssl._ssl) == SSL.SSL_ST_OK:
                        kb.set("server.renegotiation.support", True)

            conn_ssl.close()


modules.register(ServerRenegotiation)
