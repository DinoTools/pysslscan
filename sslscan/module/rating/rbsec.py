from socket import socket

from OpenSSL import SSL

from sslscan import modules
from sslscan.module.rating import BaseRating


class RBSec(BaseRating):
    """
    Rating by rbsec.

    Rating used in the sslscan tool by rbsec.

    More infos: https://github.com/rbsec/sslscan
    """

    name="rbsec"

    def __init__(self, **kwargs):
        BaseRating.__init__(self, **kwargs)
        self._rules.update({
            "cipher.bits": [
                lambda bits: 1 if bits > 56 else None,
                lambda bits: 3 if bits > 40 else None,
                lambda bits: 5
            ],
            "cipher.method": [
                lambda method: 6 if method == SSL.SSLv2_METHOD else None
            ],
            "cipher.name": [
                lambda name: 5 if "EXP" in name else None,
                lambda name: 3 if "RC" in name else None,
                lambda name: 5 if "ADH" in name else None
            ],
            "server.renegotiation.secure": [
                lambda status: 6 if status == False else None,
                lambda status: 1 if status == True else None
            ]
        })


modules.register(RBSec)
