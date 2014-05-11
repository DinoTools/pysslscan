from socket import socket

from OpenSSL import SSL

from sslscan import modules
from sslscan.module.rating import BaseRating


class RBSec(BaseRating):
    name="rbsec"

    _rules = {
        "cipher.bits": [
            lambda cipher: 1 if cipher.bits > 56 else None,
            lambda cipher: 3 if cipher.bits > 40 else None,
            lambda cipher: 5
        ],
        "cipher.method": [
            lambda cipher: 6 if cipher.method == SSL.SSLv2_METHOD else None
        ],
        "cipher.name": [
            lambda cipher: 5 if "EXP" in cipher.name else None,
            lambda cipher: 3 if "RC" in cipher.name else None,
            lambda cipher: 5 if "ADH" in cipher.name else None
        ],
        "renegotiation.secure": [
            lambda status: 6 if status == False else None,
            lambda status: 1 if status == True else None
        ]
    }


modules.register(RBSec)
