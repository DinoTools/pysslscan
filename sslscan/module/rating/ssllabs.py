from socket import socket

from OpenSSL import SSL

from sslscan import modules
from sslscan.module.rating import BaseRating


class SSLLabs2009c(BaseRating):
    name="ssllabs.2009c"

    _rules = {
        "cipher.bits": [
            lambda cipher: 6 if cipher.bits == 0 else None,
            lambda cipher: 5 if cipher.bits < 128 else None,
            lambda cipher: 2 if cipher.bits < 256 else None,
            lambda cipher: 1 if cipher.bits >= 256 else None
        ],
        "cipher.method": [
            lambda cipher: 6 if cipher.method == SSL.SSLv2_METHOD else None,
            lambda cipher: 1 if cipher.method == SSL.TLSv1_2_METHOD else None
        ],
        "renegotiation.secure": [
            lambda status: 6 if status == False else None,
            lambda status: 1 if status == True else None
        ]
    }


class SSLLabs2009d(BaseRating):
    name="ssllabs.2009d"

    _rules = {
        "cipher.bits": [
            lambda cipher: 6 if cipher.bits == 0 else None,
            lambda cipher: 5 if cipher.bits < 128 else None,
            lambda cipher: 2 if cipher.bits < 256 else None,
            lambda cipher: 1 if cipher.bits >= 256 else None
        ],
        "cipher.method": [
            lambda cipher: 6 if cipher.method == SSL.SSLv2_METHOD else None,
            lambda cipher: 1 if cipher.method == SSL.TLSv1_2_METHOD else None
        ],
        "renegotiation.secure": [
            lambda status: 6 if status == False else None,
            lambda status: 1 if status == True else None
        ]
    }


class SSLLabs2009e(BaseRating):
    name="ssllabs.2009e"

    _rules = {
        "cipher.bits": [
            lambda cipher: 6 if cipher.bits == 0 else None,
            lambda cipher: 5 if cipher.bits < 128 else None,
            lambda cipher: 3 if cipher.bits < 256 else None,
            lambda cipher: 0 if cipher.bits >= 256 else None
        ],
        "cipher.method": [
            lambda cipher: 6 if cipher.method == SSL.SSLv2_METHOD else None,
            lambda cipher: 1 if cipher.method == SSL.TLSv1_2_METHOD else None
        ],
        "renegotiation.secure": [
            lambda status: 6 if status == False else None,
            lambda status: 1 if status == True else None
        ]

    }


modules.register(SSLLabs2009c)
modules.register(SSLLabs2009d)
modules.register(SSLLabs2009e)
