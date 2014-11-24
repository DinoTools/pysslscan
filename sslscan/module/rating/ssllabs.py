from datetime import datetime
from socket import socket

from flextls import registry as reg

from sslscan import modules
from sslscan.module.rating import BaseRating, RatingRule


class SSLLabs2009c(BaseRating):
    """
    Rating used by SSL Labs 2009c

    https://www.ssllabs.com/
    """

    name="ssllabs.2009c"

    def __init__(self, **kwargs):
        BaseRating.__init__(self, **kwargs)
        self.add_rule(
            RatingRule(
                "cipher.bits",
                rules=[
                    lambda bits: 6 if bits == 0 else None,
                    lambda bits: 5 if bits < 128 else None,
                    lambda bits: 2 if bits < 256 else None,
                    lambda bits: 1 if bits >= 256 else None
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "cipher.bits",
                rules=[
                    lambda bits: 6 if bits == 0 else None,
                    lambda bits: 5 if bits < 128 else None,
                    lambda bits: 2 if bits < 256 else None,
                    lambda bits: 1 if bits >= 256 else None
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "cipher.protocol_version",
                rules=[
                    lambda method: 6 if method == reg.version.SSLv2 else None,
                    lambda method: 1 if method == reg.version.TLSv12 else None,
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "server.renegotiation.secure",
                rules=[
                    lambda status: 6 if status == False else None,
                    lambda status: 1 if status == True else None
                ]
            )
        )


class SSLLabs2009d(BaseRating):
    """
    Rating used by SSL Labs 2009d

    https://www.ssllabs.com/
    """

    name="ssllabs.2009d"

    def __init__(self, **kwargs):
        BaseRating.__init__(self, **kwargs)
        self.add_rule(
            RatingRule(
                "cipher.bits",
                rules=[
                    lambda bits: 6 if bits == 0 else None,
                    lambda bits: 5 if bits < 128 else None,
                    lambda bits: 2 if bits < 256 else None,
                    lambda bits: 1 if bits >= 256 else None
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "cipher.protocol_version",
                rules=[
                    lambda method: 6 if method == reg.version.SSLv2 else None,
                    lambda method: 1 if method == reg.version.TLSv12 else None,
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "server.renegotiation.secure",
                rules=[
                    lambda status: 6 if status == False else None,
                    lambda status: 1 if status == True else None
                ]
            )
        )


class SSLLabs2009e(BaseRating):
    """
    Rating used by SSL Labs 2009e

    https://www.ssllabs.com/
    """

    name="ssllabs.2009e"

    def __init__(self, **kwargs):
        BaseRating.__init__(self, **kwargs)
        self.add_rule(
            RatingRule(
                "cipher.bits",
                rules=[
                    lambda bits: 6 if bits == 0 else None,
                    lambda bits: 5 if bits < 128 else None,
                    lambda bits: 3 if bits < 256 else None,
                    lambda bits: 0 if bits >= 256 else None
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "cipher.protocol_version",
                rules=[
                    lambda method: 6 if method == reg.version.SSLv2 else None,
                    lambda method: 1 if method == reg.version.TLSv12 else None,
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "server.certificate.x509.signature_algorithm",
                rules=[
                    lambda algorithm: 6 if algorithm.startswith("md2") else None,
                    lambda algorithm: 6 if algorithm.startswith("md5") else None,
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "server.certificate.x509.not_after",
                rules=[
                    lambda date: 6 if date < datetime.now() else None
                ],
            )
        )

        self.add_rule(
            RatingRule(
                "server.certificate.x509.not_before",
                rules=[
                    lambda date: 6 if date > datetime.now() else None
                ],
            )
        )

        self.add_rule(
            RatingRule(
                "server.renegotiation.secure",
                rules=[
                    lambda status: 6 if status == False else None,
                    lambda status: 1 if status == True else None
                ]
            )
        )


modules.register(SSLLabs2009c)
modules.register(SSLLabs2009d)
modules.register(SSLLabs2009e)
