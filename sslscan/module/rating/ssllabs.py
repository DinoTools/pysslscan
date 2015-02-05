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
                    lambda v, i, kb: 6 if v == 0 else None,
                    lambda v, i, kb: 5 if v < 128 else None,
                    lambda v, i, kb: 2 if v < 256 else None,
                    lambda v, i, kb: 1 if v >= 256 else None
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "cipher.bits",
                rules=[
                    lambda v, i, kb: 6 if v == 0 else None,
                    lambda v, i, kb: 5 if v < 128 else None,
                    lambda v, i, kb: 2 if v < 256 else None,
                    lambda v, i, kb: 1 if v >= 256 else None
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "cipher.protocol_version",
                rules=[
                    lambda v, i, kb: 6 if v == reg.version.SSLv2 else None,
                    lambda v, i, kb: 1 if v == reg.version.TLSv12 else None,
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "server.renegotiation.secure",
                rules=[
                    lambda v, i, kb: 6 if v == False else None,
                    lambda v, i, kb: 1 if v == True else None
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
                    lambda v, i, kb: 6 if v == 0 else None,
                    lambda v, i, kb: 5 if v < 128 else None,
                    lambda v, i, kb: 2 if v < 256 else None,
                    lambda v, i, kb: 1 if v >= 256 else None
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "cipher.protocol_version",
                rules=[
                    lambda v, i, kb: 6 if v == reg.version.SSLv2 else None,
                    lambda v, i, kb: 1 if v == reg.version.TLSv12 else None,
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "server.renegotiation.secure",
                rules=[
                    lambda v, i, kb: 6 if v == False else None,
                    lambda v, i, kb: 1 if v == True else None
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
                    lambda v, i, kb: 6 if v == 0 else None,
                    lambda v, i, kb: 5 if v < 128 else None,
                    lambda v, i, kb: 3 if v < 256 else None,
                    lambda v, i, kb: 0 if v >= 256 else None
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "cipher.protocol_version",
                rules=[
                    lambda v, i, kb: 6 if v == reg.version.SSLv2 else None,
                    lambda v, i, kb: 1 if v == reg.version.TLSv12 else None,
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "server.certificate.x509.signature_algorithm",
                rules=[
                    lambda v, i, kb: 6 if v.startswith("md2") else None,
                    lambda v, i, kb: 6 if v.startswith("md5") else None,
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "server.certificate.x509.not_after",
                rules=[
                    lambda v, i, kb: 6 if v < datetime.now() else None
                ],
            )
        )

        self.add_rule(
            RatingRule(
                "server.certificate.x509.not_before",
                rules=[
                    lambda v, i, kb: 6 if v > datetime.now() else None
                ],
            )
        )

        self.add_rule(
            RatingRule(
                "server.renegotiation.secure",
                rules=[
                    lambda v, i, kb: 6 if v == False else None,
                    lambda v, i, kb: 1 if v == True else None
                ]
            )
        )


modules.register(SSLLabs2009c)
modules.register(SSLLabs2009d)
modules.register(SSLLabs2009e)
