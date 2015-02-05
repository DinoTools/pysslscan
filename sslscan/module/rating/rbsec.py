from socket import socket

from flextls import registry as reg

from sslscan import modules
from sslscan.module.rating import BaseRating, RatingRule


class RBSec(BaseRating):
    """
    Rating by rbsec.

    Rating used in the sslscan tool by rbsec.

    More infos: https://github.com/rbsec/sslscan
    """

    name="rbsec"

    def __init__(self, **kwargs):
        BaseRating.__init__(self, **kwargs)

        self.add_rule(
            RatingRule(
                "cipher.bits",
                rules=[
                    lambda v, i, kb: 1 if v > 56 else None,
                    lambda v, i, kb: 3 if v > 40 else None,
                    lambda v, i, kb: 5
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "cipher.protocol_version",
                rules=[
                    lambda v, i, kb: 6 if v == reg.version.SSLv2 else None,
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "cipher.name",
                rules=[
                    lambda v, i, kb: 5 if "EXP" in v else None,
                    lambda v, i, kb: 3 if "RC" in v else None,
                    lambda v, i, kb: 5 if "ADH" in v else None
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


modules.register(RBSec)
