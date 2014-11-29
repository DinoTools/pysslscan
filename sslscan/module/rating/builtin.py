from datetime import datetime

from flextls import registry as reg

from sslscan import modules
from sslscan.module.rating import BaseRating, RatingRule


class BuiltIn_0_5(BaseRating):
    """
    """

    name="builtin.0_5"

    def __init__(self, **kwargs):
        BaseRating.__init__(self, **kwargs)
        self.add_rule(
            RatingRule(
                "cipher.bits",
                rules=[
                    lambda v, kb: 6 if v == 0 else None,
                    lambda v, kb: 5 if v < 128 else None,
                    lambda v, kb: 3 if v < 256 else None,
                    lambda v, kb: 0 if v >= 256 else None
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "cipher.protocol_version",
                result_descriptions={
                    "poodle": "",
                    "sslv2": "SSLv2 is insecure and has been superseeded by SSLv3",
                },
                result_refs={
                    "poodle": ["cve:CVE-2014-3566"],
                },
                rules=[
                    lambda m, kb: (6, "sslv2") if m == reg.version.SSLv2 else None,
                    lambda m, kb: (5, "poodle") if m == reg.version.SSLv3 else None,
                    lambda m, kb: 1 if m == reg.version.TLSv12 else None,
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "server.certificate.x509.signature_algorithm",
                rules=[
                    lambda v, kb: 6 if v.startswith("md2") else None,
                    lambda v, kb: 6 if v.startswith("md5") else None,
                ]
            )
        )

        self.add_rule(
            RatingRule(
                "server.certificate.x509.not_after",
                rules=[
                    lambda v, kb: 6 if v < datetime.now() else None
                ],
            )
        )

        self.add_rule(
            RatingRule(
                "server.certificate.x509.not_before",
                rules=[
                    lambda v, kb: 6 if v > datetime.now() else None
                ],
            )
        )

        self.add_rule(
            RatingRule(
                "server.renegotiation.secure",
                rules=[
                    lambda v, kb: 6 if v == False else None,
                    lambda v, kb: 1 if v == True else None
                ]
            )
        )


modules.register(BuiltIn_0_5)
