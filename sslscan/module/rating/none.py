from sslscan import modules
from sslscan.module.rating import BaseRating


class NoneRating(BaseRating):
    """
    Dummy rating.
    """
    name = "none"


modules.register(NoneRating)