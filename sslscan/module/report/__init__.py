from sslscan.module import BaseModule

class BaseReport(BaseModule):
    config_options = BaseModule.config_options + [
        (
            "rating", {
                "help": "",
            }
        )
    ]
    def __init__(self, **kwargs):
        BaseModule.__init__(self, **kwargs)
