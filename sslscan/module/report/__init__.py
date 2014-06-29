from sslscan.module import BaseModule
from sslscan.module.rating import BaseRating


def get_rating_option_values(option):
    config = option.get_parent()
    module = config._module
    scanner = module.get_scanner()

    mod_mgr = scanner.get_module_manager()

    modules = mod_mgr.get_modules(base_class=BaseRating)

    values = []
    for module in modules:
        values.append(module.name)

    return values


class BaseReport(BaseModule):
    config_options = BaseModule.config_options + [
        (
            "rating", {
                "help": "The rating module to use to highlight the results",
                "type": "choice",
                "values": get_rating_option_values
            }
        )
    ]

    def __init__(self, **kwargs):
        BaseModule.__init__(self, **kwargs)
