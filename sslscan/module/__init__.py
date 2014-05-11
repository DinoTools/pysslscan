from sslscan.config import ModuleConfig


class BaseModule(object):
    config_options = []
    def __init__(self, scanner=None, config=None):
        self.scanner = scanner
        self.config = ModuleConfig(options=self.config_options)

    def get_scanner(self):
        return self.scanner

    def set_scanner(self, scanner):
        self.scanner = scanner
