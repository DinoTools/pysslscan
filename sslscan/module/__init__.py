from sslscan.config import ModuleConfig


class BaseModule(object):
    """
    Base class used by all modules.

    It provides the basic functionality.
    """

    config_options = []
    def __init__(self, scanner=None, config=None):
        self.scanner = scanner
        self.config = ModuleConfig(options=self.config_options)

    def get_scanner(self):
        """
        Get the current scanner instance.
        """

        return self.scanner

    def set_scanner(self, scanner):
        """
        Set the scanner instance the module was appended to.
        """

        self.scanner = scanner
