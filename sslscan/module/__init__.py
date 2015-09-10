from sslscan.config import ModuleConfig

STATUS_OK = 1
STATUS_WARNING = 2
STATUS_ERROR = 3

class BaseModule(object):
    """
    Base class used by all modules.

    It provides the basic functionality.
    """

    alias = None
    status = STATUS_OK
    status_messages = None
    config_options = []

    def __init__(self, scanner=None, config=None):
        self._scanner = scanner
        self.config = ModuleConfig(
            module=self,
            options=self.config_options
        )

    def get_scanner(self):
        """
        Get the current scanner instance.
        """

        return self._scanner

    def set_scanner(self, scanner):
        """
        Set the scanner instance the module was appended to.
        """

        self._scanner = scanner
