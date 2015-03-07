import importlib
import logging
import os
import re

from pprint import pformat

from six.moves.urllib.parse import urlparse, parse_qs

import flextls

from sslscan.__about__ import (
    __author__, __copyright__, __email__, __license__, __summary__, __title__,
    __uri__, __version__
)
from sslscan.config import ScanConfig
from sslscan.exception import ModuleNotFound
from sslscan.kb import KnowledgeBase
from sslscan.module.handler import BaseHandler
from sslscan.module.rating import BaseRating
from sslscan.module.report import BaseReport
from sslscan.module.scan import BaseScan


logger = logging.getLogger(__name__)


class Scanner(object):
    """
    The main scanner object.
    """

    config_options = [
        (
            "ssl2", {
                "default": False,
                "negation": "no-ssl2",
                "help": "",
                "type": "bool"
            }
        ),
        (
            "ssl3", {
                "default": False,
                "negation": "no-ssl3",
                "help": "",
                "type": "bool"
            }
        ),
        (
            "tls10", {
                "default": False,
                "negation": "no-tls10",
                "help": "",
                "type": "bool"
            }
        ),
        (
            "tls11", {
                "default": False,
                "negation": "no-tls11",
                "help": "",
                "type": "bool"
            }
        ),
        (
            "tls12", {
                "default": False,
                "negation": "no-tls12",
                "help": "",
                "type": "bool"
            }
        ),
        (
            "dtls10", {
                "default": False,
                "negation": "no-dtls10",
                "help": "",
                "type": "bool"
            }
        ),
        (
            "dtls12", {
                "default": False,
                "negation": "no-dtls12",
                "help": "",
                "type": "bool"
            }
        )
    ]
    def __init__(self, module_manager=None):
        global modules
        self._module_manager = module_manager
        if self._module_manager is None:
            self._module_manager = modules
        self._modules = []
        self.config = ScanConfig(options=self.config_options)
        self.handler = None
        self._kb = KnowledgeBase()

    def append(self, module):
        """
        Append a scan or report module.

        :param module: Instance of a scan or report module
        """

        module.set_scanner(self)
        self._modules.append(module)

    def append_load(self, name, config, base_class=None):
        """
        Append a module but load it first by using the module manager.

        :param String name: Name of the module to load
        :param Mixed config: Config of the module
        :param class base_class: Module lookup filter
        :return: False if module not found
        """

        module = self._module_manager.get(name, base_class=base_class)
        if module is None:
            raise ModuleNotFound(name=name,base_class=base_class)

        module = module(scanner=self)
        module.config.set_values(config)
        self.append(module)

    def get_enabled_versions(self):
        """
        Uses the scanner config to create and return a list of all enabled
        SSL/TLS protocol versions.

        :return: List of methods
        :rtype: List
        """

        versions = []
        if self.config.get_value('ssl2'):
            versions.append(flextls.registry.version.SSLv2)
        if self.config.get_value('ssl3'):
            versions.append(flextls.registry.version.SSLv3)
        if self.config.get_value('tls10'):
            versions.append(flextls.registry.version.TLSv10)
        if self.config.get_value('tls11'):
            versions.append(flextls.registry.version.TLSv11)
        if self.config.get_value('tls12'):
            versions.append(flextls.registry.version.TLSv12)
        if self.config.get_value('dtls10'):
            versions.append(flextls.registry.version.DTLSv10)
        if self.config.get_value('dtls12'):
            versions.append(flextls.registry.version.DTLSv12)

        return versions

    def get_handler(self):
        """
        Get the active protocol handler.

        :return: Instance of the handler
        :rtype: sslscan.module.handler.BaseHandler
        """

        return self.handler

    def get_knowledge_base(self):
        """Return the knowledge base used by this scanner."""

        return self._kb

    def get_module_manager(self):
        """Return the active module manager for this scanner."""

        return self._module_manager

    def load_handler_from_uri(self, host_uri):
        """
        Load a handler from a given uri.

        :param String host_uri: The URI
        :return: The handler
        """

        logger.debug("Loading handler from URI: %s", host_uri)
        if not re.search('^([a-zA-Z0-9]+:)?\/\/', host_uri):
            host_uri = '//' + host_uri
        uri = urlparse(host_uri)
        name = uri.scheme
        name = name.lower()
        if name == '':
            name = 'tcp'
        module = self._module_manager.get(name, base_class=BaseHandler)
        if module is None:
            return False
        module = module(host=uri.hostname, port=uri.port, scanner=self)
        tmp = parse_qs(uri.query, keep_blank_values=True)
        config = {}
        for k, v in tmp.items():
            config[k] = v[0]

        logger.debug("Extracted config values: %s", pformat(config))
        module.config.set_values(config)
        return module

    def load_rating(self, name):
        """
        Use the active module manager to load a rating module

        :param String name: Name of the rating module
        """

        module = self._module_manager.get(name, base_class=BaseRating)
        if module is None:
            if name == "none":
                raise Exception("Internal error unable to load 'none' rating")
            return self.load_rating("none")
        return module(scanner=self)

    def reset_knowledge_base(self):
        """Create and activate a new knowledge base for this scanner."""

        self._kb = KnowledgeBase()

    def run(self):
        """Execute all scan and report modules attached to the scanner."""
        self.run_scans()
        self.run_reports()

    def run_reports(self):
        """Execute all report modules attached to the scanner."""

        for module in self._modules:
            if not isinstance(module, BaseReport):
                continue

            logger.info("Running report module '%s' ...", str(module))
            module.run()

    def run_scans(self):
        """Execute all scan modules attached to the scanner."""

        for module in self._modules:
            if not isinstance(module, BaseScan):
                continue

            logger.info("Running scan module '%s' ...", str(module))
            module.run()

    def set_handler(self, handler):
        """
        Set the active protocol handler.

        :param handler: Instance of the handler
        """

        self.handler = handler


class ModuleManager(object):
    """
    Manager all modules
    """

    def __init__(self):
        self._modules = []

    def get(self, name, base_class=None):
        """
        Return a module.

        :param String name: Name of the module
        :param class base_class: The filter
        :return: If module exists return it or if not return None
        :rtype: Mixed
        """

        for module in self._modules:
            if base_class is not None and not issubclass(module, base_class):
                continue
            if module.name == name:
                return module

        return None

    def get_modules(self, base_class=None):
        """
        Return a list of available modules. Use the base_class as filter option

        :param class base_class: The filter
        :rtype: List
        """

        result = []
        for module in self._modules:
            if base_class is None or issubclass(module, base_class):
                result.append(module)

        return result

    def register(self, module):
        """
        Register a new module.
        """

        if module in self._modules:
            # ToDo: error handling
            return
        self._modules.append(module)

    def load_modules(self, pkg_names):
        """
        Load all modules provided by a given python package.

        :param List pkg_names: List of String with package names
        """

        logger.info("Loading modules ...")

        for base_pkg_name in pkg_names:
            logger.debug("Base package name: %s", base_pkg_name)
            base_pkg = importlib.import_module(base_pkg_name)

            logger.debug("Base package: %s", base_pkg)

            path = base_pkg.__path__[0]
            logger.debug("Base path: %s", path)

            for filename in os.listdir(path):
                if filename == "__init__.py":
                    continue

                pkg_name = None
                if os.path.isdir(os.path.join(path, filename)) and \
                os.path.exists(os.path.join(path, filename, "__init__.py")):
                    pkg_name = filename

                if filename[-3:] == '.py':
                    pkg_name = filename[:-3]

                if pkg_name is None:
                    continue

                mod_name = "{}.{}".format(base_pkg_name, pkg_name)
                try:
                    importlib.import_module(mod_name)
                    logger.info("Loaded '%s' successfully", mod_name)
                except Exception as msg:
                    logger.warning("Unable to load: '%s'", mod_name)
                    logger.debug("An error occurred while importing '%s'", mod_name, exc_info=True)

    def load_global_modules(self):
        """
        Load all global modules.
        """

        pkg_names = [
            "sslscan.module.handler",
            "sslscan.module.rating",
            "sslscan.module.report",
            "sslscan.module.scan"
        ]
        return self.load_modules(pkg_names)


modules = ModuleManager()
