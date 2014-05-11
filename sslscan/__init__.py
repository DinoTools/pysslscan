import argparse
import importlib
import os
import re

from urllib.parse import urlparse, parse_qs


from OpenSSL import SSL


from sslscan.config import ScanConfig
from sslscan.kb import KnowledgeBase
from sslscan.module.handler import BaseHandler
from sslscan.module.rating import BaseRating, NoneRating
from sslscan.module.report import BaseReport
from sslscan.module.scan import BaseScan


class Scanner(object):
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
        module.set_scanner(self)
        self._modules.append(module)

    def append_load(self, name, config, base_class=None):
        module = self._module_manager.get(name, base_class=base_class)
        if module is None:
            return False
        module = module()
        module.config.set_values(config)
        self.append(module)

    def get_enabled_methods(self):
        methods = []
        if self.config.get_value('ssl2'):
            methods.append(SSL.SSLv2_METHOD)
        if self.config.get_value('ssl3'):
            methods.append(SSL.SSLv3_METHOD)
        print(self.config.get_value('tls10'))
        if self.config.get_value('tls10'):
            methods.append(SSL.TLSv1_METHOD)
        if self.config.get_value('tls11'):
            methods.append(SSL.TLSv1_1_METHOD)
        if self.config.get_value('tls12'):
            methods.append(SSL.TLSv1_2_METHOD)
        return methods

    def get_knowledge_base(self):
        return self._kb

    def load_handler_from_uri(self, host_uri):
        if not re.search('^([a-z]+:)?\/\/', host_uri):
            host_uri = '//' + host_uri
        uri = urlparse(host_uri)
        name = uri.scheme
        if name == '':
            name = 'tcp'
        module = self._module_manager.get(name, base_class=BaseHandler)
        if module is None:
            return False
        module = module(host=uri.hostname, port=uri.port)
        tmp = parse_qs(uri.query, keep_blank_values=True)
        config = {}
        for k, v in tmp.items():
            config[k] = v[0]
        print(config)
        module.config.set_values(config)
        return module

    def load_rating(self, name):
        module = self._module_manager.get(name, base_class=BaseRating)
        if module is None:
            return NoneRating()
        return module()

    def run(self):
        result = []
        # Run scans
        for module in self._modules:
            if not isinstance(module, BaseScan):
                continue
            print(module)
            result.append(module.run())

        # Generate reports
        for module in self._modules:
            if not isinstance(module, BaseReport):
                continue
            print(module)
            module.run()

    def set_handler(self, handler):
        self.handler = handler


class ModuleManager(object):
    def __init__(self):
        self._modules = []

    def get(self, name, base_class=None):
        for module in self._modules:
            if base_class is not None and not issubclass(module, base_class):
                continue
            if module.name == name:
                return module

        return None

    def register(self, module):
        if module in self._modules:
            # ToDo: error handling
            return
        self._modules.append(module)

    def load_modules(self, pkg_names):
        for base_pkg_name in pkg_names:
            print(base_pkg_name)
            base_pkg = importlib.import_module(base_pkg_name)
            print(base_pkg)

            path = base_pkg.__path__[0]
            print(path)
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
                    print("Loaded '{}' successfully".format(mod_name))
                except Exception as msg:
                    print(str(msg))

    def load_global_modules(self):
        pkg_names = [
            "sslscan.module.handler",
            "sslscan.module.rating",
            "sslscan.module.report",
            "sslscan.module.scan"
        ]
        return self.load_modules(pkg_names)


def run():
    global modules
    parser = argparse.ArgumentParser(description="SSLScan")
    parser.add_argument("--verbose", "-v", action="count")
    parser.add_argument("--report", action="append", default=[])
    parser.add_argument("--scan", action="append", default=[])
    parser.add_argument("host_uris",
                        metavar="HOSTURI",
                        nargs="+",
                        help="Hosts to scan"
                        )

    for name, opt_args in Scanner.config_options:
        # ToDo: works only with bool
        parser.add_argument(
            "--%s" % name,
            action='store_true',
            default=opt_args.get('default'),
            dest=name
        )

    args = parser.parse_args()
    modules.load_global_modules()
    scanner = Scanner()
    print(args)
    args_dict = vars(args)
    print(args)
    for name, opt_args in Scanner.config_options:
        if name in args_dict:
            print("set %s %s" % (name, str(args_dict.get(name))))
            scanner.config.set_value(name, args_dict.get(name))

    for module in args.scan:
        name, sep, options = module.partition(":")
        scanner.append_load(name, options, base_class=BaseScan)

    for module in args.report:
        name, sep, options = module.partition(":")
        scanner.append_load(name, options, base_class=BaseReport)

    for host_uri in args.host_uris:
        module = scanner.load_handler_from_uri(host_uri)
        scanner.set_handler(module)
        scanner.run()


modules = ModuleManager()
