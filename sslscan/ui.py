import argparse
import logging
import sys


from sslscan import __version__, modules, Scanner
from sslscan.exception import ModuleNotFound
from sslscan.module.report import BaseReport
from sslscan.module.scan import BaseScan


logger = logging.getLogger("ui")


def run():
    global modules
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)-8s %(name)s %(message)s",
        level=logging.ERROR,
    )
    parser = argparse.ArgumentParser(description="SSLScan")
    parser.add_argument("--verbose", "-v", action="count", default=0)
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s " + __version__
    )
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
    log_level = 40 - 10 * args.verbose
    if log_level < 10:
        log_level = 10
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

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
        try:
            scanner.append_load(name, options, base_class=BaseScan)
        except ModuleNotFound as e:
            print("Scan module '{0}' not found".format(e.name))
            sys.exit(1)

    for module in args.report:
        name, sep, options = module.partition(":")
        try:
            scanner.append_load(name, options, base_class=BaseReport)
        except ModuleNotFound as e:
            print("Report module '{0}' not found".format(e.name))
            sys.exit(1)

    for host_uri in args.host_uris:
        module = scanner.load_handler_from_uri(host_uri)
        scanner.set_handler(module)
        scanner.run()
