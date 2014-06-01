import argparse
import logging
import sys


from sslscan import __version__, modules, Scanner
from sslscan.exception import ModuleNotFound
from sslscan.module.report import BaseReport
from sslscan.module.scan import BaseScan


logger = logging.getLogger(__name__)

def load_modules():
    global modules
    modules.load_global_modules()

def print_module_list(args):
    load_modules()
    scanner = Scanner()

    mod_mgr = scanner.get_module_manager()
    modules = mod_mgr.get_modules(base_class=args.base_class)
    for module in modules:
        print("{0} - ".format(module.name))

    return 0

def run_scan(args):
    load_modules()
    scanner = Scanner()

    args_dict = vars(args)
    for name, opt_args in Scanner.config_options:
        if name in args_dict:
            logger.debug("Set %s = %s", name, str(args_dict.get(name)))
            scanner.config.set_value(name, args_dict.get(name))

    for module in args.scan:
        name, sep, options = module.partition(":")
        try:
            scanner.append_load(name, options, base_class=BaseScan)
        except ModuleNotFound as e:
            logger.error("Scan module '%s' not found", e.name)
            return 1

    for module in args.report:
        name, sep, options = module.partition(":")
        try:
            scanner.append_load(name, options, base_class=BaseReport)
        except ModuleNotFound as e:
            logger.error("Report module '%s' not found", e.name)
            return 1

    for host_uri in args.host_uris:
        module = scanner.load_handler_from_uri(host_uri)
        scanner.set_handler(module)
        scanner.run()

    return 0

def run():
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)-8s %(name)s %(message)s",
        level=logging.ERROR,
    )

    parser = argparse.ArgumentParser(
        description="Command-line interface to access the pySSLScan framework",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s " + __version__
    )

    subparsers = parser.add_subparsers(
        description="The command to run",
        metavar="command",
        title="Commands",
    )

    # CMD: report.list
    parser_report_list = subparsers.add_parser(
        "report.list",
        help="Display a list of all available report modules",
    )

    parser_report_list.set_defaults(
        base_class=BaseReport,
        func=print_module_list,
    )

    # CMD: scan
    parser_scan = subparsers.add_parser(
        "scan",
        help="Scan the given hosts and services"
    )
    parser_scan.set_defaults(func=run_scan)
    parser_scan.add_argument(
        "--report",
        action="append",
        default=[],
        help="Add a report module to the processing queue",
    )
    parser_scan.add_argument(
        "--scan",
        action="append",
        default=[],
        help="Add a scan module to the processing queue",
    )
    parser_scan.add_argument(
        "host_uris",
        metavar="HOSTURI",
        nargs="+",
        help="Hosts to scan",
    )

    for name, opt_args in Scanner.config_options:
        # ToDo: works only with bool
        parser_scan.add_argument(
            "--%s" % name,
            action="store_true",
            default=opt_args.get("default"),
            dest=name
        )

    # CMD: scan.list
    parser_scan_list = subparsers.add_parser(
        "scan.list",
        help="Display a list of all available scan modules",
    )
    parser_scan_list.set_defaults(
        base_class=BaseScan,
        func=print_module_list,
    )

    args = parser.parse_args()
    log_level = 40 - 10 * args.verbose
    if log_level < 10:
        log_level = 10
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # no subcommand given, print help and exit
    func = getattr(args, "func", None)
    if func == None:
        parser.print_help()
        sys.exit(1)

    sys.exit(func(args))
