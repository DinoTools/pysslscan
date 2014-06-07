import argparse
import logging
import sys
import textwrap


from sslscan import __version__, modules, Scanner
from sslscan.exception import ModuleNotFound
from sslscan.module.handler import BaseHandler
from sslscan.module.report import BaseReport
from sslscan.module.rating import BaseRating
from sslscan.module.scan import BaseScan


logger = logging.getLogger(__name__)

def load_modules():
    global modules
    modules.load_global_modules()

def print_module_info(args):
    load_modules()
    scanner = Scanner()

    mod_mgr = scanner.get_module_manager()
    modules = mod_mgr.get_modules(base_class=args.base_class)
    heading = "Module: {}".format(args.module_name)
    print()
    print("="*len(heading))
    print(heading)
    print("="*len(heading))
    print()
    for module in modules:
        if module.name != args.module_name:
            continue

        text = module.__doc__
        if text is None:
            text = ""

        text = textwrap.dedent(text)
        formatter = argparse.RawTextHelpFormatter("", width=80)
        formatter.add_text(text)

        print(formatter.format_help())

        return 0

    return 1

def print_module_list(args):
    load_modules()
    scanner = Scanner()

    mod_mgr = scanner.get_module_manager()
    modules = mod_mgr.get_modules(base_class=args.base_class)
    for module in modules:
        name = module.name
        text = module.__doc__
        if text is None:
            text = ""

        text = text.splitlines()
        while len(text) > 0:
            if len(text[0].strip()) > 0:
                break
            text.pop(0)

        if len(text) == 0:
            text = ""
        else:
            text = text[0]

        text = textwrap.dedent(text)
        print("{0} - {1}".format(name, text))

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

    # CMD: handler.info
    parser_handler_info = subparsers.add_parser(
        "handler.info",
        help="Display more information for a specified protocol handler module",
    )
    parser_handler_info.set_defaults(
        base_class=BaseHandler,
        func=print_module_info,
    )

    parser_handler_info.add_argument(
        "module_name",
        action="store",
        default=None,
        metavar="MODULE",
        help="Name of the module",
    )

    # CMD: handler.list
    parser_handler_list = subparsers.add_parser(
        "handler.list",
        help="Display a list of all available protocol handler modules",
    )
    parser_handler_list.set_defaults(
        base_class=BaseHandler,
        func=print_module_list,
    )

    # CMD: rating.info
    parser_rating_info = subparsers.add_parser(
        "rating.info",
        help="Display more information for a specified rating module",
    )
    parser_rating_info.set_defaults(
        base_class=BaseRating,
        func=print_module_info,
    )

    parser_rating_info.add_argument(
        "module_name",
        action="store",
        default=None,
        metavar="MODULE",
        help="Name of the module",
    )

    # CMD: rating.list
    parser_rating_list = subparsers.add_parser(
        "rating.list",
        help="Display a list of all available rating modules",
    )
    parser_rating_list.set_defaults(
        base_class=BaseRating,
        func=print_module_list,
    )

    # CMD: report.info
    parser_report_info = subparsers.add_parser(
        "report.info",
        help="Display more information",
    )
    parser_report_info.set_defaults(
        base_class=BaseReport,
        func=print_module_info,
    )

    parser_report_info.add_argument(
        "module_name",
        action="store",
        default=None,
        metavar="MODULE",
        help="Name of the module",
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

    # CMD: scan.info
    parser_scan_info = subparsers.add_parser(
        "scan.info",
        help="Display more information",
    )
    parser_scan_info.set_defaults(
        base_class=BaseScan,
        func=print_module_info,
    )

    parser_scan_info.add_argument(
        "module_name",
        action="store",
        default=None,
        metavar="MODULE",
        help="Name of the module",
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
