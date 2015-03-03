import argparse
import logging
import sys
import textwrap


from sslscan import __version__, modules, Scanner
from sslscan.exception import ConfigOptionNotFound, ModuleNotFound, OptionValueError
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

    module_found = None
    for module in modules:
        if module.name == args.module_name:
            module_found = module

    if module_found is None:
        logger.error(
            "Unable to display help. Module '{0}' not found.".format(
                args.module_name
            )
        )
        return 1

    module = module_found(scanner=scanner)

    heading = "Module: {}".format(args.module_name)
    print("")
    print(heading)
    print("="*len(heading))
    print("")

    text = module.__doc__
    if text is None:
        text = ""

    text = textwrap.dedent(text)
    text = text.lstrip("\n")

    print(textwrap.fill(text, width=80))
    print("")

    for name in module.config.get_option_names():
        option = module.config.get_option(name)

        text = option.help
        if text is None or text.strip() == "":
            text = "No help text available"

        indent_text = "{0} - ".format(
            option.name
        )

        indent_len = len(indent_text)

        print(
            textwrap.fill(
                text,
                initial_indent=indent_text
            )
        )

        print(
            "{}Type: {}".format(
                " "*indent_len,
                option.type
            )
        )

        print(
            "{}Default: {}".format(
                " "*indent_len,
                option.default
            )
        )

        values = option.values
        if values is not None:
            if callable(values):
                values = values(option)
            print(
                textwrap.fill(
                    "Values: {0}".format(
                        ", ".join(values)
                    ),
                    initial_indent=" "*indent_len,
                    subsequent_indent=" "*indent_len
                )
            )

    print("")

    return 0


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

    # Enable groups of methods
    if args.enable_ssl:
        for name in ["ssl2", "ssl3"]:
            scanner.config.set_value(name, True)
    if args.enable_tls:
        for name in ["tls10", "tls11", "tls12"]:
            scanner.config.set_value(name, True)

    args_dict = vars(args)
    opt_names = ["ssl2", "ssl3", "tls10", "tls11", "tls12", "dtls10", "dtls12"]
    for name in list(opt_names):
        opt_names.append("no-%s" % name)

    for name in opt_names:
        if name not in args_dict:
            continue
        if not args_dict.get(name):
            continue
        logger.debug("Set %s = %s", name, str(args_dict.get(name)))
        scanner.config.set_value(name, True)

    if len(args.scan) == 0:
        logger.error("No scan module specified")
        return 1

    enabled_ssl_method_found = False
    for name in ["ssl2", "ssl3", "tls10", "tls11", "tls12"]:
        if scanner.config.get_value(name):
            enabled_ssl_method_found = True
            break

    enabled_dtls_method_found = False
    for name in ["dtls10", "dtls12"]:
        if scanner.config.get_value(name):
            enabled_dtls_method_found = True
            break
    if not enabled_ssl_method_found and not enabled_dtls_method_found:
        logger.error(
            "No SSL/TLS or DTLS method enabled. "
            "Example: Use --tls10 to enable TLS 1.0"
        )
        return 1

    if enabled_ssl_method_found and enabled_dtls_method_found:
        logger.error(
            "SSL/TLS and DTLS are not compatible."
        )
        return 1

    for module in args.scan:
        name, sep, options = module.partition(":")
        try:
            scanner.append_load(name, options, base_class=BaseScan)
        except ModuleNotFound as e:
            logger.error("Scan module '%s' not found", e.name)
            return 1
        except ConfigOptionNotFound as e:
            logger.error(
                "Unrecognised command line option '%s' for scan module '%s'.",
                e.name,
                name
            )
            return 1

    reports = args.report
    if len(reports) == 0:
        default_report = "term:rating=builtin.0_5"
        logger.debug(
            "No report module specified. Using: %s" % default_report
        )
        reports.append(default_report)

    for module in reports:
        name, sep, options = module.partition(":")
        try:
            scanner.append_load(name, options, base_class=BaseReport)
        except ModuleNotFound as e:
            logger.error("Report module '%s' not found", e.name)
            return 1
        except OptionValueError as e:
            logger.error(
                "An error occurred while setting the value of the configuration"
                " option '{1}' to '{2}' for module '{0}'.".format(
                    name,
                    e.option.name,
                    e.value
                )
            )
            return 1
        except ConfigOptionNotFound as e:
            logger.error(
                "Unrecognised command line option '%s' for report module '%s'.",
                e.name,
                name
            )
            return 1

    for host_uri in args.host_uris:
        module = scanner.load_handler_from_uri(host_uri)
        scanner.set_handler(module)
        scanner.reset_knowledge_base()
        scanner.run()

    return 0


def run():
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)-8s %(name)s %(message)s",
        level=logging.ERROR,
    )

    parser = argparse.ArgumentParser(
        description=textwrap.dedent(
            """
            Command-line interface to access the pySSLScan framework.
            """
        ),
        epilog=textwrap.dedent(
            """
            Examples:

                Display this help:

                    %(prog)s -h

                Use the scan.list command to list all available scan modules:

                    %(prog)s scan.list

                Display additional information for the scan.list command:

                    %(prog)s scan.list -h

                Perform a scan:

                    %(prog)s scan --scan=server.ciphers --report=term --tls10 127.0.0.1

                To get more scan examples run:

                    %(prog)s scan -h
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
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
        help="Scan the given hosts and services",
        epilog=textwrap.dedent(
            """
            Examples:

                Perform a scan:

                 * activate scan module to detect server ciphers
                 * activate report module to print results to STDOUT
                 * use TLSv1.0 method
                 * use TCP protocol handler

                    %(prog)s --scan=server.ciphers --report=term --tls10 127.0.0.1
                    %(prog)s --scan=server.ciphers --report=term --tls10 tcp://127.0.0.1

                Perform a scan:

                  * activate scan module to detect server ciphers
                  * activate report module to print results to STDOUT
                  * use TLSv1.0 method
                  * use HTTP protocol handler

                    %(prog)s --scan=server.ciphers --report=term --tls10 http://127.0.0.1

                Perform a scan:

                  * activate scan module to detect server ciphers
                  * activate report module to print results to STDOUT
                  * use TLSv1.0 method
                  * use SMTP protocol handler

                    %(prog)s --scan=server.ciphers --report=term --tls10 'smtp://127.0.0.1?starttls=true'
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser_scan.set_defaults(func=run_scan)

    # Workaround to fix formating
    tmp_description = textwrap.dedent("""
        Load and add new modules to the processing queue.
    """)

    group_module = parser_scan.add_argument_group(
        title="Modules",
        description=tmp_description
    )
    group_module.add_argument(
        "--report",
        action="append",
        default=[],
        help="Load and add a report module",
    )
    group_module.add_argument(
        "--scan",
        action="append",
        default=[],
        help="Load and add a scan module",
    )
    parser_scan.add_argument(
        "host_uris",
        metavar="HOSTURI",
        nargs="+",
        help="Hosts to scan",
    )

    # Workaround to fix formating
    tmp_description = textwrap.dedent("""
        The options are evaluated in the following order.
        1. Group options (e.g. --ssl)
        2. Enable options (e.g. --tls10)
        3. Disable options (e.g. --no-tls10)
        """)
    group_method = parser_scan.add_argument_group(
        title="Enable/Disable methods",
        description=tmp_description
    )
    group_method.add_argument(
        "--ssl",
        action="store_true",
        default=False,
        dest="enable_ssl",
        help="Enable SSLv2 and SSLv3 methods"
    )

    group_method.add_argument(
        "--tls",
        action="store_true",
        default=False,
        dest="enable_tls",
        help="Enable all TLS 1.x methods"
    )

    opt_names = [
        ("ssl2", "SSLv2"),
        ("ssl3", "SSLv3"),
        ("tls10", "TLS1.0"),
        ("tls11", "TLS1.1"),
        ("tls12", "TLS1.2"),
        ("dtls10", "DTLS1.0"),
        ("dtls12", "DTLS1.2")
    ]
    for name, label in opt_names:
        group_method.add_argument(
            "--%s" % name,
            action="store_true",
            default=False,
            dest=name,
            help="Enable %s" % label
        )
        group_method.add_argument(
            "--no-%s" % name,
            action="store_true",
            default=False,
            dest="no-%s" % name,
            help="Disable %s" % label
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
    if func is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(func(args))
