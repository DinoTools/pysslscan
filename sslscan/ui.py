import argparse


from sslscan import modules, Scanner
from sslscan.module.report import BaseReport
from sslscan.module.scan import BaseScan

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
