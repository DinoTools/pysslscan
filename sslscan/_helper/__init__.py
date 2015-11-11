import sys

try:
    from colorama import Fore
    from colorama import init as colorama_init
except ImportError:
    colorama_init = None

def rating2color(color, level):
    # ToDo:
    if level == None:
        return color.RESET
    if level < 3:
        return color.OK
    if level < 5:
        return color.WARNING
    if level < 7:
        return color.DANGER
    return color.RESET


class Console(object):
    def __init__(self):
        self.icon = ConsoleIcons(self)
        self.color = ColorConsole()

    @property
    def is_terminal(self):
        return sys.stdout.encoding is not None

    @property
    def encoding(self):
        if sys.stdout.encoding is None:
            return ""
        else:
            return sys.stdout.encoding.lower()


class ConsoleIcons(object):
    def __init__(self, console):
        """

        :param Console console:
        """
        self._console = console

        self._mapped_characters = {
            "default": {
                "ERROR": "E",
                "OK": "O",
                "WARNING": "W"
            },
            "utf8": {
                "ERROR": "\u2715",
                "OK": "\u2713",
                "WARNING": "\u26A0"
            }
        }

    @property
    def scheme(self):
        # ToDo: get scheme from config
        if self._console.is_terminal and self._console.encoding == "utf-8":
            return "utf8"
        return "default"

    def __getattr__(self, name):
        characters = self._mapped_characters.get(self.scheme)
        if characters is None:
            characters = self._mapped_characters["default"]

        icon = characters.get(name)
        if icon is None:
            icon = self._mapped_characters["default"].get(name)
        if icon is None:
            raise KeyError("Icon not found")

        return icon


class ColorConsole(object):
    def __init__(self):
        if colorama_init:
            colorama_init(autoreset=False)
            self.colors = {
                "RESET": Fore.RESET,
                "BLACK": Fore.BLACK,
                "RED": Fore.RED,
                "GREEN": Fore.GREEN,
                "YELLOW": Fore.YELLOW,
                "BLUE": Fore.BLUE,
                "MAGENTA": Fore.MAGENTA,
                "CYAN": Fore.CYAN
                #"GRAY": Fore.GRAY
            }
        else:
            CSI = "\33["
            self.CSI = CSI
            self.colors = {
                "RESET": CSI + "0m",
                "BLACK": CSI + "0;30m",
                "RED": CSI + "0;31m",
                "GREEN": CSI + "0;32m",
                "YELLOW": CSI + "0;33m",
                "BLUE": CSI + "0;34m",
                "MAGENTA": CSI + "0;35m",
                "CYAN": CSI + "0;36m"
                #"GRAY": CSI + "0;37m"
            }

        self.mapped_colors = {}
        self.mapped_colors["default"] = {
            "DANGER": "RED",
            "ERROR": "RED",
            "OK": "GREEN",
            "SUCCESS": "GREEN",
            "WARNING": "YELLOW"
        }

    def __getattr__(self, name):
        #scheme = self.config.get_value("color")
        #if scheme == "none":
        #    return ""
        scheme = 'default'
        mapped_colors = self.mapped_colors.get(
            scheme,
            self.mapped_colors.get("default", {})
        )
        map_name = mapped_colors.get(name, "")
        if map_name != "":
            name = map_name
        code = self.colors.get(name, "")
        return code
