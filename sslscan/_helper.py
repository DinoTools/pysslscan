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


class ColorConsole(object):
    def __init__(self):
        #self.config = config
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
            "CYAN": CSI + "0;36m",
            "GRAY": CSI + "0;37m"
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
