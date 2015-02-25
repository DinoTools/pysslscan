class ModuleNotFound(Exception):
    def __init__(self, name="", base_class=None):
        self.name = name
        self.base_class = base_class

    def __str__(self):
        return "Module '{}' not found".format(self.name)


class BaseConfigError(Exception):
    pass


class ConfigOptionNotFound(BaseConfigError):
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __str__(self):
        s = "Option with name '{0}' does not exist.".format(
            self.name
        )
        return s


class OptionValueError(BaseConfigError):
    def __init__(self, option, value):
        self.option = option
        self.value = value

    def __str__(self):
        s = "Unable to set value '{2}' for option '{0}' of type '{1}'".format(
            self.option.name,
            self.option.type,
            self.value
        )
        return s


class Timeout(Exception):
    pass


class StartTLSError(Exception):
    def __init__(self, *args):
        Exception.__init__(self, "There was an error during the STARTTLS command", *args)