class ModuleNotFound(Exception):
    def __init__(self, name="", base_class=None):
        self.name = name
        self.base_class = base_class

    def __str__(self):
        return "Module '{}' not found".format(self.name)


class ModuleLoadStatus(Exception):
    def __init__(self, name="", base_class=None, module=None):
        self.name = name
        self.base_class = base_class
        self.module = module

    def __str__(self):
        status = "Unknown"
        if self.module:
            from sslscan.module import STATUS_NAMES
            status = STATUS_NAMES.get(self.module.status, status)
        return "Unable to load module '{}' with status '{}'".format(self.name, status)


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