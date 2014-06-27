class ModuleNotFound(Exception):
    def __init__(self, name="", base_class=None):
        self.name = name
        self.base_class = base_class

    def __str__(self):
        return "Module '{}' not found".format(self.name)


class BaseConfigError(Exception):
    pass


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
