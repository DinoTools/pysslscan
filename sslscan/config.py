class BaseConfig(object):
    def __init__(self, options=None):
        self._option_map = {}
        self._options = []
        self._option_groups = []

        if options is not None:
            for name, args in options:
                if name is None:
                    group = OptionGroup(options=args)
                    self.add_option_group(group)
                else:
                    self.add_option(name, **args)

    def add_option(self, name, **kwargs):
        if name in self._option_map:
            return False
        option = Option(name, **kwargs)
        self._option_map[name] = option
        if option.type == "bool" and option.negation is not None:
            self._option_map[option.negation] = name
        self._options.append(option)

    def add_option_group(self, group):
        option_map = group.get_option_map()
        for name in option_map.keys():
            if name in self._option_map:
                return False
        self._option_map.update(option_map)
        self._option_groups.append(group)

    def get_option(self, name):
        return self._option_map.get(name, None)

    def get_option_map(self):
        return self._option_map

    def get_value(self, name, default=None):
        option = self.get_option(name)
        if option is None:
            return None
        return option.get_value(default=default)

    def set_value(self, name, value):
        print(name)
        option = self._option_map.get(name, None)
        if option is None:
            return False

        negate = False
        if type(option) == str:
            option = self._mapped_global_options.get(name, None)
            negate = True

        if option is None:
            return False

        value = option.convert_value_type(value)
        if option.type == "bool" and negate is True:
            value = not value

        return option.set_value(value)

    def set_values(self, data):
        if isinstance(data, str):
            # ToDo: support escape characters
            data_parts = data.split(":")
            for option_data in data_parts:
                name, sep, value = option_data.partition("=")
                if name is None or name == "":
                    return False

                negation = False
                option = self._option_map.get(name, None)
                if type(option) is str:
                    negation = True
                    option = self._option_map.get(option, None)

                if option is None:
                    return False

                if option.type == "bool" and sep == "":
                    value = not negation

                option.set_value(value)

        elif isinstance(data, dict):
            for name, value in data.items():
                self.set_value(name, value)


class ModuleConfig(BaseConfig):
    def __init__(self, **kwargs):
        BaseConfig.__init__(self, **kwargs)


class ScanConfig(BaseConfig):
    def __init__(self, **kwargs):
        BaseConfig.__init__(self, **kwargs)


class Option(object):
    def __init__(self, name, action="store", default=None, help="", metavar="", type="string", values=None, negation=None):
        self.name = name
        self.action = action
        self.default = default
        self.help = help
        self.metavar = metavar
        self.negation = negation
        self.value = None
        if type == "choice" and values is None:
            values = {}
        self.values = values
        self.type = type

    def convert_value_type(self, value):
        if self.type == "bool":
            if type(value) == int:
                return bool(value)
            if type(value) != str:
                value = str(value)
            value = value.strip().lower()
            return value in ["1", "true", "yes", ""]

        if self.type == "int":
            return int(value)

        if self.type == "float":
            return float(value)

        return value

    def get_value(self, default=None):
        if self.value is not None:
            return self.value
        if default is not None:
            return default
        return self.default

    def set_value(self, value):
        value = self.convert_value_type(value)

        if self.type == "choice":
            if value not in self.values:
                return False
            self.value = value
            return True

        if self.action == "store":
            self.value = value
            return True

        if self.action == "append":
            if type(self.value) is not list:
                self.value = []
            self.value.append(value)
            return True

        return False


class OptionGroup(BaseConfig):
    def __init__(self, label, help=None):
        BaseConfig.__init__(self)
        self.label = label
        self.help = help
