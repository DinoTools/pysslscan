"""
A collection of classes to handle the configuration of a scanner or a module.
"""

import logging

from sslscan.exception import ConfigOptionNotFound, OptionValueError


logger = logging.getLogger(__name__)


class BaseConfig(object):
    """
    The base config. All other configuration classes use it as base class.
    """

    def __init__(self, options=None, parent=None):
        self._option_map = {}
        self._options = []
        self._option_groups = []
        self._parent = parent

        if options is not None:
            for name, args in options:
                if name is None:
                    group = OptionGroup(options=args)
                    self.add_option_group(group)
                else:
                    self.add_option(name, **args)

    def add_option(self, name, **kwargs):
        """
        Add an option.

        :param String name: Name of the config option
        :param kwargs: Additional params are used for a new :class:`sslscan.config.Option` instance
        """

        if name in self._option_map:
            return False

        kwargs["parent"] = self
        option = Option(name, **kwargs)
        self._option_map[name] = option
        if option.type == "bool" and option.negation is not None:
            self._option_map[option.negation] = name
        self._options.append(option)

    def add_option_group(self, group):
        """
        Add grouped options.

        :param group: Instance of :class:`sslscan.config.OptionGroup`
        :type group: :class:`sslscan.config.OptionGroup`
        """

        option_map = group.get_option_map()
        for name in option_map.keys():
            if name in self._option_map:
                return False
        self._option_map.update(option_map)
        group.set_parent(self)
        self._option_groups.append(group)

    def get_option(self, name):
        """
        Return an option.

        :param String name: The name of the option
        :return: The option or None if not found
        """

        return self._option_map.get(name, None)

    def get_option_map(self):
        """Return the option map"""

        return self._option_map

    def get_option_names(self):
        """Return list of option names"""

        names = [option.name for option in self._options]

        return names

    def get_parent(self):
        """
        Return the parent config object or None if no parent is set.

        :return: Object or None
        """

        return self._parent

    def get_value(self, name, default=None):
        """
        Get the value of an option.

        :param String name: Name of the option
        :param Mixed default: Default value
        :return: If found the value of the option or the default value
        """

        option = self.get_option(name)
        if option is None:
            return None
        return option.get_value(default=default)

    def set_parent(self, parent):
        """
        Set the current parent config object.

        :param Object|None parent: Set or reset parent config object
        """

        self._parent = parent

    def set_value(self, name, value):
        """
        Set the value of an option.

        :param String name: Name of the option
        :param Mixed value: The value of the option to set
        :return: False or True
        :rtype: Boolean
        """

        logger.debug("Set value '%s' to '%r'", name, value)
        option = self._option_map.get(name, None)
        if option is None:
            raise ConfigOptionNotFound(
                name=name,
                value=value,
            )

        negate = False
        if type(option) == str:
            option = self._option_map.get(option, None)
            negate = True

        if option is None:
            raise ConfigOptionNotFound(
                name=name,
                value=value,
            )

        value = option.convert_value_type(value)
        if option.type == "bool" and negate is True:
            value = not value

        return option.set_value(value)

    def set_values(self, data):
        """
        Set the value of multiple options at once.

        :param date: The values to set

        :todo: Improve docs
        """

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
                    raise ConfigOptionNotFound(
                        name=name,
                        value=value,
                    )

                if option.type == "bool" and sep == "":
                    value = not negation

                option.set_value(value)

        elif isinstance(data, dict):
            for name, value in data.items():
                self.set_value(name, value)


class ModuleConfig(BaseConfig):
    """
    Holds the config of a module

    :param module: The module this config is for
    """

    def __init__(self, module=None, **kwargs):
        self._module = module
        BaseConfig.__init__(self, **kwargs)

    def get_module(self):
        return self._module


class ScanConfig(BaseConfig):
    """Holds the config of a scanner instance"""

    def __init__(self, **kwargs):
        BaseConfig.__init__(self, **kwargs)


class Option(object):
    """

    """

    def __init__(self, name, action="store", default=None, help="", metavar="",
                 type="string", values=None, negation=None, parent=None):
        self.name = name
        self.action = action
        self.default = default
        self.help = help
        self.metavar = metavar
        self.negation = negation
        self._parent = parent
        self.value = None
        if type == "choice" and values is None:
            values = {}
        self.values = values
        self.type = type

    def convert_value_type(self, value):
        """
        Tries to convert the value into the right type

        :param Mixed value: Value to convert
        :return: The value
        :rtype: Mixed
        """

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

    def get_parent(self):
        """
        Return the parent config object or None if no parent is set.

        :return: Object or None
        """

        return self._parent

    def get_value(self, default=None):
        """
        Get the value.

        :param Mixed default: Default value if value of option not set
        :return: The value or the default value
        :rtype: Mixed
        """

        if self.value is not None:
            return self.value
        if default is not None:
            return default
        return self.default

    def set_value(self, value):
        """
        Set the value and returns True if it was successful or False if not.

        :param Mixed value: The value
        :raises sslscan.exception.OptionValueError: if types do not match
        """

        logger.debug("Set value of option '%s' to '%r'", self.name, value)

        value = self.convert_value_type(value)

        if self.type == "choice":
            values = self.values
            if callable(values):
                values = values(self)

            if value not in values:
                raise OptionValueError(option=self, value=value)

            self.value = value
            return

        if self.action == "store":
            self.value = value
            return

        if self.action == "append":
            if type(self.value) is not list:
                self.value = []
            self.value.append(value)
            return

        raise OptionValueError(option=self, value=value)


class OptionGroup(BaseConfig):
    """Used to group multiple options"""
    def __init__(self, label, help=None):
        BaseConfig.__init__(self)
        self.label = label
        self.help = help
