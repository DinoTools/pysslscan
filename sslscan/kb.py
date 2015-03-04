"""
The knowledge base is used to store and access all collected information.

Example 1::

    >>> kb = KnowledgeBase()
    >>> kb.set("test.foo", 1234)
    >>> kb.get("test.foo")

Example 2::

    >>> kb = KnowledgeBase()
    >>> cipher = Cipher()
    >>> kb.append("client.ciphers", cipher)
    >>> kb.get("client.ciphers")

Example 3::

    >>> group = ResultGroup(label="My Results")
    >>> value = ResultValue(label="Yes/No", True)
    >>> group.append(value)
"""

import flextls.helper
from sslscan import _helper as helper

class KnowledgeBase(object):
    """
    The knowledge base is used to store and access all collected information.
    """

    def __init__(self):
        self._default_items = {
            "client.ciphers": [],
            "client.custom": [],
            "server.ciphers": [],
            "server.custom": [],
            "server.ec.named_curves": [],
            "server.preferred_ciphers": [],
        }
        self._items = {}

    def add(self, kb_id, value):
        """
        Add the value to the KB value with the given key. If a value does not exist it is initialised with 0.

        :param String kb_id: The ID of the value in the KB
        :param Integer|Float value: The value to add to the value from the KB
        :return:
        """
        v = self.get(kb_id, 0)
        v += value
        self.set(kb_id, v)

    def append(self, kb_id, value):
        """
        Append a new value to the knowledge base.

        :param String kb_id: The ID of the value
        :param Mixed value: The value
        """

        # ToDo: checks
        item = self._items.get(kb_id)
        if item is None:
            item = self._default_items.get(kb_id)
            if item is None:
                return None
            self._items[kb_id] = item

        item.append(value)

    def get(self, kb_id, default=None):
        """
        Fetch a value by its ID from the knowledge base. If not found return
        the default value.

        :param String kb_id: The knowledge base id
        :param Mixed default: Default value, returned if kb_id not found
        :return: Value or default
        :rtype: Mixed
        """

        return self._items.get(kb_id, default)

    def get_list(self, kb_id):
        """
        Fetch all values and sub-values by a given ID

        :param String kb_id: The ID
        :return: List of values
        :rtype: List
        """

        if kb_id[-1] != ".":
            kb_id = kb_id + "."

        result = {}
        for k, v in self._items.items():
            if k.find(kb_id) == 0:
                result[k] = v
        return result

    def get_group_ids(self, kb_id):
        """
        Collect and return all values that are result groups.

        The given kb_id is used as filter.

        :param String kb_id: The ID
        """

        result = []
        items = self.get_list(kb_id)
        for k, v in items.items():
            if isinstance(v, ResultGroup):
                result.append(k)

        return result

    def set(self, kb_id, value):
        self._items[kb_id] = value

class CipherResult(object):
    """
    This class is used to store all information for a cipher.
    """

    def __init__(self, protocol_version, cipher_suite, status=None):
        self.protocol_version = protocol_version
        self.cipher_suite = cipher_suite
        self.status = status

    @property
    def protocol_version_name(self):
        return flextls.helper.get_version_name(self.protocol_version)

    @property
    def status_name(self):
        if self.status < 0:
            return "failed"
        if self.status == 0:
            return "rejected"
        if self.status > 0:
            return "accepted"
        return "unknown"


class ECResult(object):
    """
    This class is used to store all information for a elliptic curve.
    """

    def __init__(self, protocol_version, elliptic_curve):
        self.protocol_version = protocol_version
        self.elliptic_curve = elliptic_curve

    @property
    def protocol_version_name(self):
        return flextls.helper.get_version_name(self.protocol_version)


class BaseResult(object):
    """Base class for custom results."""

    def __init__(self, label=None):
        self.label = label

class ResultGroup(BaseResult):
    """Group results"""

    def __init__(self, **kwargs):
        BaseResult.__init__(self, **kwargs)
        self._items = []

    def __iter__(self):
        return self._items.__iter__()

    def append(self, item):
        self._items.append(item)

    def get_items(self):
        return self._items

class ResultValue(BaseResult):
    """A single result value"""

    def __init__(self, name=None, value=None, **kwargs):
        BaseResult.__init__(self, **kwargs)
        self.name = name
        self.value = value
