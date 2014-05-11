from sslscan import _helper as helper

class KnowledgeBase(object):
    def __init__(self):
        self._default_items = {
            "client.ciphers": [],
            "client.custom": [],
            "server.ciphers": [],
            "server.custom": [],
            "server.preferred_ciphers": [],
        }
        self._items = {}

    def append(self, kb_id, value):
        # ToDo: checks
        item = self._items.get(kb_id)
        if item is None:
            item = self._default_items.get(kb_id)
            if item is None:
                return None
            self._items[kb_id] = item

        item.append(value)

    def get(self, kb_id):
        return self._items.get(kb_id)

    def get_list(self, kb_id):
        if kb_id[-1] != ".":
            kb_id = kb_id + "."

        result = {}
        for k, v in self._items.items():
            if k.find(kb_id) == 0:
                result[k] = v
        return result

    def get_group_ids(self, kb_id):
        result = []
        items = self.get_list(kb_id)
        for k, v in items.items():
            if isinstance(v, ResultGroup):
                result.append(k)

        return result

    def set(self, kb_id, value):
        self._items[kb_id] = value

class Cipher(object):
    def __init__(self, method=None, name=None, bits=None, status=None):
        self.method = method
        if isinstance(name, bytes):
            name = name.decode("ASCII")
        self.name = name
        self.bits = bits
        self.status = status

    @property
    def method_name(self):
        return helper.get_method_name(self.method)

    @property
    def status_name(self):
        if self.status < 0:
            return "failed"
        if self.status == 0:
            return "rejected"
        if self.status > 0:
            return "accepted"
        return "unknown"

class BaseResult(object):
    def __init__(self, label=None):
        self.label = label

class ResultGroup(BaseResult):
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
    def __init__(self, name=None, value=None, **kwargs):
        BaseResult.__init__(self, **kwargs)
        self.name = name
        self.value = value
