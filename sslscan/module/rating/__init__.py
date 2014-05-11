from sslscan.module import BaseModule


class BaseRating(BaseModule):
    def __init__(self, **kwargs):
        BaseModule.__init__(self, **kwargs)

    def rate(self, rule_id, data):
        rules = self._rules.get(rule_id)
        if rules is None:
            return None

        for rule in rules:
            result = rule(data)
            if result is not None:
                return result
        return result

class NoneRating(BaseRating):
    name="none"

    _rules = {}
