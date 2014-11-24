from sslscan.module import BaseModule


class BaseRating(BaseModule):
    def __init__(self, **kwargs):
        BaseModule.__init__(self, **kwargs)
        self._rules = {}

    def add_rule(self, rule):
        name = rule.name
        self._rules[name] = rule

    def get_rule(self, name):
        return self._rules.get(name)

    def rate(self, rule_name, value):
        rule = self.get_rule(rule_name)
        if rule is None:
            return None
        return rule.rate(value)


class NoneRating(BaseRating):
    name="none"

    def __init__(self, **kwargs):
        BaseModule.__init__(self, **kwargs)


class RatingRule(object):
    def __init__(self, name, description="", result_description=None,
            rules=[]):
        self.name = name
        self.description = description
        self._result_description = result_description
        self._rules = rules

    def rate(self, value):
        result = None
        for rule in self._rules:
            result = rule(value)
            if result is not None:
                break
        return RatingResult(result, self)


class RatingResult(object):
    def __init__(self, result, rule):
        self._result = result
        self._rule = rule

    def __eq__(self, other):
        return self.get_value() == other

    def __gt__(self, other):
        return self.get_value() > other

    def __lt__(self, other):
        return self.get_value() < other

    def get_description(self):
        return self._rule.description

    def get_result_description(self):
        return self._rule._result_description.get(self._result)

    def get_value(self):
        return self._result
