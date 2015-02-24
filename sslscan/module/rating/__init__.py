from sslscan.kb import KnowledgeBase
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

    def rate(self, rule_name, value, item=None, kb=None):
        if item is None:
            item = value
        if kb is None:
            kb = self._scanner.get_knowledge_base()
        rule = self.get_rule(rule_name)
        if rule is None:
            return None
        return rule.rate(value, item, kb)


class RatingRule(object):
    def __init__(self, name, description="", result_descriptions=None,
            result_refs=None, rules=[]):
        self.name = name
        self.description = description
        self._result_descriptions = result_descriptions
        self._result_refs = result_refs
        self._rules = rules

    def rate(self, value, item=None, kb=None):
        if item is None:
            item = value
        if kb is None:
            kb = KnowledgeBase()
        result = None
        for rule in self._rules:
            result = rule(value, item, kb)
            if result is not None:
                break
        return RatingResult(result, self)


class RatingResult(object):
    def __init__(self, result, rule):
        self._result_reason = None
        if isinstance(result, tuple):
            self._result_value = result[0]
            self._result_reason = result[1]
        else:
            self._result_value = result
        self._rule = rule

    def __eq__(self, other):
        return self.get_value() == other

    def __gt__(self, other):
        return self.get_value() > other

    def __lt__(self, other):
        return self.get_value() < other

    def get_description(self):
        return self._rule.description

    def get_reason(self):
        return self._result_reason

    def get_result_description(self):
        tmp = self._rule._result_descriptions.get(self._result_reason)
        if tmp is None:
            tmp = self._rule._result_descriptions.get(self._result_value)
        return tmp

    def get_result_refs(self):
        tmp = self._rule._result_refs.get(self._result_reason)
        if tmp is None:
            tmp = self._rule._result_refs.get(self._result_value)
        return tmp

    def get_value(self):
        return self._result_value
