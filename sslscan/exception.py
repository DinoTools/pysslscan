class ModuleNotFound(Exception):
    def __init__(self, name="", base_class=None):
        self.name = name
        self.base_class = base_class

    def __str__(self):
        return "Module '{}' not found".format(self.name)
