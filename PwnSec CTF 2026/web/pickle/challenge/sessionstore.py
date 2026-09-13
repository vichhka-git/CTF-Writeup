class Capsule:
    def __init__(self, owner="guest"):
        self.owner = owner
        self.cache = {}

    def __repr__(self):
        return "<Capsule owner=%r fields=%s>" % (self.owner, list(self.cache))


def render(record, key):
    return record.cache[key]


def new_capsule(owner="guest"):
    return Capsule(owner)