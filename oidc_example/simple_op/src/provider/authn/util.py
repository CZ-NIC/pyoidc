import json


class JSONDictDB(object):
    def __init__(self, json_path):
        with open(json_path, "r") as f:
            self._db = json.load(f)

    def __getitem__(self, item):
        return self._db[item]

    def __contains__(self, item):
        return item in self._db
