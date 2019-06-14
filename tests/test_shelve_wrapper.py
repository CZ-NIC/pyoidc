# pylint: disable=missing-docstring,no-self-use,redefined-outer-name
import os

import pytest

from oic.utils import shelve_wrapper

__author__ = "mathiashedstrom"

VALUES = {"key_1": "val_1", "key_2": "val_2", "key_3": "val_3"}


def _eq(l1, l2):
    return set(l1) == set(l2)


@pytest.fixture
def db(tmpdir):
    return shelve_wrapper.open(os.path.join(tmpdir.strpath, "test_db_shelve_wrapper"))


@pytest.fixture
def populated_db(db):
    for k, v in VALUES.items():
        db[k] = v

    return db


class TestShelfWrapper(object):
    def test_keys(self, populated_db):
        assert _eq(populated_db.keys(), VALUES.keys())

    def test_contains(self, populated_db):
        for k in VALUES.keys():
            assert k in populated_db

        assert "NO_KEY" not in populated_db

    def test_get(self, populated_db):
        for k, v in VALUES.items():
            assert populated_db.get(k) == v

        assert populated_db.get("NO_KEY") is None

    def test_getitem(self, populated_db):
        for k, v in VALUES.items():
            assert populated_db[k] == v

        with pytest.raises(KeyError):
            populated_db["NO_KEY"]  # pylint: disable=pointless-statement

    def test_delitem(self, populated_db):
        key = list(VALUES.keys())[0]
        del populated_db[key]

        with pytest.raises(KeyError):
            populated_db[key]  # pylint: disable=pointless-statement

    def test_len(self, db):
        assert len(db) == 0

        length = 4
        for i in range(length):
            db["key_{}".format(i)] = "foo"
        assert len(db) == length
