from builtins import range
import os
from oic.utils.shelve_wrapper import open
import pytest

__author__ = 'mathiashedstrom'

DB_NAMNE = "test_db_shelve_wrapper"

def teardown_module(module):
    _clear_db()

@pytest.fixture
def db():
    _clear_db()
    return open(DB_NAMNE, writeback=True)

def test_keys(db):
    key_1 = "key_1"
    key_2 = "key_2"
    key_3 = "key_3"

    db[key_1] = "foo"
    db[key_2] = "foo"
    db[key_3] = "foo"

    key_list = list()
    key_list.append(key_1)
    key_list.append(key_2)
    key_list.append(key_3)

    keys = list(db.keys())

    for k in keys:
        assert k in key_list

def test_has_keys(db):
    key_1 = "key_1"
    key_2 = "key_2"
    key_3 = "key_3"

    db[key_1] = "foo"
    db[key_2] = "foo"
    db[key_3] = "foo"

    key_list = list()
    key_list.append(key_1)
    key_list.append(key_2)
    key_list.append(key_3)

    for k in key_list:
        assert db.has_key(k)

    assert not db.has_key("NO_KEY")

def test_contains(db):
    key_1 = "key_1"
    key_2 = "key_2"
    key_3 = "key_3"

    db[key_1] = "foo"
    db[key_2] = "foo"
    db[key_3] = "foo"

    key_list = list()
    key_list.append(key_1)
    key_list.append(key_2)
    key_list.append(key_3)

    for k in key_list:
        assert k in db

    assert "NO_KEY" not in db

def test_get(db):
    key_list = list()
    value_list = list()

    for i in range(3):
        key = "key_{}".format(i)
        value = "value_{}".format(i)
        key_list.append(key)
        value_list.append(value)
        db[key] = value

    for index, key in enumerate(key_list):
        assert db.get(key) == value_list[index]

    assert db.get("NO_KEY") == None

def test_getitem(db):
    key_list = list()
    value_list = list()

    for i in range(3):
        key = "key_{}".format(i)
        value = "value_{}".format(i)
        key_list.append(key)
        value_list.append(value)
        db[key] = value

    for index, key in enumerate(key_list):
        assert db[key] == value_list[index]

    with pytest.raises(KeyError):
        db["NO_KEY"]

def test_delitem(db):
    key_list = list()
    value_list = list()

    for i in range(3):
        key = "key_{}".format(i)
        value = "value_{}".format(i)
        key_list.append(key)
        value_list.append(value)
        db[key] = value

    del db[key_list[0]]

    with pytest.raises(KeyError):
        db[key_list[0]]

    for index in range(1, len(key_list)):
        assert db[key_list[index]] == value_list[index]


def test_len(db):
    assert len(db) == 0
    lenght = 4
    for i in range(lenght):
        db["key_{}".format(i)] = "foo"
    assert len(db) == lenght

def _clear_db():
    extensions = ["db", "bak", "dat", "dir"]
    for e in extensions:
        try:
            os.remove("{db_name}.{extension}".format(db_name=DB_NAMNE, extension=e))
        except:
            pass

#_clear_db()
