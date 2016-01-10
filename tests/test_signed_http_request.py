# pylint: disable=missing-docstring
import pytest

from collections import Counter

from jwkest.jwk import SYMKey

from oic.extension.signed_http_req import serialize_dict
from oic.extension.signed_http_req import get_hash_size
from oic.extension.signed_http_req import UnknownHashSizeError
from oic.extension.signed_http_req import hash_value
from oic.extension.signed_http_req import SignedHttpRequest
from oic.extension.signed_http_req import ValidationError
from oic.extension.signed_http_req import EmptyHTTPRequestError

ALG = "HS256"
SIGN_KEY = SYMKey(key="a_key", alg=ALG)

TEST_DATA = {"key": SIGN_KEY, "method": "GET", "host": "host",
             "path": "/foo/bar", "query_params": {"k1": "v1", "k2": "v2"},
             "headers": {"h1": "d1", "h2": "d2"},
             "body": "my body"}


def test_sign_empty_http_req():
    with pytest.raises(EmptyHTTPRequestError):
        SignedHttpRequest(SIGN_KEY).sign(ALG)


def test_serialize():
    data = {"key_1": "v1", "key_2": "v2", "key_3": "v3"}
    form = ".{}:{}"
    keys, serialized_data = serialize_dict(data, form)

    assert Counter(keys) == Counter(data.keys())

    data_parts = serialized_data.split(".")[1:]
    for index, part in enumerate(data_parts):
        key, value = part.split(":")

        assert key == keys[index]
        assert value == data[key]


@pytest.mark.parametrize("value,expected", [
    ("RS256", 256),
    ("RS384", 384),
    ("RS512", 512),
])
def test_get_hash_size(value, expected):
    assert get_hash_size(value) == expected


def test_hash_value():
    data = "some_test_string"
    with pytest.raises(UnknownHashSizeError):
        hash_value(123, data)
    assert hash_value(256, data)


def test_verify():
    timestamp = 12347456
    shr = SignedHttpRequest(SIGN_KEY)
    result = shr.sign(alg=ALG, time_stamp=12347456, **TEST_DATA)
    signature = shr.verify(signature=result, **TEST_DATA)

    assert signature["ts"] == timestamp


def test_verify_fail_wrong_key():
    shr = SignedHttpRequest(SIGN_KEY)
    result = shr.sign(alg=ALG, **TEST_DATA)
    with pytest.raises(ValidationError):
        rshr = SignedHttpRequest(SYMKey(key="wrong_key", alg="HS256"))
        rshr.verify(signature=result, **TEST_DATA)


@pytest.mark.parametrize("key,value", [
    ("method", "FAIL"),
    ("host", "FAIL"),
    ("path", "FAIL"),
    ("query_params", {"k1": "v1", "k2": "FAIL"}),
    ("headers", {"h1": "d1", "h2": "FAIL"}),
    ("body", "FAIL"),
])
def test_verify_fail(key, value, monkeypatch):
    shr = SignedHttpRequest(SIGN_KEY)
    result = shr.sign(alg=ALG, **TEST_DATA)
    monkeypatch.setitem(TEST_DATA, key, value)
    with pytest.raises(ValidationError):
        shr.verify(signature=result, **TEST_DATA)


@pytest.mark.parametrize("key,value", [
    ("query_params", {"k1": "v1", "k2": "v2", "k3": "v3"}),
    ("headers", {"h1": "d1", "h2": "d2", "h3": "d3"}),
])
def test_verify_strict(key, value, monkeypatch):
    shr = SignedHttpRequest(SIGN_KEY)
    result = shr.sign(alg=ALG, **TEST_DATA)
    monkeypatch.setitem(TEST_DATA, key, value)
    with pytest.raises(ValidationError):
        shr.verify(signature=result,
                   strict_query_params_verification=True,
                   strict_headers_verification=True, **TEST_DATA)


@pytest.mark.parametrize("key,value", [
    ("query_params", {"k1": "v1", "k2": "v2", "k3": "v3"}),
    ("headers", {"h1": "d1", "h2": "d2", "h3": "d3"}),
])
def test_verify_not_strict(key, value, monkeypatch):
    shr = SignedHttpRequest(SIGN_KEY)
    result = shr.sign(alg=ALG, **TEST_DATA)
    monkeypatch.setitem(TEST_DATA, key, value)
    shr.verify(signature=result,
               strict_query_params_verification=False,
               strict_headers_verification=False, **TEST_DATA)
