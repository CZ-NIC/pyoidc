# pylint: disable=missing-docstring
import copy
import json
from collections import Counter

import pytest
from jwkest.jwk import SYMKey
from jwkest.jws import JWS
from jwkest.jwt import JWT

from oic.extension.signed_http_req import SignedHttpRequest
from oic.extension.signed_http_req import ValidationError
from oic.extension.signed_http_req import get_hash_size
from oic.extension.signed_http_req import hash_value
from oic.extension.signed_http_req import serialize_dict

ALG = "HS256"
SIGN_KEY = SYMKey(key="a_key", alg=ALG)

DEFAULT_DATA = {
    "key": SIGN_KEY,
    "method": "GET",
    "host": "host",
    "path": "/foo/bar",
    "query_params": {"k1": "v1", "k2": "v2"},
    "headers": {"h1": "d1", "h2": "d2"},
    "body": "my body",
}


def test_sign_empty_http_req():
    with pytest.raises(ValueError):
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


@pytest.mark.parametrize(
    "value,expected", [("RS256", 256), ("RS384", 384), ("RS512", 512)]
)
def test_get_hash_size(value, expected):
    assert get_hash_size(value) == expected


def test_hash_value():
    data = "some_test_string"
    with pytest.raises(ValueError):
        hash_value(123, data)
    assert hash_value(256, data)


def test_verify():
    timestamp = 12347456
    shr = SignedHttpRequest(SIGN_KEY)
    result = shr.sign(alg=ALG, time_stamp=12347456, **DEFAULT_DATA)
    signature = shr.verify(signature=result, **DEFAULT_DATA)

    assert signature["ts"] == timestamp


def test_verify_fail_wrong_key():
    shr = SignedHttpRequest(SIGN_KEY)
    result = shr.sign(alg=ALG, **DEFAULT_DATA)
    with pytest.raises(ValidationError):
        rshr = SignedHttpRequest(SYMKey(key="wrong_key", alg="HS256"))
        rshr.verify(signature=result, **DEFAULT_DATA)


@pytest.mark.parametrize(
    "param,value",
    [
        ("method", "FAIL"),
        ("host", "FAIL"),
        ("path", "FAIL"),
        ("query_params", {"k1": "v1", "k2": "FAIL"}),
        ("headers", {"h1": "d1", "h2": "FAIL"}),
        ("body", "FAIL"),
    ],
)
def test_verify_fail(param, value):
    shr = SignedHttpRequest(SIGN_KEY)
    result = shr.sign(alg=ALG, **DEFAULT_DATA)

    wrong_data = DEFAULT_DATA.copy()
    wrong_data[param] = value
    with pytest.raises(ValidationError):
        shr.verify(signature=result, **wrong_data)


@pytest.mark.parametrize("param", ["query_params", "headers"])
def test_verify_strict_with_too_many(param):
    shr = SignedHttpRequest(SIGN_KEY)
    result = shr.sign(alg=ALG, **DEFAULT_DATA)

    request_with_extra_params = copy.deepcopy(DEFAULT_DATA)
    request_with_extra_params[param]["foo"] = "bar"  # insert extra param
    with pytest.raises(ValidationError):
        shr.verify(
            signature=result,
            strict_query_params_verification=True,
            strict_headers_verification=True,
            **request_with_extra_params,
        )


@pytest.mark.parametrize("param", ["query_params", "headers"])
def test_verify_with_too_few(param):
    test_data = copy.deepcopy(DEFAULT_DATA)
    test_data[param]["foo"] = "bar"  # insert extra param
    shr = SignedHttpRequest(SIGN_KEY)
    result = shr.sign(alg=ALG, **test_data)

    with pytest.raises(ValidationError):
        shr.verify(signature=result, **DEFAULT_DATA)


@pytest.mark.parametrize("param", ["query_params", "headers"])
def test_verify_not_strict(param):
    shr = SignedHttpRequest(SIGN_KEY)
    result = shr.sign(alg=ALG, **DEFAULT_DATA)

    request_with_extra_params = copy.deepcopy(DEFAULT_DATA)
    request_with_extra_params[param]["foo"] = "bar"  # insert extra param
    shr.verify(
        signature=result,
        strict_query_params_verification=False,
        strict_headers_verification=False,
        **DEFAULT_DATA,
    )


def test_verify_fail_on_missing_body():
    shr = SignedHttpRequest(SIGN_KEY)
    result = shr.sign(alg=ALG, body="abcdef")
    with pytest.raises(ValidationError):
        shr.verify(signature=result)


def test_sign_specifies_jws_typ_pop():
    shr = SignedHttpRequest(SIGN_KEY)
    result = shr.sign(alg=ALG, body="abcdef")
    assert JWT().unpack(result).headers["typ"] == "pop"


def test_verify_reject_jws_wo_typ_pop():
    method = "GET"

    signature_without_typ = JWS(json.dumps(dict(m=method)), alg=ALG).sign_compact(
        [SIGN_KEY]
    )
    shr = SignedHttpRequest(SIGN_KEY)
    with pytest.raises(ValidationError) as exc:
        shr.verify(signature_without_typ, method=method)

    assert "typ" in str(exc.value)
