# pylint: disable=no-self-use,missing-docstring
import json
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
from jwkest.jwk import SYMKey

from oic.oauth2.message import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS
from oic.oauth2.message import SINGLE_OPTIONAL_INT
from oic.oauth2.message import SINGLE_OPTIONAL_JSON
from oic.oauth2.message import SINGLE_OPTIONAL_STRING
from oic.oauth2.message import SINGLE_REQUIRED_STRING
from oic.oauth2.message import AccessTokenRequest
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import AuthorizationErrorResponse
from oic.oauth2.message import AuthorizationRequest
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import CCAccessTokenRequest
from oic.oauth2.message import DecodeError
from oic.oauth2.message import ErrorResponse
from oic.oauth2.message import Message
from oic.oauth2.message import MissingRequiredAttribute
from oic.oauth2.message import ParamDefinition
from oic.oauth2.message import RefreshAccessTokenRequest
from oic.oauth2.message import ROPCAccessTokenRequest
from oic.oauth2.message import TokenErrorResponse
from oic.oauth2.message import json_deserializer
from oic.oauth2.message import json_serializer
from oic.oauth2.message import sp_sep_list_deserializer
from oic.utils.keyio import build_keyjar

__author__ = 'rohe0002'

keys = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["enc"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]},
]

keym = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["sig"]},
]

KEYJAR = build_keyjar(keys)[1]
IKEYJAR = build_keyjar(keys)[1]
IKEYJAR.issuer_keys['issuer'] = IKEYJAR.issuer_keys['']
del IKEYJAR.issuer_keys['']

KEYJARS = {}
for iss in ['A', 'B', 'C']:
    _kj = build_keyjar(keym)[1]
    _kj.issuer_keys[iss] = _kj.issuer_keys['']
    del _kj.issuer_keys['']
    KEYJARS[iss] = _kj


def url_compare(url1, url2):
    url1 = urlparse(url1)
    url2 = urlparse(url2)

    if url1.scheme != url2.scheme:
        return False
    if url1.netloc != url2.netloc:
        return False
    if url1.path != url2.path:
        return False
    if not query_string_compare(url1.query, url2.query):
        return False
    if not query_string_compare(url1.fragment, url2.fragment):
        return False

    return True


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_sp_sep_list_deserializer():
    vals = sp_sep_list_deserializer("foo bar zen")
    assert len(vals) == 3
    assert _eq(vals, ["foo", "bar", "zen"])

    vals = sp_sep_list_deserializer(["foo bar zen"])
    assert len(vals) == 3
    assert _eq(vals, ["foo", "bar", "zen"])


def test_json_serializer():
    val = json_serializer({"foo": ["bar", "stool"]})
    val_obj = json.loads(val)
    assert val_obj == {"foo": ["bar", "stool"]}


def test_json_deserializer():
    _dict = {"foo": ["bar", "stool"]}
    val = json_serializer(_dict)

    sdict = json_deserializer(val)
    assert _dict == sdict


class DummyMessage(Message):
    c_param = {
        "req_str": SINGLE_REQUIRED_STRING,
        "opt_str": SINGLE_OPTIONAL_STRING,
        "opt_int": SINGLE_OPTIONAL_INT,
        "opt_str_list": OPTIONAL_LIST_OF_STRINGS,
        "req_str_list": REQUIRED_LIST_OF_STRINGS,
        "opt_json": SINGLE_OPTIONAL_JSON
    }


class StarMessage(Message):
    c_param = {'*': SINGLE_REQUIRED_STRING}


class MessageListMessage(Message):
    c_param = {'opt_message_list': ParamDefinition([Message], False, None, None, False)}


class TestMessage(object):
    def test_json_serialization(self):
        item = DummyMessage(req_str="Fair", opt_str="game", opt_int=9,
                            opt_str_list=["one", "two"],
                            req_str_list=["spike", "lee"],
                            opt_json='{"ford": "green"}')

        jso = item.serialize(method="json")
        item2 = DummyMessage().deserialize(jso, "json")
        assert _eq(item2.keys(),
                   ['opt_str', 'req_str', 'opt_json', 'req_str_list',
                    'opt_str_list', 'opt_int'])

    def test_from_json(self):
        jso = '{"req_str": "Fair", "req_str_list": ["spike", "lee"], ' \
              '"opt_int": 9}'
        item = DummyMessage().deserialize(jso, "json")

        assert _eq(item.keys(), ['req_str', 'req_str_list', 'opt_int'])
        assert item["opt_int"] == 9

    def test_single_optional(self):
        jso = '{"req_str": "Fair", "req_str_list": ["spike", "lee"], ' \
              '"opt_int": [9, 10]}'
        with pytest.raises(ValueError):
            DummyMessage().deserialize(jso, "json")

    def test_extra_param(self):
        jso = '{"req_str": "Fair", "req_str_list": ["spike", "lee"], "extra": ' \
              '"out"}'
        item = DummyMessage().deserialize(jso, "json")

        assert _eq(item.keys(), ['req_str', 'req_str_list', 'extra'])
        assert item["extra"] == "out"

    def test_to_from_jwt(self):
        item = DummyMessage(req_str="Fair", opt_str="game", opt_int=9,
                            opt_str_list=["one", "two"],
                            req_str_list=["spike", "lee"],
                            opt_json='{"ford": "green"}')
        keys = [SYMKey(key="A1B2C3D4")]
        jws = item.to_jwt(keys, "HS256")

        jitem = DummyMessage().from_jwt(jws, key=keys)

        assert _eq(jitem.keys(), ['opt_str', 'req_str', 'opt_json',
                                  'req_str_list', 'opt_str_list', 'opt_int'])

    def test_verify(self):
        _dict = {"req_str": "Fair", "opt_str": "game", "opt_int": 9,
                 "opt_str_list": ["one", "two"],
                 "req_str_list": ["spike", "lee"],
                 "opt_json": '{"ford": "green"}'}

        cls = DummyMessage(**_dict)
        assert cls.verify()
        assert _eq(cls.keys(), ['opt_str', 'req_str', 'opt_json',
                                'req_str_list', 'opt_str_list', 'opt_int'])

        _dict = {"req_str": "Fair", "opt_str": "game", "opt_int": 9,
                 "opt_str_list": ["one", "two"],
                 "req_str_list": ["spike", "lee"],
                 "opt_json": '{"ford": "green"}', "extra": "internal"}

        cls = DummyMessage(**_dict)
        assert cls.verify()
        assert _eq(cls.keys(), ['opt_str', 'req_str', 'extra', 'opt_json',
                                'req_str_list', 'opt_str_list', 'opt_int'])

        _dict = {"req_str": "Fair", "opt_str": "game", "opt_int": 9,
                 "opt_str_list": ["one", "two"],
                 "req_str_list": ["spike", "lee"]}

        cls = DummyMessage(**_dict)
        cls.verify()
        assert _eq(cls.keys(), ['opt_str', 'req_str', 'req_str_list',
                                'opt_str_list', 'opt_int'])

    def test_request(self):
        req = DummyMessage(req_str="Fair",
                           req_str_list=["game"]).request("http://example.com")
        assert url_compare(req,
                           "http://example.com?req_str=Fair&req_str_list=game")

    def test_get(self):
        _dict = {"req_str": "Fair", "opt_str": "game", "opt_int": 9,
                 "opt_str_list": ["one", "two"],
                 "req_str_list": ["spike", "lee"],
                 "opt_json": '{"ford": "green"}'}

        cls = DummyMessage(**_dict)

        assert cls.get("req_str") == "Fair"
        assert cls.get("opt_int", 8) == 9
        assert cls.get("missing") is None
        assert cls.get("missing", []) == []

    def test_from_dict_simple(self):
        _dict = {'req_str': 'Fair', 'opt_str': 'game', 'opt_int': 9}

        message = DummyMessage().from_dict(_dict)
        assert message.to_dict() == _dict

    def test_from_dict_lang(self):
        _dict = {'req_str#en': 'Fair', 'opt_str': 'game', 'opt_int': 9}

        message = DummyMessage().from_dict(_dict)
        assert message.to_dict() == _dict

    def test_from_dict_wrong_lang_key_no_star(self):
        _dict = {'bad_str#en': None}

        message = DummyMessage().from_dict(_dict)
        assert message.to_dict() == _dict

    def test_from_dict_wrong_lang_key_star(self):
        _dict = {'bad_str#en': 'test'}

        message = StarMessage().from_dict(_dict)
        assert message.to_dict() == _dict

    def test_from_dict_wrong_lang_key_star_none(self):
        _dict = {'bad_str#en': None}

        message = StarMessage().from_dict(_dict)
        assert message.to_dict() == _dict

    def test_from_dict_wrong_key_no_star(self):
        _dict = {'req_str_en': None}

        message = DummyMessage().from_dict(_dict)
        assert message.to_dict() == _dict

    def test_from_dict_wrong_key_star(self):
        _dict = {'req_str_en': 'test'}

        message = StarMessage().from_dict(_dict)
        assert message.to_dict() == _dict

    def test_from_dict_wrong_key_star_none(self):
        _dict = {'req_str_en': None}

        message = StarMessage().from_dict(_dict)
        assert message.to_dict() == _dict

    def test_from_dict_empty_val(self):
        _dict = {'req_str': '', 'req_str_list': ['']}

        message = DummyMessage().from_dict(_dict)
        assert message.to_dict() == {}

    def test_from_dict_message(self):
        _dict = {'opt_message_list': DummyMessage(req_str='test')}

        message = MessageListMessage().from_dict(_dict)
        assert message.to_dict() == {'opt_message_list': [{'req_str': 'test'}]}

    def test_from_dict_message_list(self):
        _dict = {'opt_message_list': [DummyMessage(req_str='test')]}

        message = MessageListMessage().from_dict(_dict)
        assert message.to_dict() == {'opt_message_list': [{'req_str': 'test'}]}


class TestAuthorizationRequest(object):
    def test_authz_req_urlencoded(self):
        ar = AuthorizationRequest(response_type=["code"], client_id="foobar")
        ue = ar.to_urlencoded()
        assert query_string_compare(ue, "response_type=code&client_id=foobar")

    def test_urlencoded_with_redirect_uri(self):
        ar = AuthorizationRequest(response_type=["code"], client_id="foobar",
                                  redirect_uri="http://foobar.example.com/oaclient",
                                  state="cold")

        ue = ar.to_urlencoded()
        assert query_string_compare(ue,
                                    "state=cold&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&"
                                    "response_type=code&client_id=foobar")

    def test_urlencoded_resp_type_token(self):
        ar = AuthorizationRequest(response_type=["token"],
                                  client_id="s6BhdRkqt3",
                                  redirect_uri="https://client.example.com/cb",
                                  state="xyz")

        ue = ar.to_urlencoded()
        assert query_string_compare(ue,
                                    "state=xyz&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&response_type=token&"
                                    "client_id=s6BhdRkqt3")

    def test_deserialize_urlencoded(self):
        ar = AuthorizationRequest(response_type=["code"],
                                  client_id="foobar")
        urlencoded = ar.to_urlencoded()
        ar2 = AuthorizationRequest().deserialize(urlencoded, "urlencoded")

        assert ar == ar2

    def test_urlencoded_with_scope(self):
        ar = AuthorizationRequest(response_type=["code"], client_id="foobar",
                                  redirect_uri="http://foobar.example.com/oaclient",
                                  scope=["foo", "bar"], state="cold")

        ue = ar.to_urlencoded()
        assert query_string_compare(ue,
                                    "scope=foo+bar&state=cold&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&"
                                    "response_type=code&client_id=foobar")

    def test_deserialize_urlencoded_multiple_params(self):
        ar = AuthorizationRequest(response_type=["code"],
                                  client_id="foobar",
                                  redirect_uri="http://foobar.example.com/oaclient",
                                  scope=["foo", "bar"], state="cold")
        urlencoded = ar.to_urlencoded()
        ar2 = AuthorizationRequest().deserialize(urlencoded, "urlencoded")

        assert ar == ar2

    def test_urlencoded_missing_required(self):
        ar = AuthorizationRequest(response_type=["code"])
        with pytest.raises(MissingRequiredAttribute):
            ar.verify()

    def test_urlencoded_invalid_scope(self):
        args = {"response_type": [10], "client_id": "foobar",
                "redirect_uri": "http://foobar.example.com/oaclient",
                "scope": ["foo", "bar"], "state": "cold"}

        with pytest.raises(DecodeError):
            AuthorizationRequest(**args)

    def test_urlencoded_deserialize_state(self):
        txt = "scope=foo+bar&state=-11&redirect_uri=http%3A%2F%2Ffoobar" \
              ".example.com%2Foaclient&response_type=code&" \
              "client_id=foobar"

        ar = AuthorizationRequest().deserialize(txt, "urlencoded")
        assert ar["state"] == "-11"

    def test_urlencoded_deserialize_response_type(self):
        txt = "scope=openid&state=id-6a3fc96caa7fd5cb1c7d00ed66937134&" \
              "redirect_uri=http%3A%2F%2Flocalhost%3A8087authz&response_type" \
              "=code&client_id=a1b2c3"

        ar = AuthorizationRequest().deserialize(txt, "urlencoded")
        assert ar["scope"] == ["openid"]
        assert ar["response_type"] == ["code"]

    def test_req_json_serialize(self):
        ar = AuthorizationRequest(response_type=["code"],
                                  client_id="foobar")

        js_obj = json.loads(ar.serialize(method="json"))
        expected_js_obj = {
            "response_type": "code",
            "client_id": "foobar"
        }
        assert js_obj == expected_js_obj

    def test_json_multiple_params(self):
        ar = AuthorizationRequest(response_type=["code"],
                                  client_id="foobar",
                                  redirect_uri="http://foobar.example.com/oaclient",
                                  state="cold")

        ue_obj = json.loads(ar.serialize(method="json"))
        expected_ue_obj = {
            "response_type": "code",
            "state": "cold",
            "redirect_uri": "http://foobar.example.com/oaclient",
            "client_id": "foobar"
        }
        assert ue_obj == expected_ue_obj

    def test_json_resp_type_token(self):
        ar = AuthorizationRequest(response_type=["token"],
                                  client_id="s6BhdRkqt3",
                                  redirect_uri="https://client.example.com/cb",
                                  state="xyz")

        ue_obj = json.loads(ar.serialize(method="json"))
        expected_ue_obj = {
            "state": "xyz",
            "redirect_uri": "https://client.example.com/cb",
            "response_type": "token",
            "client_id": "s6BhdRkqt3"
        }
        assert ue_obj == expected_ue_obj

    def test_json_serialize_deserialize(self):
        ar = AuthorizationRequest(response_type=["code"],
                                  client_id="foobar")
        jtxt = ar.serialize(method="json")
        ar2 = AuthorizationRequest().deserialize(jtxt, "json")

        assert ar == ar2

    def test_verify(self):
        query = 'redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauthz' \
                '&response_type=code&client_id=0123456789'
        ar = AuthorizationRequest().deserialize(query, "urlencoded")
        assert ar.verify()

    def test_load_dict(self):
        bib = {"scope": ["openid"],
               "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
               "redirect_uri": "http://localhost:8087authz",
               "response_type": ["code"],
               "client_id": "a1b2c3"}

        arq = AuthorizationRequest(**bib)

        assert arq["scope"] == bib["scope"]
        assert arq["response_type"] == bib["response_type"]
        assert arq["redirect_uri"] == bib["redirect_uri"]
        assert arq["state"] == bib["state"]
        assert arq["client_id"] == bib["client_id"]

    def test_json_serizalize_deserialize_multiple_params(self):
        argv = {"scope": ["openid"],
                "state": "id-b0be8bb64118c3ec5f70093a1174b039",
                "redirect_uri": "http://localhost:8087authz",
                "response_type": ["code"],
                "client_id": "a1b2c3"}

        arq = AuthorizationRequest(**argv)
        jstr = arq.serialize(method="json")
        jarq = AuthorizationRequest().deserialize(jstr, "json")

        assert jarq["scope"] == ["openid"]
        assert jarq["response_type"] == ["code"]
        assert jarq["redirect_uri"] == "http://localhost:8087authz"
        assert jarq["state"] == "id-b0be8bb64118c3ec5f70093a1174b039"
        assert jarq["client_id"] == "a1b2c3"

    def test_multiple_response_types_urlencoded(self):
        ar = AuthorizationRequest(response_type=["code", "token"],
                                  client_id="foobar")

        ue = ar.to_urlencoded()
        ue_splits = ue.split('&')
        expected_ue_splits = "response_type=code+token&client_id=foobar".split(
            '&')
        assert _eq(ue_splits, expected_ue_splits)

        are = AuthorizationRequest().deserialize(ue, "urlencoded")
        assert _eq(are.keys(), ["response_type", "client_id"])
        assert _eq(are["response_type"], ["code", "token"])

    def test_multiple_scopes_urlencoded(self):
        ar = AuthorizationRequest(response_type=["code", "token"],
                                  client_id="foobar",
                                  scope=["openid", "foxtrot"])
        ue = ar.to_urlencoded()
        ue_splits = ue.split('&')
        expected_ue_splits = "scope=openid+foxtrot&response_type=code+token&client_id=foobar".split('&')
        assert _eq(ue_splits, expected_ue_splits)

        are = AuthorizationRequest().deserialize(ue, "urlencoded")
        assert _eq(are.keys(), ["response_type", "client_id", "scope"])
        assert _eq(are["response_type"], ["code", "token"])
        assert _eq(are["scope"], ["openid", "foxtrot"])

    def test_multiple_response_types_json(self):
        ar = AuthorizationRequest(response_type=["code", "token"],
                                  client_id="foobar")
        ue = ar.to_json()
        ue_obj = json.loads(ue)
        expected_ue_obj = {
            "response_type": "code token",
            "client_id": "foobar"
        }
        assert ue_obj == expected_ue_obj

        are = AuthorizationRequest().deserialize(ue, "json")
        assert _eq(are.keys(), ["response_type", "client_id"])
        assert _eq(are["response_type"], ["code", "token"])

    def test_multiple_scopes_json(self):
        ar = AuthorizationRequest(response_type=["code", "token"],
                                  client_id="foobar",
                                  scope=["openid", "foxtrot"])
        ue = ar.to_json()
        ue_obj = json.loads(ue)
        expected_ue_obj = {
            "scope": "openid foxtrot",
            "response_type": "code token",
            "client_id": "foobar"
        }
        assert ue_obj == expected_ue_obj

        are = AuthorizationRequest().deserialize(ue, "json")
        assert _eq(are.keys(), ["response_type", "client_id", "scope"])
        assert _eq(are["response_type"], ["code", "token"])
        assert _eq(are["scope"], ["openid", "foxtrot"])


class TestAuthorizationErrorResponse(object):
    def test_init(self):
        aer = AuthorizationErrorResponse(error="access_denied",
                                         state="xyz")
        assert aer["error"] == "access_denied"
        assert aer["state"] == "xyz"

    def test_extra_params(self):
        aer = AuthorizationErrorResponse(error="access_denied",
                                         error_description="brewers has a "
                                                           "four game series",
                                         foo="bar")
        assert aer["error"] == "access_denied"
        assert aer["error_description"] == "brewers has a four game series"
        assert aer["foo"] == "bar"


class TestTokenErrorResponse(object):
    def test_init(self):
        ter = TokenErrorResponse(error="access_denied", state="xyz")

        assert ter["error"] == "access_denied"
        assert ter["state"] == "xyz"

    def test_extra_params(self):
        ter = TokenErrorResponse(error="access_denied",
                                 error_description="brewers has a four game "
                                                   "series",
                                 foo="bar")

        assert ter["error"] == "access_denied"
        assert ter["error_description"] == "brewers has a four game series"
        assert ter["foo"] == "bar"


class TestAccessTokenResponse(object):
    def test_json_serialize(self):
        at = AccessTokenResponse(access_token="SlAV32hkKG",
                                 token_type="Bearer", expires_in=3600)

        atj = at.serialize(method="json")
        atj_obj = json.loads(atj)
        expected_atj_obj = {
            "token_type": "Bearer",
            "access_token": "SlAV32hkKG",
            "expires_in": 3600
        }
        assert atj_obj == expected_atj_obj

    def test_multiple_scope(self):
        atr = AccessTokenResponse(
            access_token="2YotnFZFEjr1zCsicMWpAA",
            token_type="example",
            expires_in=3600,
            refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
            example_parameter="example_value",
            scope=["inner", "outer"])

        assert _eq(atr["scope"], ["inner", "outer"])

        uec = atr.to_urlencoded()
        assert "inner+outer" in uec

    def test_to_urlencoded_extended_omit(self):
        atr = AccessTokenResponse(
            access_token="2YotnFZFEjr1zCsicMWpAA",
            token_type="example",
            expires_in=3600,
            refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
            example_parameter="example_value",
            scope=["inner", "outer"],
            extra=["local", "external"],
            level=3)

        uec = atr.to_urlencoded()
        assert query_string_compare(uec,
                                    "scope=inner+outer&level=3&expires_in=3600&token_type=example&extra=local&"
                                    "extra=external&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA&"
                                    "access_token=2YotnFZFEjr1zCsicMWpAA&example_parameter=example_value")

        del atr["extra"]
        ouec = atr.to_urlencoded()
        assert query_string_compare(ouec,
                                    "access_token=2YotnFZFEjr1zCsicMWpAA&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA&"
                                    "level=3&example_parameter=example_value&token_type=example&expires_in=3600&"
                                    "scope=inner+outer")
        assert len(uec) == (len(ouec) + len("extra=local") +
                            len("extra=external") + 2)

        atr2 = AccessTokenResponse().deserialize(uec, "urlencoded")
        assert _eq(atr2.keys(), ['access_token', 'expires_in', 'token_type',
                                 'scope', 'refresh_token', 'level',
                                 'example_parameter', 'extra'])

        atr3 = AccessTokenResponse().deserialize(ouec, "urlencoded")
        assert _eq(atr3.keys(), ['access_token', 'expires_in', 'token_type',
                                 'scope', 'refresh_token', 'level',
                                 'example_parameter'])


class TestAccessTokenRequest(object):
    def test_extra(self):
        atr = AccessTokenRequest(grant_type="authorization_code",
                                 code="SplxlOBeZQQYbYS6WxSbIA",
                                 redirect_uri="https://client.example.com/cb",
                                 extra="foo")

        query = atr.to_urlencoded()
        assert query_string_compare(query,
                                    "code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&"
                                    "grant_type=authorization_code&extra=foo")

        atr2 = AccessTokenRequest().deserialize(query, "urlencoded")
        assert atr == atr2


class TestAuthorizationResponse(object):
    def test_init(self):
        atr = AuthorizationResponse(code="SplxlOBeZQQYbYS6WxSbIA",
                                    state="Fun_state", extra="foo")

        assert atr["code"] == "SplxlOBeZQQYbYS6WxSbIA"
        assert atr["state"] == "Fun_state"
        assert atr["extra"] == "foo"


class TestROPCAccessTokenRequest(object):
    def test_init(self):
        ropc = ROPCAccessTokenRequest(grant_type="password",
                                      username="johndoe", password="A3ddj3w")

        assert ropc["grant_type"] == "password"
        assert ropc["username"] == "johndoe"
        assert ropc["password"] == "A3ddj3w"


class TestCCAccessTokenRequest(object):
    def test_init(self):
        cc = CCAccessTokenRequest(scope="/foo")

        assert cc["grant_type"] == "client_credentials"
        assert cc["scope"] == ["/foo"]


class TestRefreshAccessTokenRequest(object):
    def test_init(self):
        ratr = RefreshAccessTokenRequest(refresh_token="ababababab",
                                         client_id="Client_id")

        assert ratr["grant_type"] == "refresh_token"
        assert ratr["refresh_token"] == "ababababab"
        assert ratr["client_id"] == "Client_id"

        assert ratr.verify()


class TestErrorResponse(object):
    def test_omit(self):
        err = ErrorResponse(error="invalid_request",
                            error_description="Something was missing",
                            error_uri="http://example.com/error_message.html")

        ue_str = err.to_urlencoded()
        del err["error_uri"]
        ueo_str = err.to_urlencoded()

        assert ue_str != ueo_str
        assert "error_message" not in ueo_str
        assert "error_message" in ue_str

    def test_missing_required(self):
        err = ErrorResponse()
        assert "error" not in err

        with pytest.raises(MissingRequiredAttribute):
            err.to_urlencoded()


@pytest.mark.parametrize("keytype,alg", [
    ('RSA', 'RS256'),
    ('EC', 'ES256')
])
def test_to_jwt(keytype, alg):
    msg = Message(a='foo', b='bar', c='tjoho')
    _jwt = msg.to_jwt(KEYJAR.get_signing_key(keytype, ''), alg)
    msg1 = Message().from_jwt(_jwt, KEYJAR.get_signing_key(keytype, ''))
    assert msg1 == msg


@pytest.mark.parametrize("keytype,alg,enc", [
    ('RSA', 'RSA1_5', 'A128CBC-HS256'),
    ('EC', 'ECDH-ES', 'A128GCM'),
])
def test_to_jwe(keytype, alg, enc):
    msg = Message(a='foo', b='bar', c='tjoho')
    _jwe = msg.to_jwe(KEYJAR.get_encrypt_key(keytype, ''), alg=alg, enc=enc)
    msg1 = Message().from_jwe(_jwe, KEYJAR.get_encrypt_key(keytype, ''))
    assert msg1 == msg


def test_to_dict_with_message_obj():
    content = Message(a={'a': {'foo': {'bar': [{'bat': []}]}}})
    _dict = content.to_dict(lev=0)
    content_fixture = {'a': {'a': {'foo': {'bar': [{'bat': []}]}}}}
    assert _dict == content_fixture


def test_to_dict_with_raw_types():
    msg = Message(c_default=[])
    content_fixture = {'c_default': []}
    _dict = msg.to_dict(lev=1)
    assert _dict == content_fixture


def test_get_verify_keys_no_kid_multiple_keys():
    msg = Message()
    header = {'alg': 'RS256'}
    keys = []
    msg.get_verify_keys(KEYJARS['A'], keys, {'iss': 'A'}, header, {})
    assert keys == []


def test_get_verify_keys_no_kid_single_key():
    msg = Message()
    header = {'alg': 'RS256'}
    keys = []
    msg.get_verify_keys(IKEYJAR, keys, {'iss': 'issuer'}, header, {})
    assert len(keys) == 1


def test_get_verify_keys_no_kid_multiple_keys_no_kid_issuer():
    msg = Message()
    header = {'alg': 'RS256'}
    keys = []

    a_kids = [k.kid for k in
              KEYJARS['A'].get_verify_key(owner='A', key_type='RSA')]
    no_kid_issuer = {'A': a_kids}

    msg.get_verify_keys(KEYJARS['A'], keys, {'iss': 'A'}, header, {},
                        no_kid_issuer=no_kid_issuer)
    assert len(keys) == 3
    assert set([k.kid for k in keys]) == set(a_kids)


def test_get_verify_keys_no_kid_multiple_keys_no_kid_issuer_lim():
    msg = Message()
    header = {'alg': 'RS256'}
    keys = []

    a_kids = [k.kid for k in
              KEYJARS['A'].get_verify_key(owner='A', key_type='RSA')]
    # get rid of one kid
    a_kids = a_kids[:-1]
    no_kid_issuer = {'A': a_kids}

    msg.get_verify_keys(KEYJARS['A'], keys, {'iss': 'A'}, header, {},
                        no_kid_issuer=no_kid_issuer)
    assert len(keys) == 2
    assert set([k.kid for k in keys]) == set(a_kids)


def test_get_verify_keys_matching_kid():
    msg = Message()
    a_kids = [k.kid for k in
              KEYJARS['A'].get_verify_key(owner='A', key_type='RSA')]
    header = {'alg': 'RS256', 'kid': a_kids[0]}
    keys = []
    msg.get_verify_keys(KEYJARS['A'], keys, {'iss': 'A'}, header, {})
    assert len(keys) == 1
    assert keys[0].kid == a_kids[0]


def test_get_verify_keys_no_matching_kid():
    msg = Message()
    header = {'alg': 'RS256', 'kid': 'aaaaaaa'}
    keys = []
    msg.get_verify_keys(KEYJARS['A'], keys, {'iss': 'A'}, header, {})
    assert keys == []
