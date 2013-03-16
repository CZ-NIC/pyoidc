# -*- coding: utf-8 -*-
__author__ = 'rohe0002'

import json

from oic.oic.message import ProviderConfigurationResponse
from oic.oic.message import msg_ser
from oic.oic.message import claims_ser
from oic.oic.message import RegistrationRequest
from oic.oic.message import IDTokenClaim
from oic.oic.message import UserInfoClaim
from oic.oic.message import userinfo_deser
from oic.oic.message import claims_deser
from oic.oic.message import AddressClaim
from oic.oic.message import address_deser
from oic.oic.message import Claims
from oic.oic.message import idtokenclaim_deser


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_ProviderConfigurationResponse():
    resp = {
        "authorization_endpoint": "https://server.example.com/connect/authorize",
        "issuer" : "https://server.example.com",
        "token_endpoint": "https://server.example.com/connect/token",
        "token_endpoint_auth_types_supported": ["client_secret_basic", "private_key_jwt"],
        "userinfo_endpoint": "https://server.example.com/connect/user",
        "check_id_endpoint": "https://server.example.com/connect/check_id",
        "refresh_session_endpoint": "https://server.example.com/connect/refresh_session",
        "end_session_endpoint": "https://server.example.com/connect/end_session",
        "jwk_url": "https://server.example.com/jwk.json",
        "registration_endpoint": "https://server.example.com/connect/register",
        "scopes_supported": ["openid", "profile", "email", "address", "phone"],
        "response_types_supported": ["code", "code id_token", "token id_token"],
        "acrs_supported": ["1","2","http://id.incommon.org/assurance/bronze"],
        "user_id_types_supported": ["public", "pairwise"],
        "userinfo_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW", "RSA1_5"],
        "id_token_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW", "RSA1_5"],
        "request_object_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW", "RSA1_5"]
    }

    pcr = ProviderConfigurationResponse().deserialize(json.dumps(resp), "json")

    assert _eq(pcr["user_id_types_supported"], ["public", "pairwise"])
    assert _eq(pcr["acrs_supported"], ["1", "2",
                                    "http://id.incommon.org/assurance/bronze"])


def test_idtokenclaim_deser():
    claims = Claims(weather={"acr": "2"})
    pre = IDTokenClaim(claims=claims, max_age=3600)
    idt = idtokenclaim_deser(pre.to_json(), sformat="json")
    assert _eq(idt.keys(), ['claims', "max_age"])


def test_userinfo_deser():
    CLAIM = Claims(name={"essential": True}, nickname=None,
                   email={"essential": True},
                   email_verified={"essential": True}, picture=None)

    pre_uic = UserInfoClaim(claims=CLAIM, format="signed")

    uic = userinfo_deser(pre_uic.to_json(), sformat="json")
    assert _eq(uic.keys(), ["claims", "format"])

def test_claims_deser():
    pre = Claims(name={"essential": True}, nickname=None,
                   email={"essential": True},
                   email_verified={"essential": True}, picture=None)

    claims = claims_deser(pre.to_json(), sformat="json")
    assert _eq(claims.keys(), ['name', 'nickname', 'email', 'email_verified',
                               'picture'])

    claims = claims_deser(pre.to_dict(), sformat="dict")
    assert _eq(claims.keys(), ['name', 'nickname', 'email', 'email_verified',
                           'picture'])

def test_address_deser():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea",
                       country="Sweden")

    adc = address_deser(pre.to_json(), sformat="json")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])

    adc = address_deser(pre.to_dict(), sformat="json")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])


def test_msg_ser_json():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea",
                       country="Sweden")

    ser = msg_ser(pre, "json")

    adc = address_deser(ser, "json")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])

def test_msg_ser_urlencoded():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea",
                       country="Sweden")

    ser = msg_ser(pre, "urlencoded")

    adc = address_deser(ser, "urlencoded")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])

def test_msg_ser_dict():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea",
                       country="Sweden")

    ser = msg_ser(pre, "dict")

    adc = address_deser(ser, "dict")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])

def test_msg_ser_dictionary():
    pre = {"street_address":"Kasamark 114", "locality":"Umea",
           "country":"Sweden"}

    ser = msg_ser(pre, "dict")

    adc = address_deser(ser, "dict")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])


CLAIMS = Claims(name={"essential": True}, nickname=None,
                email={"essential": True},
                email_verified={"essential": True}, picture=None)

def test_claims_ser_json():
    claims = claims_deser(claims_ser(CLAIMS, "json"), sformat="json")
    assert _eq(claims.keys(), ['name', 'nickname', 'email', 'email_verified',
                           'picture'])

def test_claims_ser_urlencoded():
    claims = claims_deser(claims_ser(CLAIMS, "urlencoded"), sformat="urlencoded")
    assert _eq(claims.keys(), ['name', 'nickname', 'email', 'email_verified',
                               'picture'])


def test_claims_ser_urlencoded_dict():
    pass

def test_registration_request():
    req = RegistrationRequest(operation="register", default_max_age=10,
                              require_auth_time=True, default_acr="foo",
                              application_type="web",
                              redirect_uris=["https://example.com/authz_cb"])
    js = req.to_json()
    print js
    assert js == '{"redirect_uris": ["https://example.com/authz_cb"], "application_type": "web", "default_acr": "foo", "require_auth_time": true, "operation": "register", "default_max_age": 10}'
    ue = req.to_urlencoded()
    print ue
    assert ue == 'redirect_uris=https%3A%2F%2Fexample.com%2Fauthz_cb&application_type=web&default_acr=foo&require_auth_time=True&operation=register&default_max_age=10'
