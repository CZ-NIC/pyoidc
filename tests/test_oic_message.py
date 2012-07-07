# -*- coding: utf-8 -*-
__author__ = 'rohe0002'

import json

from oic.oic.message import ProviderConfigurationResponse, msg_ser, msg_list_ser, claims_ser, RegistrationRequest
from oic.oic.message import IDTokenClaim
from oic.oic.message import UserInfoClaim
from oic.oic.message import userinfo_deser
from oic.oic.message import claims_deser
from oic.oic.message import AddressClaim
from oic.oic.message import address_deser
from oic.oic.message import keyobj_list_deser
#from oic.oic.message import AccessTokenResponse
from oic.oic.message import Claims
from oic.oic.message import idtokenclaim_deser
from oic.oic.message import SWDServiceRedirect
from oic.oic.message import JWKEllipticKeyObject
from oic.oic.message import JWKRSAKeyObject
from oic.oic.message import JWKKeyObject
from oic.oic.message import IssuerResponse


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

def test_iss():
    swd = SWDServiceRedirect(location="https://example.net")
    ir = IssuerResponse(SWD_service_redirect=swd)
    res = ir.serialize(method="json")

    assert res == '{"SWD_service_redirect": {"location": "https://example.net"}}'

def test_JWKEllipticKeyObject():
    jeko = JWKEllipticKeyObject(algorithm="EC", curve="P-256",
                   x="MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                   y="4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                   use="encryption", keyid="1")

    assert jeko["keyid"] == "1"
    assert jeko["use"] == "encryption"
    assert jeko["curve"] == "P-256"

def test_JWKRSAKeyObject():
    jrsa = JWKRSAKeyObject(algorithm="RSA", exponent="AQAB",
                           keyid="2011-04-29",
                   modulus="0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    )

    assert jrsa["algorithm"] == "RSA"
    assert jrsa["exponent"] == "AQAB"

def test_JWKKeyObject():
    jwk = JWKKeyObject(algorithm="RSA", exponent="AQAB", keyid="2011-04-29",
                    modulus="0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")

    assert _eq(jwk.keys(), ['keyid', 'algorithm', 'modulus', 'exponent'])

def test_idtokenclaim_deser():
    claims = Claims(weather={"acr": "2"})
    pre = IDTokenClaim(claims=claims, max_age=3600)
    idt = idtokenclaim_deser(pre.to_json(), format="json")
    assert _eq(idt.keys(), ['claims', "max_age"])


def test_userinfo_deser():
    CLAIM = Claims(name={"essential": True}, nickname=None,
                   email={"essential": True},
                   email_verified={"essential": True}, picture=None)

    pre_uic = UserInfoClaim(claims=CLAIM, format="signed")

    uic = userinfo_deser(pre_uic.to_json(), format="json")
    assert _eq(uic.keys(), ["claims", "format"])

def test_claims_deser():
    pre = Claims(name={"essential": True}, nickname=None,
                   email={"essential": True},
                   email_verified={"essential": True}, picture=None)

    claims = claims_deser(pre.to_json(), format="json")
    assert _eq(claims.keys(), ['name', 'nickname', 'email', 'email_verified',
                               'picture'])

    claims = claims_deser(pre.to_dict(), format="dict")
    assert _eq(claims.keys(), ['name', 'nickname', 'email', 'email_verified',
                           'picture'])

def test_address_deser():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea",
                       country="Sweden")

    adc = address_deser(pre.to_json(), format="json")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])

    adc = address_deser(pre.to_dict(), format="json")
    assert _eq(adc.keys(), ['street_address', 'locality', 'country'])

def test_keyobj_list_deser():
    jko1 = JWKKeyObject(algorithm="RSA", exponent="AQAB", keyid="2011-04-29",
                       modulus="0vx7agoebGcQSuuPiLJ")
    jko2 = JWKKeyObject(algorithm="RSA", exponent="AQAB", keyid="2012-05-29",
                        modulus="Marsupilami")

    jkos = keyobj_list_deser([jko1.to_json(), jko2.to_json()], "json")

    assert len(jkos) == 2
    assert isinstance(jkos[0], JWKKeyObject)
    assert isinstance(jkos[1], JWKKeyObject)

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

def test_msg_list_ser():
    jko1 = JWKKeyObject(algorithm="RSA", exponent="AQAB", keyid="2011-04-29",
                        modulus="0vx7agoebGcQSuuPiLJ")
    jko2 = JWKKeyObject(algorithm="RSA", exponent="AQAB", keyid="2012-05-29",
                        modulus="Marsupilami")

    ser = msg_list_ser([jko1, jko2], "dict")

    jkos = keyobj_list_deser(ser, "dict")
    assert len(jkos) == 2
    assert isinstance(jkos[0], JWKKeyObject)
    assert isinstance(jkos[1], JWKKeyObject)

CLAIMS = Claims(name={"essential": True}, nickname=None,
                 email={"essential": True},
                 email_verified={"essential": True}, picture=None)

def test_claims_ser_json():
    claims = claims_deser(claims_ser(CLAIMS, "json"), format="json")
    assert _eq(claims.keys(), ['name', 'nickname', 'email', 'email_verified',
                           'picture'])

def test_claims_ser_urlencoded():
    claims = claims_deser(claims_ser(CLAIMS, "urlencoded"), format="urlencoded")
    assert _eq(claims.keys(), ['name', 'nickname', 'email', 'email_verified',
                               'picture'])


def test_claims_ser_urlencoded_dict():
    pass

def test_registration_request():
    req = RegistrationRequest(type="client_associate", default_max_age=10,
                              require_auth_time=True, default_acr="foo")
    js = req.to_json()
    print js
    assert js == '{"require_auth_time": true, "default_acr": "foo", "type": "client_associate", "default_max_age": 10}'
    ue = req.to_urlencoded()
    print ue
    assert ue == 'default_acr=foo&type=client_associate&default_max_age=10&require_auth_time=True'
