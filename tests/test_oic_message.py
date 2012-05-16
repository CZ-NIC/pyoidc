from oic.oauth2.message import by_schema

__author__ = 'rohe0002'

import json

from oic.oic.message import ProviderConfigurationResponse, AccessTokenResponse
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
