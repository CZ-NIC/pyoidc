# -*- coding: utf-8 -*-
from jwkest import BadSignature
from jwkest.jwk import SYMKey
from oic.oauth2 import WrongSigningAlgorithm

__author__ = 'rohe0002'

import json

from oic.oic.message import ProviderConfigurationResponse, RegistrationResponse, AuthorizationRequest, \
    IdToken, AccessTokenResponse
from oic.oic.message import msg_ser
from oic.oic.message import claims_ser
from oic.oic.message import RegistrationRequest
from oic.oic.message import claims_deser
from oic.oic.message import AddressClaim
from oic.oic.message import address_deser
from oic.oic.message import Claims

from utils_for_tests import _eq


def test_ProviderConfigurationResponse():
    resp = {
        "authorization_endpoint": "https://server.example.com/connect/authorize",
        "issuer": "https://server.example.com",
        "token_endpoint": "https://server.example.com/connect/token",
        "token_endpoint_auth_methods_supported": ["client_secret_basic",
                                                  "private_key_jwt"],
        "userinfo_endpoint": "https://server.example.com/connect/user",
        "check_id_endpoint": "https://server.example.com/connect/check_id",
        "refresh_session_endpoint": "https://server.example.com/connect/refresh_session",
        "end_session_endpoint": "https://server.example.com/connect/end_session",
        "jwk_url": "https://server.example.com/jwk.json",
        "registration_endpoint": "https://server.example.com/connect/register",
        "scopes_supported": ["openid", "profile", "email", "address", "phone"],
        "response_types_supported": ["code", "code id_token", "token id_token"],
        "acrs_supported": ["1", "2", "http://id.incommon.org/assurance/bronze"],
        "user_id_types_supported": ["public", "pairwise"],
        "userinfo_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW",
                                    "RSA1_5"],
        "id_token_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW",
                                    "RSA1_5"],
        "request_object_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW",
                                          "RSA1_5"]
    }

    pcr = ProviderConfigurationResponse().deserialize(json.dumps(resp), "json")

    assert _eq(pcr["user_id_types_supported"], ["public", "pairwise"])
    assert _eq(pcr["acrs_supported"],
               ["1", "2", "http://id.incommon.org/assurance/bronze"])


def test_example_response():
    resp = {
        "version": "3.0",
        "issuer": "https://server.example.com",
        "authorization_endpoint":
            "https://server.example.com/connect/authorize",
        "token_endpoint": "https://server.example.com/connect/token",
        "token_endpoint_auth_methods_supported": ["client_secret_basic",
                                                  "private_key_jwt"],
        "token_endpoint_alg_values_supported": ["RS256", "ES256"],
        "userinfo_endpoint": "https://server.example.com/connect/userinfo",
        "check_session_iframe":
            "https://server.example.com/connect/check_session",
        "end_session_endpoint":
            "https://server.example.com/connect/end_session",
        "jwks_uri": "https://server.example.com/jwks.json",
        "registration_endpoint": "https://server.example.com/connect/register",
        "scopes_supported": ["openid", "profile", "email", "address",
                             "phone", "offline_access"],
        "response_types_supported": ["code", "code id_token", "id_token",
                                     "token id_token"],
        "acr_values_supported": ["urn:mace:incommon:iap:silver",
                                 "urn:mace:incommon:iap:bronze"],
        "subject_types_supported": ["public", "pairwise"],
        "userinfo_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
        "userinfo_encryption_alg_values_supported": ["RSA1_5", "A128KW"],
        "userinfo_encryption_enc_values_supported": ["A128CBC+HS256",
                                                     "A128GCM"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
        "id_token_encryption_alg_values_supported": ["RSA1_5", "A128KW"],
        "id_token_encryption_enc_values_supported": ["A128CBC+HS256",
                                                     "A128GCM"],
        "request_object_signing_alg_values_supported": ["none", "RS256",
                                                        "ES256"],
        "display_values_supported": ["page", "popup"],
        "claim_types_supported": ["normal", "distributed"],
        "claims_supported": ["sub", "iss", "auth_time", "acr", "name",
                             "given_name", "family_name", "nickname", "profile",
                             "picture", "website", "email", "email_verified",
                             "locale", "zoneinfo",
                             "http://example.info/claims/groups"],
        "claims_parameter_supported": True,
        "service_documentation":
            "http://server.example.com/connect/service_documentation.html",
        "ui_locales_supported": ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"]
    }

    pcr = ProviderConfigurationResponse().deserialize(json.dumps(resp), "json")
    rk = resp.keys()
    # parameters with default value if missing
    rk.extend(["grant_types_supported", "request_parameter_supported",
               "request_uri_parameter_supported",
               "require_request_uri_registration"])
    rk.sort()
    pk = pcr.keys()
    pk.sort()
    print rk
    print pk
    assert _eq(pk, rk)


def test_client_registration():
    msg = {
        "application_type": "web",
        "redirect_uris": ["https://client.example.org/callback",
                          "https://client.example.org/callback2"],
        "client_name": "My Example",
        "client_name#ja-Jpan-JP": "クライアント名",
        "logo_uri": "https://client.example.org/logo.png",
        "subject_type": "pairwise",
        "sector_identifier_uri":
            "https://other.example.net/file_of_redirect_uris.json",
        "token_endpoint_auth_method": "client_secret_basic",
        "jwks_uri": "https://client.example.org/my_public_keys.jwks",
        "userinfo_encrypted_response_alg": "RSA1_5",
        "userinfo_encrypted_response_enc": "A128CBC+HS256",
        "contacts": ["ve7jtb@example.org", "mary@example.org"],
        "request_uris": [
            "https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"]
    }

    reg = RegistrationRequest().deserialize(json.dumps(msg), "json")

    assert _eq(msg.keys(), reg.keys())


def test_client_response():
    msg = {
        "client_id": "s6BhdRkqt3",
        "client_secret": "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
        "client_secret_expires_at": 1577858400,
        "registration_access_token": "this.is.an.access.token.value.ffx83",
        "registration_client_uri":
            "https://server.example.com/connect/register?client_id=s6BhdRkqt3",
        "token_endpoint_auth_method": "client_secret_basic",
        "application_type": "web",
        "redirect_uris": ["https://client.example.org/callback",
                          "https://client.example.org/callback2"],
        "client_name": "My Example",
        "client_name#ja-Jpan-JP": "クライアント名",
        "logo_uri": "https://client.example.org/logo.png",
        "subject_type": "pairwise",
        "sector_identifier_uri":
            "https://other.example.net/file_of_redirect_uris.json",
        "jwks_uri": "https://client.example.org/my_public_keys.jwks",
        "userinfo_encrypted_response_alg": "RSA1_5",
        "userinfo_encrypted_response_enc": "A128CBC+HS256",
        "contacts": ["ve7jtb@example.org", "mary@example.org"],
        "request_uris": [
            "https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"]
    }

    resp = RegistrationResponse().deserialize(json.dumps(msg), "json")

    assert _eq(msg.keys(), resp.keys())


def test_authz_request():
    example = "https://server.example.com/authorize?response_type=token%20id_token&client_id=0acf77d4-b486-4c99-bd76-074ed6a64ddf&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj"

    req = AuthorizationRequest().deserialize(example.split("?")[1],
                                             "urlencoded")

    print req.keys()
    assert _eq(req.keys(), ['nonce', 'state', 'redirect_uri', 'response_type',
                            'client_id', 'scope'])

    assert req["response_type"] == ["token", "id_token"]
    assert req["scope"] == ["openid", "profile"]


def test_claims_deser_0():
    _dic = {
        "userinfo": {
            "given_name": {"essential": True},
            "nickname": None,
            "email": {"essential": True},
            "email_verified": {"essential": True},
            "picture": None,
            "http://example.info/claims/groups": None
        },
        "id_token": {
            "auth_time": {"essential": True},
            "acr": {"values": ["urn:mace:incommon:iap:silver"]}
        }
    }

    claims = claims_deser(json.dumps(_dic), sformat="json")
    assert _eq(claims.keys(), ["userinfo", "id_token"])


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
    pre = {"street_address": "Kasamark 114", "locality": "Umea",
           "country": "Sweden"}

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


def test_registration_request():
    req = RegistrationRequest(operation="register", default_max_age=10,
                              require_auth_time=True, default_acr="foo",
                              application_type="web",
                              redirect_uris=["https://example.com/authz_cb"])
    js = req.to_json()
    js_obj = json.loads(js)
    expected_js_obj = {"redirect_uris": ["https://example.com/authz_cb"], "application_type": "web", "default_acr": "foo", "require_auth_time": True, "operation": "register", "default_max_age": 10}
    assert js_obj == expected_js_obj
    ue = req.to_urlencoded()
    ue_splits = ue.split('&')
    expected_ue_splits = 'redirect_uris=https%3A%2F%2Fexample.com%2Fauthz_cb&application_type=web&default_acr=foo&require_auth_time=True&operation=register&default_max_age=10'.split('&')
    assert _eq(ue_splits, expected_ue_splits)


def test_faulty_idtoken():
    idval = {'nonce': 'KUEYfRM2VzKDaaKD', 'sub': 'EndUserSubject',
             'iss': 'https://alpha.cloud.nds.rub.de', 'exp': 1420823073,
             'iat': 1420822473, 'aud': 'TestClient'}
    idts = IdToken(**idval)
    key = SYMKey(key="TestPassword")
    _signed_jwt = idts.to_jwt(key=[key], algorithm="HS256")

    #Mess with the signed id_token
    p = _signed_jwt.split(".")
    p[2] = "aaa"
    _faulty_signed_jwt = ".".join(p)

    _info = {"access_token": "accessTok", "id_token": _faulty_signed_jwt,
             "token_type": "Bearer", "expires_in": 3600}

    # Should fail
    at = AccessTokenResponse(**_info)
    try:
        at.verify(key=[key])
    except BadSignature:
        pass
    else:
        raise


def test_wrong_alg():
    idval = {'nonce': 'KUEYfRM2VzKDaaKD', 'sub': 'EndUserSubject',
             'iss': 'https://alpha.cloud.nds.rub.de', 'exp': 1420823073,
             'iat': 1420822473, 'aud': 'TestClient'}
    idts = IdToken(**idval)
    key = SYMKey(key="TestPassword")
    _signed_jwt = idts.to_jwt(key=[key], algorithm="HS256")

    _info = {"access_token": "accessTok", "id_token": _signed_jwt,
             "token_type": "Bearer", "expires_in": 3600}

    at = AccessTokenResponse(**_info)
    try:
        at.verify(key=[key], algs={"sign": "HS512"})
    except WrongSigningAlgorithm:
        pass


if __name__ == "__main__":
    test_wrong_alg()