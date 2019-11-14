import json
import os
import sys
from urllib.parse import parse_qs
from urllib.parse import urlencode

import pytest
from jwkest import BadSignature
from jwkest.jwk import SYMKey
from jwkest.jws import left_hash

from oic import rndstr
from oic.exception import MessageException
from oic.exception import NotForMe
from oic.oauth2.message import MissingRequiredAttribute
from oic.oauth2.message import MissingRequiredValue
from oic.oauth2.message import WrongSigningAlgorithm
from oic.oic.message import BACK_CHANNEL_LOGOUT_EVENT
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AddressClaim
from oic.oic.message import AtHashError
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AuthorizationResponse
from oic.oic.message import BackChannelLogoutRequest
from oic.oic.message import CHashError
from oic.oic.message import Claims
from oic.oic.message import FrontChannelLogoutRequest
from oic.oic.message import IdToken
from oic.oic.message import LogoutToken
from oic.oic.message import OpenIDSchema
from oic.oic.message import ProviderConfigurationResponse
from oic.oic.message import RegistrationRequest
from oic.oic.message import RegistrationResponse
from oic.oic.message import VerificationError
from oic.oic.message import address_deser
from oic.oic.message import claims_deser
from oic.oic.message import claims_ser
from oic.oic.message import msg_ser
from oic.oic.message import verify_id_token
from oic.utils import time_util
from oic.utils.jwt import JWT
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from oic.utils.time_util import utc_time_sans_frac

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

__author__ = "rohe0002"


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_openidschema():
    inp = '{"middle_name":null, "updated_at":"20170328081544", "sub":"abc"}'
    ois = OpenIDSchema().from_json(inp)
    assert ois.verify() is False


@pytest.mark.parametrize(
    "json_param",
    [
        '{"middle_name":"fo", "updated_at":"20170328081544Z", "sub":"abc"}',
        '{"middle_name":true, "updated_at":"20170328081544", "sub":"abc"}',
        '{"middle_name":"fo", "updated_at":false, "sub":"abc"}',
        '{"middle_name":"fo", "updated_at":"20170328081544Z", "sub":true}',
    ],
)
def test_openidschema_from_json(json_param):
    with pytest.raises(MessageException):
        OpenIDSchema().from_json(json_param)


@pytest.mark.parametrize(
    "json_param",
    [
        '{"email_verified":false, "email":"foo@example.com", "sub":"abc"}',
        '{"email_verified":true, "email":"foo@example.com", "sub":"abc"}',
        '{"phone_number_verified":false, "phone_number":"+1 555 200000", '
        '"sub":"abc"}',
        '{"phone_number_verified":true, "phone_number":"+1 555 20000", ' '"sub":"abc"}',
    ],
)
def test_claim_booleans(json_param):
    assert OpenIDSchema().from_json(json_param)


@pytest.mark.parametrize(
    "json_param",
    [
        '{"email_verified":"Not", "email":"foo@example.com", "sub":"abc"}',
        '{"email_verified":"Sure", "email":"foo@example.com", "sub":"abc"}',
        '{"phone_number_verified":"Not", "phone_number":"+1 555 200000", '
        '"sub":"abc"}',
        '{"phone_number_verified":"Sure", "phone_number":"+1 555 20000", '
        '"sub":"abc"}',
    ],
)
def test_claim_not_booleans(json_param):
    with pytest.raises(MessageException):
        OpenIDSchema().from_json(json_param)


def test_claims_deser():
    _dic = {
        "userinfo": {
            "given_name": {"essential": True},
            "nickname": None,
            "email": {"essential": True},
            "email_verified": {"essential": True},
            "picture": None,
            "http://example.info/claims/groups": None,
        },
        "id_token": {
            "auth_time": {"essential": True},
            "acr": {"values": ["urn:mace:incommon:iap:silver"]},
        },
    }

    claims = claims_deser(json.dumps(_dic), sformat="json")
    assert _eq(claims.keys(), ["userinfo", "id_token"])


def test_claims_deser_dict():
    pre = Claims(
        name={"essential": True},
        nickname=None,
        email={"essential": True},
        email_verified={"essential": True},
        picture=None,
    )

    claims = claims_deser(pre.to_json(), sformat="json")
    assert _eq(
        claims.keys(), ["name", "nickname", "email", "email_verified", "picture"]
    )

    claims = claims_deser(pre.to_dict(), sformat="dict")
    assert _eq(
        claims.keys(), ["name", "nickname", "email", "email_verified", "picture"]
    )


def test_address_deser():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea", country="Sweden")

    adc = address_deser(pre.to_json(), sformat="json")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])

    adc = address_deser(pre.to_dict(), sformat="json")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])


def test_msg_ser_json():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea", country="Sweden")

    ser = msg_ser(pre, "json")

    adc = address_deser(ser, "json")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])


def test_msg_ser_urlencoded():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea", country="Sweden")

    ser = msg_ser(pre, "urlencoded")

    adc = address_deser(ser, "urlencoded")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])


def test_msg_ser_dict():
    pre = AddressClaim(street_address="Kasamark 114", locality="Umea", country="Sweden")

    ser = msg_ser(pre, "dict")

    adc = address_deser(ser, "dict")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])


def test_msg_ser_from_dict():
    pre = {"street_address": "Kasamark 114", "locality": "Umea", "country": "Sweden"}

    ser = msg_ser(pre, "dict")

    adc = address_deser(ser, "dict")
    assert _eq(adc.keys(), ["street_address", "locality", "country"])


def test_claims_ser_json():
    claims = Claims(
        name={"essential": True},
        nickname=None,
        email={"essential": True},
        email_verified={"essential": True},
        picture=None,
    )
    claims = claims_deser(claims_ser(claims, "json"), sformat="json")
    assert _eq(
        claims.keys(), ["name", "nickname", "email", "email_verified", "picture"]
    )


class TestProviderConfigurationResponse(object):
    def test_deserialize(self):
        resp = {
            "authorization_endpoint": "https://server.example.com/connect/authorize",
            "issuer": "https://server.example.com",
            "token_endpoint": "https://server.example.com/connect/token",
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "private_key_jwt",
            ],
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
            "userinfo_algs_supported": [
                "HS256",
                "RS256",
                "A128CBC",
                "A128KW",
                "RSA1_5",
            ],
            "id_token_algs_supported": [
                "HS256",
                "RS256",
                "A128CBC",
                "A128KW",
                "RSA1_5",
            ],
            "request_object_algs_supported": [
                "HS256",
                "RS256",
                "A128CBC",
                "A128KW",
                "RSA1_5",
            ],
        }

        pcr = ProviderConfigurationResponse().deserialize(json.dumps(resp), "json")

        assert _eq(pcr["user_id_types_supported"], ["public", "pairwise"])
        assert _eq(
            pcr["acrs_supported"], ["1", "2", "http://id.incommon.org/assurance/bronze"]
        )

    def test_example_response(self):
        resp = {
            "version": "3.0",
            "issuer": "https://server.example.com",
            "authorization_endpoint": "https://server.example.com/connect/authorize",
            "token_endpoint": "https://server.example.com/connect/token",
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "private_key_jwt",
            ],
            "token_endpoint_alg_values_supported": ["RS256", "ES256"],
            "userinfo_endpoint": "https://server.example.com/connect/userinfo",
            "check_session_iframe": "https://server.example.com/connect/check_session",
            "end_session_endpoint": "https://server.example.com/connect/end_session",
            "jwks_uri": "https://server.example.com/jwks.json",
            "registration_endpoint": "https://server.example.com/connect/register",
            "scopes_supported": [
                "openid",
                "profile",
                "email",
                "address",
                "phone",
                "offline_access",
            ],
            "response_types_supported": [
                "code",
                "code id_token",
                "id_token",
                "token id_token",
            ],
            "acr_values_supported": [
                "urn:mace:incommon:iap:silver",
                "urn:mace:incommon:iap:bronze",
            ],
            "subject_types_supported": ["public", "pairwise"],
            "userinfo_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
            "userinfo_encryption_alg_values_supported": ["RSA1_5", "A128KW"],
            "userinfo_encryption_enc_values_supported": ["A128CBC+HS256", "A128GCM"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
            "id_token_encryption_alg_values_supported": ["RSA1_5", "A128KW"],
            "id_token_encryption_enc_values_supported": ["A128CBC+HS256", "A128GCM"],
            "request_object_signing_alg_values_supported": ["none", "RS256", "ES256"],
            "display_values_supported": ["page", "popup"],
            "claim_types_supported": ["normal", "distributed"],
            "claims_supported": [
                "sub",
                "iss",
                "auth_time",
                "acr",
                "name",
                "given_name",
                "family_name",
                "nickname",
                "profile",
                "picture",
                "website",
                "email",
                "email_verified",
                "locale",
                "zoneinfo",
                "http://example.info/claims/groups",
            ],
            "claims_parameter_supported": True,
            "service_documentation": "http://server.example.com/connect/service_documentation.html",
            "ui_locales_supported": ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"],
        }

        pcr = ProviderConfigurationResponse().deserialize(json.dumps(resp), "json")
        rk = list(resp.keys())
        # parameters with default value if missing
        rk.extend(
            [
                "grant_types_supported",
                "request_parameter_supported",
                "request_uri_parameter_supported",
                "require_request_uri_registration",
                "frontchannel_logout_supported",
                "frontchannel_logout_session_supported",
                "backchannel_logout_supported",
                "backchannel_logout_session_supported",
            ]
        )
        assert set(rk) == set(pcr.keys())

    @pytest.mark.parametrize(
        "required_param",
        [
            "issuer",
            "authorization_endpoint",
            "jwks_uri",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
        ],
    )
    def test_required_parameters(self, required_param):
        provider_config = {
            "issuer": "https://server.example.com",
            "authorization_endpoint": "https://server.example.com/connect/authorize",
            "jwks_uri": "https://server.example.com/jwks.json",
            "response_types_supported": [
                "code",
                "code id_token",
                "id_token",
                "token id_token",
            ],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
        }

        del provider_config[required_param]
        with pytest.raises(MissingRequiredAttribute):
            ProviderConfigurationResponse(**provider_config).verify()

    def test_token_endpoint_is_not_required_for_implicit_flow_only(self):
        provider_config = {
            "issuer": "https://server.example.com",
            "authorization_endpoint": "https://server.example.com/connect/authorize",
            "jwks_uri": "https://server.example.com/jwks.json",
            "response_types_supported": ["id_token", "token id_token"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
        }

        # should not raise an exception
        assert ProviderConfigurationResponse(**provider_config).verify()

    def test_token_endpoint_is_required_for_other_than_implicit_flow_only(self):
        provider_config = {
            "issuer": "https://server.example.com",
            "authorization_endpoint": "https://server.example.com/connect/authorize",
            "jwks_uri": "https://server.example.com/jwks.json",
            "response_types_supported": ["code", "id_token"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
        }

        with pytest.raises(MissingRequiredAttribute):
            ProviderConfigurationResponse(**provider_config).verify()


class TestRegistrationRequest(object):
    def test_deserialize(self):
        msg = {
            "application_type": "web",
            "redirect_uris": [
                "https://client.example.org/callback",
                "https://client.example.org/callback2",
            ],
            "client_name": "My Example",
            "client_name#ja-Jpan-JP": "クライアント名",
            "logo_uri": "https://client.example.org/logo.png",
            "subject_type": "pairwise",
            "sector_identifier_uri": "https://other.example.net/file_of_redirect_uris.json",
            "token_endpoint_auth_method": "client_secret_basic",
            "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "userinfo_encrypted_response_alg": "RSA1_5",
            "userinfo_encrypted_response_enc": "A128CBC+HS256",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
            "request_uris": [
                "https://client.example.org/rf.txt"
                "#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"
            ],
        }

        reg = RegistrationRequest().deserialize(json.dumps(msg), "json")
        assert _eq(list(msg.keys()) + ["response_types"], reg.keys())

    def test_registration_request(self):
        req = RegistrationRequest(
            operation="register",
            default_max_age=10,
            require_auth_time=True,
            default_acr="foo",
            application_type="web",
            redirect_uris=["https://example.com/authz_cb"],
        )
        js = req.to_json()
        js_obj = json.loads(js)
        expected_js_obj = {
            "redirect_uris": ["https://example.com/authz_cb"],
            "application_type": "web",
            "default_acr": "foo",
            "require_auth_time": True,
            "operation": "register",
            "default_max_age": 10,
            "response_types": ["code"],
        }
        assert js_obj == expected_js_obj

        flattened_list_dict = {
            k: v[0] if isinstance(v, list) else v for k, v in expected_js_obj.items()
        }
        assert query_string_compare(req.to_urlencoded(), urlencode(flattened_list_dict))

    @pytest.mark.parametrize(
        "enc_param",
        [
            "request_object_encryption_enc",
            "id_token_encrypted_response_enc",
            "userinfo_encrypted_response_enc",
        ],
    )
    def test_registration_request_with_coupled_encryption_params(self, enc_param):
        registration_params = {
            "redirect_uris": ["https://example.com/authz_cb"],
            enc_param: "RS25asdasd6",
        }
        registration_req = RegistrationRequest(**registration_params)
        with pytest.raises(AssertionError):
            registration_req.verify()


class TestRegistrationResponse(object):
    def test_deserialize(self):
        msg = {
            "client_id": "s6BhdRkqt3",
            "client_secret": "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
            "client_secret_expires_at": 1577858400,
            "registration_access_token": "this.is.an.access.token.value.ffx83",
            "registration_client_uri": "https://server.example.com/connect/register?client_id"
            "=s6BhdRkqt3",
            "token_endpoint_auth_method": "client_secret_basic",
            "application_type": "web",
            "redirect_uris": [
                "https://client.example.org/callback",
                "https://client.example.org/callback2",
            ],
            "client_name": "My Example",
            "client_name#ja-Jpan-JP": "クライアント名",
            "logo_uri": "https://client.example.org/logo.png",
            "subject_type": "pairwise",
            "sector_identifier_uri": "https://other.example.net/file_of_redirect_uris.json",
            "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "userinfo_encrypted_response_alg": "RSA1_5",
            "userinfo_encrypted_response_enc": "A128CBC+HS256",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
            "request_uris": [
                "https://client.example.org/rf.txt"
                "#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"
            ],
        }

        resp = RegistrationResponse().deserialize(json.dumps(msg), "json")
        assert _eq(msg.keys(), resp.keys())


class TestAuthorizationRequest(object):
    def test_deserialize(self):
        query = (
            "response_type=token%20id_token&client_id=0acf77d4-b486-4c99"
            "-bd76-074ed6a64ddf&redirect_uri=https%3A%2F%2Fclient.example"
            ".com%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n"
            "-0S6_WzA2Mj"
        )

        req = AuthorizationRequest().deserialize(query, "urlencoded")

        assert _eq(
            req.keys(),
            ["nonce", "state", "redirect_uri", "response_type", "client_id", "scope"],
        )

        assert req["response_type"] == ["token", "id_token"]
        assert req["scope"] == ["openid", "profile"]

    def test_verify_no_scopes(self):
        args = {
            "client_id": "foobar",
            "redirect_uri": "http://foobar.example.com/oaclient",
            "response_type": "code",
        }
        ar = AuthorizationRequest(**args)
        with pytest.raises(MissingRequiredAttribute):
            ar.verify()


class TestAuthorizationResponse(object):
    def test_verify_token_type(self):
        args = {"access_token": "foobar", "token_type": "bearer"}
        ar = AuthorizationResponse(**args)
        ar.verify()

        args = {"access_token": "foobar"}
        ar = AuthorizationResponse(**args)
        with pytest.raises(MissingRequiredValue):
            ar.verify()


class TestAccessTokenResponse(object):
    def test_faulty_idtoken(self):
        _now = time_util.utc_time_sans_frac()
        idval = {
            "nonce": "KUEYfRM2VzKDaaKD",
            "sub": "EndUserSubject",
            "iss": "https://alpha.cloud.nds.rub.de",
            "exp": _now + 3600,
            "iat": _now,
            "aud": "TestClient",
        }
        idts = IdToken(**idval)
        key = SYMKey(key="TestPassword")
        _signed_jwt = idts.to_jwt(key=[key], algorithm="HS256")

        # Mess with the signed id_token
        p = _signed_jwt.split(".")
        p[2] = "aaa"
        _faulty_signed_jwt = ".".join(p)

        _info = {
            "access_token": "accessTok",
            "id_token": _faulty_signed_jwt,
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        at = AccessTokenResponse(**_info)
        with pytest.raises(BadSignature):
            at.verify(key=[key])

    def test_wrong_alg(self):
        _now = time_util.utc_time_sans_frac()
        idval = {
            "nonce": "KUEYfRM2VzKDaaKD",
            "sub": "EndUserSubject",
            "iss": "https://alpha.cloud.nds.rub.de",
            "exp": _now + 3600,
            "iat": _now,
            "aud": "TestClient",
        }
        idts = IdToken(**idval)
        key = SYMKey(key="TestPassword")
        _signed_jwt = idts.to_jwt(key=[key], algorithm="HS256")

        _info = {
            "access_token": "accessTok",
            "id_token": _signed_jwt,
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        at = AccessTokenResponse(**_info)
        with pytest.raises(WrongSigningAlgorithm):
            at.verify(key=[key], algs={"sign": "HS512"})

    def test_token_type(self):
        # lacks required token_type parameter
        _info = {"access_token": "accessTok", "id_token": "blabla"}
        at = AccessTokenResponse(**_info)
        with pytest.raises(MissingRequiredAttribute):
            at.verify()


def test_id_token():
    _now = time_util.utc_time_sans_frac()

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "at_hash": "L4Ign7TCAD_EppRbHAuCyw",
            "iat": _now,
            "exp": _now + 3600,
            "iss": "https://sso.qa.7pass.ctf.prosiebensat1.com",
        }
    )

    idt.verify()


def test_verify_id_token():
    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com",
        "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ",
        ["sig"],
    )
    packer = JWT(
        kj,
        sign_alg="HS256",
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        lifetime=3600,
    )
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    vidt = verify_id_token(
        msg,
        keyjar=kj,
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        client_id="554295ce3770612820620000",
    )
    assert vidt


def test_verify_id_token_wrong_issuer():
    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com",
        "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ",
        ["sig"],
    )
    packer = JWT(kj, sign_alg="HS256", iss="https://example.com/as", lifetime=3600)
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    with pytest.raises(ValueError):
        verify_id_token(
            msg,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


def test_verify_id_token_wrong_aud():
    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com",
        "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ",
        ["sig"],
    )
    packer = JWT(kj, sign_alg="HS256", iss="https://example.com/as", lifetime=3600)
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    with pytest.raises(ValueError):
        verify_id_token(
            msg,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="aaaaaaaaaaaaaaaaaaaa",
        )


def test_verify_id_token_mismatch_aud_azp():
    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "aaaaaaaaaaaaaaaaaaaa",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com",
        "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ",
        ["sig"],
    )
    packer = JWT(kj, sign_alg="HS256", iss="https://example.com/as", lifetime=3600)
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    with pytest.raises(ValueError):
        verify_id_token(
            msg,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="aaaaaaaaaaaaaaaaaaaa",
        )


def test_verify_id_token_c_hash():
    code = "AccessCode1"
    lhsh = left_hash(code)

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "c_hash": lhsh,
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com",
        "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ",
        ["sig"],
    )
    packer = JWT(
        kj,
        sign_alg="HS256",
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        lifetime=3600,
    )
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(code=code, id_token=_jws)
    verify_id_token(
        msg,
        check_hash=True,
        keyjar=kj,
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        client_id="554295ce3770612820620000",
    )


def test_verify_id_token_c_hash_fail():
    code = "AccessCode1"
    lhsh = left_hash(code)

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "c_hash": lhsh,
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com",
        "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ",
        ["sig"],
    )
    packer = JWT(
        kj,
        sign_alg="HS256",
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        lifetime=3600,
    )
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(code="AccessCode289", id_token=_jws)
    with pytest.raises(CHashError):
        verify_id_token(
            msg,
            check_hash=True,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


def test_verify_id_token_at_hash():
    token = "AccessTokenWhichCouldBeASignedJWT"
    lhsh = left_hash(token)

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "at_hash": lhsh,
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com",
        "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ",
        ["sig"],
    )
    packer = JWT(
        kj,
        sign_alg="HS256",
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        lifetime=3600,
    )
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(access_token=token, id_token=_jws)
    verify_id_token(
        msg,
        check_hash=True,
        keyjar=kj,
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        client_id="554295ce3770612820620000",
    )


def test_verify_id_token_at_hash_fail():
    token = "AccessTokenWhichCouldBeASignedJWT"
    token2 = "ACompletelyOtherAccessToken"
    lhsh = left_hash(token)

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "at_hash": lhsh,
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com",
        "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ",
        ["sig"],
    )
    packer = JWT(
        kj,
        sign_alg="HS256",
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        lifetime=3600,
    )
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(access_token=token2, id_token=_jws)
    with pytest.raises(AtHashError):
        verify_id_token(
            msg,
            check_hash=True,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


def test_verify_id_token_missing_at_hash():
    token = "AccessTokenWhichCouldBeASignedJWT"

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com",
        "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ",
        ["sig"],
    )
    packer = JWT(
        kj,
        sign_alg="HS256",
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        lifetime=3600,
    )
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(access_token=token, id_token=_jws)
    with pytest.raises(MissingRequiredAttribute):
        verify_id_token(
            msg,
            check_hash=True,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


def test_verify_id_token_missing_c_hash():
    code = "AccessCode1"

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com",
        "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ",
        ["sig"],
    )
    packer = JWT(
        kj,
        sign_alg="HS256",
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        lifetime=3600,
    )
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(code=code, id_token=_jws)
    with pytest.raises(MissingRequiredAttribute):
        verify_id_token(
            msg,
            check_hash=True,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


def test_verify_id_token_at_hash_and_chash():
    token = "AccessTokenWhichCouldBeASignedJWT"
    at_hash = left_hash(token)
    code = "AccessCode1"
    c_hash = left_hash(code)

    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
            "at_hash": at_hash,
            "c_hash": c_hash,
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com",
        "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ",
        ["sig"],
    )
    packer = JWT(
        kj,
        sign_alg="HS256",
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        lifetime=3600,
    )
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(access_token=token, id_token=_jws, code=code)
    verify_id_token(
        msg,
        check_hash=True,
        keyjar=kj,
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        client_id="554295ce3770612820620000",
    )


def test_verify_id_token_missing_iss():
    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com",
        "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ",
        ["sig"],
    )
    packer = JWT(kj, sign_alg="HS256", lifetime=3600)
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    with pytest.raises(MissingRequiredAttribute):
        verify_id_token(
            msg,
            check_hash=True,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


def test_verify_id_token_iss_not_in_keyjar():
    idt = IdToken(
        **{
            "sub": "553df2bcf909104751cfd8b2",
            "aud": ["5542958437706128204e0000", "554295ce3770612820620000"],
            "auth_time": 1441364872,
            "azp": "554295ce3770612820620000",
        }
    )

    kj = KeyJar()
    kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
    kj.add_symmetric(
        "https://sso.qa.7pass.ctf.prosiebensat1.com",
        "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ",
        ["sig"],
    )
    packer = JWT(kj, sign_alg="HS256", lifetime=3600, iss="https://example.com/op")
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    with pytest.raises(ValueError):
        verify_id_token(
            msg,
            check_hash=True,
            keyjar=kj,
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


def test_verify_token_encrypted():
    idt = IdToken(
        sub="553df2bcf909104751cfd8b2",
        aud=["5542958437706128204e0000", "554295ce3770612820620000"],
        auth_time=1441364872,
        azp="554295ce3770612820620000",
    )
    kj = KeyJar()
    kb = KeyBundle()
    kb.do_local_der(
        os.path.join(os.path.dirname(__file__), "data", "keys", "cert.key"),
        "some",
        ["enc", "sig"],
    )
    kj.add_kb("", kb)
    kj.add_kb("https://sso.qa.7pass.ctf.prosiebensat1.com", kb)

    packer = JWT(
        kj,
        lifetime=3600,
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        encrypt=True,
    )
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    vidt = verify_id_token(
        msg,
        keyjar=kj,
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        client_id="554295ce3770612820620000",
    )
    assert vidt
    assert vidt.jwe_header == {"enc": "A128CBC-HS256", "alg": "RSA1_5", "cty": "JWT"}


def test_verify_token_encrypted_no_key():
    idt = IdToken(
        sub="553df2bcf909104751cfd8b2",
        aud=["5542958437706128204e0000", "554295ce3770612820620000"],
        auth_time=1441364872,
        azp="554295ce3770612820620000",
    )
    kj = KeyJar()
    kb = KeyBundle()
    kb.do_local_der(
        os.path.join(os.path.dirname(__file__), "data", "keys", "cert.key"),
        "some",
        ["enc", "sig"],
    )
    kj.add_kb("", kb)
    kj.add_kb("https://sso.qa.7pass.ctf.prosiebensat1.com", kb)

    packer = JWT(
        kj,
        lifetime=3600,
        iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
        encrypt=True,
    )
    _jws = packer.pack(**idt.to_dict())
    msg = AuthorizationResponse(id_token=_jws)
    # Do not pass they keyjar with keys
    with pytest.raises(VerificationError):
        verify_id_token(
            msg,
            keyjar=KeyJar(),
            iss="https://sso.qa.7pass.ctf.prosiebensat1.com",
            client_id="554295ce3770612820620000",
        )


class TestLogoutToken:
    def test_with_sub(self):
        # All the required claims. Note there must be a sub, a sid or both
        lt = LogoutToken(
            iss="https://example.com",
            aud=["https://rp.example.org"],
            events={BACK_CHANNEL_LOGOUT_EVENT: {}},
            iat=utc_time_sans_frac(),
            jti=rndstr(16),
            sub="https://example.com/sub",
        )

        assert lt.verify()

    def test_with_sid(self):
        lt = LogoutToken(
            iss="https://example.com",
            aud=["https://rp.example.org"],
            events={BACK_CHANNEL_LOGOUT_EVENT: {}},
            iat=utc_time_sans_frac(),
            jti=rndstr(16),
            sid=rndstr(),
        )

        assert lt.verify()

    def test_with_sub_and_sid(self):
        lt = LogoutToken(
            iss="https://example.com",
            aud=["https://rp.example.org"],
            events={BACK_CHANNEL_LOGOUT_EVENT: {}},
            iat=utc_time_sans_frac(),
            jti=rndstr(16),
            sub="https://example.com/sub",
            sid=rndstr(),
        )

        assert lt.verify()

    def test_no_sub_or_sid(self):
        lt = LogoutToken(
            iss="https://example.com",
            aud=["https://rp.example.org"],
            events={BACK_CHANNEL_LOGOUT_EVENT: {}},
            iat=utc_time_sans_frac(),
            jti=rndstr(16),
        )

        with pytest.raises(ValueError):
            lt.verify()

    def test_with_nonce(self):
        lt = LogoutToken(
            iss="https://example.com",
            aud=["https://rp.example.org"],
            events={BACK_CHANNEL_LOGOUT_EVENT: {}},
            iat=utc_time_sans_frac(),
            jti=rndstr(16),
            nonce=rndstr(16),
        )

        with pytest.raises(MessageException):
            lt.verify()

    def test_extra_event(self):
        # more the one event
        lt = LogoutToken(
            iss="https://example.com",
            aud=["https://rp.example.org"],
            events={
                BACK_CHANNEL_LOGOUT_EVENT: {},
                "http://schemas.openid.net/event/other}": {},
            },
            jti=rndstr(16),
            iat=utc_time_sans_frac(),
            sub="https://example.com/sub",
        )

        with pytest.raises(ValueError):
            lt.verify()

    def test_wrong_event(self):
        lt = LogoutToken(
            iss="https://example.com",
            aud=["https://rp.example.org"],
            events={"http://schemas.openid.net/event/other}": {}},
            jti=rndstr(16),
            iat=utc_time_sans_frac(),
            sub="https://example.com/sub",
        )

        with pytest.raises(ValueError):
            lt.verify()

    def test_wrong_event_content(self):
        lt = LogoutToken(
            iss="https://example.com",
            aud=["https://rp.example.org"],
            events={BACK_CHANNEL_LOGOUT_EVENT: {"foo": "bar"}},
            jti=rndstr(16),
            iat=utc_time_sans_frac(),
            sub="https://example.com/sub",
        )

        with pytest.raises(ValueError):
            lt.verify()

    def test_wrong_aud(self):
        lt = LogoutToken(
            iss="https://example.com",
            aud=["https://rp.example.org"],
            events={BACK_CHANNEL_LOGOUT_EVENT: {}},
            iat=utc_time_sans_frac(),
            jti=rndstr(16),
            sub="https://example.com/sub",
        )

        with pytest.raises(NotForMe):
            lt.verify(aud="https://example.com")

    def test_wrong_iss(self):
        lt = LogoutToken(
            iss="https://example.com",
            aud=["https://rp.example.org"],
            events={BACK_CHANNEL_LOGOUT_EVENT: {}},
            iat=utc_time_sans_frac(),
            jti=rndstr(16),
            sub="https://example.com/sub",
        )

        with pytest.raises(NotForMe):
            lt.verify(iss="https://rp.example.org")

    def test_wrong_iat(self):
        # Issued sometime in the future
        lt = LogoutToken(
            iss="https://example.com",
            aud=["https://rp.example.org"],
            events={BACK_CHANNEL_LOGOUT_EVENT: {}},
            iat=utc_time_sans_frac() + 86400,
            jti=rndstr(16),
            sub="https://example.com/sub",
        )

        with pytest.raises(ValueError):
            lt.verify()


class TestBackchannelLogout(object):
    @pytest.fixture(autouse=True)
    def setup(self):
        self.kj = KeyJar()
        self.kj.add_symmetric("", "dYMmrcQksKaPkhdgRNYk3zzh5l7ewdDJ", ["sig"])
        self.key = self.kj.get_signing_key("oct")
        lt = LogoutToken(
            iss="https://example.com",
            aud=["https://rp.example.org"],
            events={BACK_CHANNEL_LOGOUT_EVENT: {}},
            iat=utc_time_sans_frac(),
            jti=rndstr(16),
            sub="https://example.com/sub",
        )

        self.signed_jwt = lt.to_jwt(key=self.key, algorithm="HS256")

    def test_verify_with_keyjar(self):
        bclr = BackChannelLogoutRequest(logout_token=self.signed_jwt)
        assert bclr.verify(keyjar=self.kj)

        # The signed JWT is replaced by a dictionary with all the verified values
        assert bclr["logout_token"]["iss"] == "https://example.com"

    def test_verify_with_key(self):
        bclr = BackChannelLogoutRequest(logout_token=self.signed_jwt)
        assert bclr.verify(key=self.key)

        # The signed JWT is replaced by a dictionary with all the verified values
        assert bclr["logout_token"]["iss"] == "https://example.com"

    def test_bogus_logout_token(self):
        lt = LogoutToken(
            iss="https://example.com",
            aud=["https://rp.example.org"],
            events={BACK_CHANNEL_LOGOUT_EVENT: {}},
            iat=utc_time_sans_frac(),
            jti=rndstr(16),
            nonce=rndstr(16),
        )
        signed_jwt = lt.to_jwt(key=self.key, algorithm="HS256")
        bclr = BackChannelLogoutRequest(logout_token=signed_jwt)

        with pytest.raises(MessageException):
            bclr.verify(key=self.key)


class TestFrontchannelLogout(object):
    def test_verify_request(self):
        # May be completely empty
        fclr = FrontChannelLogoutRequest()

        assert fclr.verify()
