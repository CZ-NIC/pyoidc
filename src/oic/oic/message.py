import time
from urlparse import urlparse
from oic.oauth2.exception import InvalidRequest, PyoidcError

__author__ = 'rohe0002'

import urllib
import json
import logging

from oic.oauth2 import message, MissingRequiredValue
from oic.oauth2 import MissingRequiredAttribute
from oic.oauth2 import VerificationError
from oic.oauth2.message import Message, REQUIRED_LIST_OF_SP_SEP_STRINGS
from oic.oauth2.message import SINGLE_OPTIONAL_STRING
from oic.oauth2.message import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2.message import SINGLE_REQUIRED_STRING
from oic.oauth2.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oic.oauth2.message import SINGLE_OPTIONAL_INT
from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS

import jwkest
from jwkest import jws

logger = logging.getLogger(__name__)


#noinspection PyUnusedLocal
def json_ser(val, sformat=None, lev=0):
    return json.dumps(val)


#noinspection PyUnusedLocal
def json_deser(val, sformat=None, lev=0):
    return json.loads(val)

# value type, required, serializer, deserializer, null value allowed
SINGLE_OPTIONAL_BOOLEAN = (bool, False, None, None, False)
SINGLE_OPTIONAL_JSON_WN = (dict, False, json_ser, json_deser, True)
SINGLE_OPTIONAL_JSON = (dict, False, json_ser, json_deser, False)
SINGLE_REQUIRED_INT = (int, True, None, None, False)


#noinspection PyUnusedLocal
def idtoken_deser(val, sformat="urlencoded"):
    # id_token are always serialized as a JWT
    return IdToken().deserialize(val, "jwt")


# def idtokenclaim_deser(val, sformat="urlencoded"):
#     if sformat in ["dict", "json"]:
#         if not isinstance(val, basestring):
#             val = json.dumps(val)
#             sformat = "json"
#     return IDTokenClaim().deserialize(val, sformat)
#
#
# def userinfo_deser(val, sformat="urlencoded"):
#     if sformat in ["dict", "json"]:
#         if not isinstance(val, basestring):
#             val = json.dumps(val)
#             sformat = "json"
#     return UserInfoClaim().deserialize(val, sformat)

def address_deser(val, sformat="urlencoded"):
    if sformat in ["dict", "json"]:
        if not isinstance(val, basestring):
            val = json.dumps(val)
            sformat = "json"
    return AddressClaim().deserialize(val, sformat)


def claims_deser(val, sformat="urlencoded"):
    if sformat in ["dict", "json"]:
        if not isinstance(val, basestring):
            val = json.dumps(val)
            sformat = "json"
    return Claims().deserialize(val, sformat)


def msg_ser(inst, sformat, lev=0):
    if sformat in ["urlencoded", "json"]:
        if isinstance(inst, dict) or isinstance(inst, Message):
            res = inst.serialize(sformat, lev)
        else:
            res = inst
    elif sformat == "dict":
        if isinstance(inst, Message):
            res = inst.serialize(sformat, lev)
        elif isinstance(inst, dict):
            res = inst
        else:
            raise ValueError("%s" % type(inst))
    else:
        raise PyoidcError("Unknown sformat")

    return res


def msg_ser_json(inst, sformat="json", lev=0):
    # sformat = "json" always except when dict
    if sformat == "dict":
        if isinstance(inst, Message):
            res = inst.serialize(sformat, lev)
        elif isinstance(inst, dict):
            res = inst
        else:
            raise ValueError("%s" % type(inst))
    else:
        sformat = "json"
        if isinstance(inst, dict) or isinstance(inst, Message):
            res = inst.serialize(sformat, lev)
        else:
            res = inst

    return res


def msg_list_ser(insts, sformat, lev=0):
    return [msg_ser(inst, sformat, lev) for inst in insts]


def claims_ser(val, sformat="urlencoded", lev=0):
    # everything in c_extension
    if isinstance(val, basestring):
        item = val
    elif isinstance(val, list):
        item = val[0]
    else:
        item = val

    if isinstance(item, Message):
        return item.serialize(method=sformat, lev=lev + 1)

    if sformat == "urlencoded":
        res = urllib.urlencode(item)
    elif sformat == "json":
        if lev:
            res = item
        else:
            res = json.dumps(item)
    elif sformat == "dict":
        if isinstance(item, dict):
            res = item
        else:
            raise ValueError("%s" % type(item))
    else:
        raise PyoidcError("Unknown sformat")

    return res


def registration_request_deser(val, sformat="urlencoded"):
    if sformat in ["dict", "json"]:
        if not isinstance(val, basestring):
            val = json.dumps(val)
            sformat = "json"
    return RegistrationRequest().deserialize(val, sformat)


def claims_request_deser(val, sformat="json"):
    # never 'urlencoded'
    if sformat == "urlencoded":
        sformat = "json"
    if sformat in ["dict", "json"]:
        if not isinstance(val, basestring):
            val = json.dumps(val)
            sformat = "json"
    return ClaimsRequest().deserialize(val, sformat)


OPTIONAL_ADDRESS = (Message, False, msg_ser, address_deser, False)
OPTIONAL_LOGICAL = (bool, False, None, None, False)
OPTIONAL_MULTIPLE_Claims = (Message, False, claims_ser, claims_deser, False)
# SINGLE_OPTIONAL_USERINFO_CLAIM = (Message, False, msg_ser, userinfo_deser)
# SINGLE_OPTIONAL_ID_TOKEN_CLAIM = (Message, False, msg_ser, idtokenclaim_deser)

SINGLE_OPTIONAL_JWT = (basestring, False, msg_ser, None, False)
SINGLE_OPTIONAL_IDTOKEN = (basestring, False, msg_ser, None, False)

SINGLE_OPTIONAL_REGISTRATION_REQUEST = (Message, False, msg_ser,
                                        registration_request_deser, False)
SINGLE_OPTIONAL_CLAIMSREQ = (Message, False, msg_ser_json, claims_request_deser,
                             False)

# ----------------------------------------------------------------------------


SCOPE_CHARSET = []
for char in ['\x21', ('\x23', '\x5b'), ('\x5d', '\x7E')]:
    if isinstance(char, tuple):
        c = char[0]
        while c <= char[1]:
            SCOPE_CHARSET.append(c)
            c = chr(ord(c) + 1)
    else:
        SCOPE_CHARSET.append(set)


def check_char_set(string, allowed):
    for c in string:
        if c not in allowed:
            raise ValueError("'%c' not in the allowed character set" % c)


# -----------------------------------------------------------------------------

class RefreshAccessTokenRequest(message.RefreshAccessTokenRequest):
    pass


class TokenErrorResponse(message.TokenErrorResponse):
    pass


class AccessTokenResponse(message.AccessTokenResponse):
    c_param = message.AccessTokenResponse.c_param.copy()
    c_param.update({"id_token": SINGLE_OPTIONAL_STRING})

    def verify(self, **kwargs):
        if "id_token" in self:
            # Try to decode the JWT, checks the signature
            args = {}
            for arg in ["key", "keyjar"]:
                try:
                    args[arg] = kwargs[arg]
                except KeyError:
                    pass
            idt = IdToken().from_jwt(str(self["id_token"]), **args)
            if not idt.verify(**kwargs):
                return False

            # replace the JWT with the IdToken instance
            self["id_token"] = idt

        return super(AccessTokenResponse, self).verify(**kwargs)


class UserInfoRequest(Message):
    c_param = {
        "access_token": SINGLE_OPTIONAL_STRING,
    }


class AuthorizationResponse(message.AuthorizationResponse,
                            message.AccessTokenResponse):

    c_param = message.AuthorizationResponse.c_param.copy()
    c_param.update(message.AccessTokenResponse.c_param)
    c_param.update({
        "code": SINGLE_OPTIONAL_STRING,
        "nonce": SINGLE_OPTIONAL_STRING,
        "access_token": SINGLE_OPTIONAL_STRING,
        "token_type": SINGLE_OPTIONAL_STRING,
        "id_token": SINGLE_OPTIONAL_IDTOKEN
    })

    def verify(self, **kwargs):
        if "aud" in self:
            if "client_id" in kwargs:
                # check that it's for me
                if kwargs["client_id"] not in self["aud"]:
                    return False

        if "id_token" in self:
            # Try to decode the JWT, checks the signature
            args = {}
            for arg in ["key", "keyjar"]:
                try:
                    args[arg] = kwargs[arg]
                except KeyError:
                    pass
            idt = IdToken().from_jwt(str(self["id_token"]), **args)
            if not idt.verify(**kwargs):
                raise VerificationError("Could not verify id_token")

            hfunc = "HS" + jwkest.unpack(self["id_token"])[0]["alg"][-3:]

            if "access_token" in self:
                try:
                    assert "at_hash" in idt
                except AssertionError:
                    raise MissingRequiredAttribute("Missing at_hash property")
                try:
                    assert idt["at_hash"] == jws.left_hash(
                        self["access_token"], hfunc)
                except AssertionError:
                    raise VerificationError(
                        "Failed to verify access_token hash")

            if "code" in self:
                try:
                    assert "c_hash" in idt
                except AssertionError:
                    raise MissingRequiredAttribute("Missing c_hash property")
                try:
                    assert idt["c_hash"] == jws.left_hash(self["code"], hfunc)
                except AssertionError:
                    raise VerificationError("Failed to verify code hash")

            self["id_token"] = idt

        return super(AuthorizationResponse, self).verify(**kwargs)


class AuthorizationErrorResponse(message.AuthorizationErrorResponse):
    c_allowed_values = message.AuthorizationErrorResponse.c_allowed_values.copy()
    c_allowed_values["error"].extend(["interaction_required",
                                      "login_required",
                                      "session_selection_required",
                                      "consent_required",
                                      "invalid_request_uri",
                                      "invalid_request_object",
                                      "registration_not_supported",
                                      "request_not_supported"])


class AuthorizationRequest(message.AuthorizationRequest):
    c_param = message.AuthorizationRequest.c_param.copy()
    c_param.update(
        {
            "scope": REQUIRED_LIST_OF_SP_SEP_STRINGS,
            "redirect_uri": SINGLE_REQUIRED_STRING,
            "nonce": SINGLE_OPTIONAL_STRING,
            "display": SINGLE_OPTIONAL_STRING,
            "prompt": OPTIONAL_LIST_OF_STRINGS,
            "max_age": SINGLE_OPTIONAL_INT,
            "ui_locales": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
            "claims_locale": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
            "id_token_hint": SINGLE_OPTIONAL_STRING,
            "login_hint": SINGLE_OPTIONAL_STRING,
            "acr_values": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
            "claims": SINGLE_OPTIONAL_CLAIMSREQ,
            "registration": SINGLE_OPTIONAL_JSON,
            "request": SINGLE_OPTIONAL_STRING,
            "request_uri": SINGLE_OPTIONAL_STRING,
            "session_state": SINGLE_OPTIONAL_STRING,
        }
    )
    c_allowed_values = message.AuthorizationRequest.c_allowed_values.copy()
    c_allowed_values.update({
        "display": ["page", "popup", "touch", "wap"],
        "prompt": ["none", "login", "consent", "select_account"]
    })

    def verify(self, **kwargs):
        """Authorization Request parameters that are OPTIONAL in the OAuth 2.0
        specification MAY be included in the OpenID Request Object without also
        passing them as OAuth 2.0 Authorization Request parameters, with one
        exception: The scope parameter MUST always be present in OAuth 2.0
        Authorization Request parameters.
        All parameter values that are present both in the OAuth 2.0
        Authorization Request and in the OpenID Request Object MUST exactly
        match."""
        args = {}
        for arg in ["key", "keyjar"]:
            try:
                args[arg] = kwargs[arg]
            except KeyError:
                pass

        if "request" in self:
            if isinstance(self["request"], basestring):
                # Try to decode the JWT, checks the signature
                oidr = OpenIDRequest().from_jwt(str(self["request"]), **args)

                # verify that nothing is change in the original message
                for key, val in oidr.items():
                    if key in self:
                        assert self[key] == val

                # replace the JWT with the parsed and verified instance
                self["request"] = oidr
        if "id_token" in self:
            if isinstance(self["id_token"], basestring):
                idt = IdToken().from_jwt(str(self["id_token"]), **args)
                self["id_token"] = idt

        if "response_type" not in self:
            raise MissingRequiredAttribute("response_type missing")

        _rt = self["response_type"]
        if "token" in _rt or "id_token" in _rt:
            try:
                assert "nonce" in self
            except AssertionError:
                raise MissingRequiredAttribute("Nonce missing")

        try:
            assert "openid" in self["scope"]
        except AssertionError:
            raise MissingRequiredValue("openid in scope")

        if "offline_access" in self["scope"]:
            try:
                assert "consent" in self["prompt"]
            except AssertionError:
                raise MissingRequiredValue("consent in prompt")

        if "prompt" in self:
            if "none" in self["prompt"] and len(self["prompt"]) > 1:
                raise InvalidRequest("prompt none combined with other value")

        return super(AuthorizationRequest, self).verify(**kwargs)


class AccessTokenRequest(message.AccessTokenRequest):
    c_param = message.AccessTokenRequest.c_param.copy()
    c_param.update({"client_assertion_type": SINGLE_OPTIONAL_STRING,
                    "client_assertion": SINGLE_OPTIONAL_STRING})

    c_allowed_values = {
        "client_assertion_type": [
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"],
    }


class AddressClaim(Message):
    c_param = {"formatted": SINGLE_OPTIONAL_STRING,
               "street_address": SINGLE_OPTIONAL_STRING,
               "locality": SINGLE_OPTIONAL_STRING,
               "region": SINGLE_OPTIONAL_STRING,
               "postal_code": SINGLE_OPTIONAL_STRING,
               "country": SINGLE_OPTIONAL_STRING}


class OpenIDSchema(Message):
    c_param = {"sub": SINGLE_REQUIRED_STRING,
               "name": SINGLE_OPTIONAL_STRING,
               "given_name": SINGLE_OPTIONAL_STRING,
               "family_name": SINGLE_OPTIONAL_STRING,
               "middle_name": SINGLE_OPTIONAL_STRING,
               "nickname": SINGLE_OPTIONAL_STRING,
               "preferred_username": SINGLE_OPTIONAL_STRING,
               "profile": SINGLE_OPTIONAL_STRING,
               "picture": SINGLE_OPTIONAL_STRING,
               "website": SINGLE_OPTIONAL_STRING,
               "email": SINGLE_OPTIONAL_STRING,
               "email_verified": SINGLE_OPTIONAL_BOOLEAN,
               "gender": SINGLE_OPTIONAL_STRING,
               "birthdate": SINGLE_OPTIONAL_STRING,
               "zoneinfo": SINGLE_OPTIONAL_STRING,
               "locale": SINGLE_OPTIONAL_STRING,
               "phone_number": SINGLE_OPTIONAL_STRING,
               "phone_number_verified": SINGLE_OPTIONAL_STRING,
               "address": OPTIONAL_ADDRESS,
               "updated_at": SINGLE_OPTIONAL_INT,
               "_claim_names": SINGLE_OPTIONAL_JSON,
               "_claim_sources": SINGLE_OPTIONAL_JSON}

    def verify(self, **kwargs):
        if "birthdate" in self:
            # Either YYYY-MM-DD or just YYYY
            try:
                _ = time.strptime(self["birthdate"], "%Y-%m-%d")
            except ValueError:
                try:
                    _ = time.strptime(self["birthdate"], "%Y")
                except ValueError:
                    raise VerificationError("Birthdate format error")

        return super(OpenIDSchema, self).verify(**kwargs)


class RegistrationRequest(Message):
    c_param = {
        "redirect_uris": REQUIRED_LIST_OF_STRINGS,
        "response_types": OPTIONAL_LIST_OF_STRINGS,
        "grant_types": OPTIONAL_LIST_OF_STRINGS,
        "application_type": SINGLE_OPTIONAL_STRING,
        "contacts": OPTIONAL_LIST_OF_STRINGS,
        "client_name": SINGLE_OPTIONAL_STRING,
        "logo_uri": SINGLE_OPTIONAL_STRING,
        "client_uri": SINGLE_OPTIONAL_STRING,
        "policy_uri": SINGLE_OPTIONAL_STRING,
        "tos_uri": SINGLE_OPTIONAL_STRING,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "sector_identifier_uri": SINGLE_OPTIONAL_STRING,
        "subject_type": SINGLE_OPTIONAL_STRING,
        "id_token_signed_response_alg": SINGLE_OPTIONAL_STRING,
        "id_token_encrypted_response_alg": SINGLE_OPTIONAL_STRING,
        "id_token_encrypted_response_enc": SINGLE_OPTIONAL_STRING,
        "userinfo_signed_response_alg": SINGLE_OPTIONAL_STRING,
        "userinfo_encrypted_response_alg": SINGLE_OPTIONAL_STRING,
        "userinfo_encrypted_response_enc": SINGLE_OPTIONAL_STRING,
        "request_object_signing_alg": SINGLE_OPTIONAL_STRING,
        "request_object_encryption_alg": SINGLE_OPTIONAL_STRING,
        "request_object_encryption_enc": SINGLE_OPTIONAL_STRING,
        "token_endpoint_auth_method": SINGLE_OPTIONAL_STRING,
        "token_endpoint_auth_signing_alg": SINGLE_OPTIONAL_STRING,
        "default_max_age": SINGLE_OPTIONAL_INT,
        "require_auth_time": OPTIONAL_LOGICAL,
        "default_acr_values": OPTIONAL_LIST_OF_STRINGS,
        "initiate_login_uri": SINGLE_OPTIONAL_STRING,
        "request_uris": OPTIONAL_LIST_OF_STRINGS,
        #"client_id": SINGLE_OPTIONAL_STRING,
        #"client_secret": SINGLE_OPTIONAL_STRING,
        "access_token": SINGLE_OPTIONAL_STRING,
        "post_logout_redirect_uris": OPTIONAL_LIST_OF_STRINGS,
    }
    c_default = {"application_type": "web"}
    c_allowed_values = {"application_type": ["native", "web"],
                        "subject_type": ["public", "pairwise"]}

    def verify(self, **kwargs):
        if "initiate_login_uri" in self:
            assert self["initiate_login_uri"].startswith("https:")

        return super(RegistrationRequest, self).verify(**kwargs)


class RegistrationResponse(Message):
    """
    Response to client_register registration requests
    """
    c_param = {
        "client_id": SINGLE_REQUIRED_STRING,
        "client_secret": SINGLE_OPTIONAL_STRING,
        "registration_access_token": SINGLE_REQUIRED_STRING,
        "registration_client_uri": SINGLE_OPTIONAL_STRING,
        "client_id_issued_at": SINGLE_OPTIONAL_INT,
        "client_secret_expires_at": SINGLE_OPTIONAL_INT,
    }
    c_param.update(RegistrationRequest.c_param)

    def verify(self, **kwargs):
        """
        Implementations MUST either return both a Client Configuration Endpoint
        and a Registration Access Token or neither of them.
        :param kwargs:
        :return: True if the message is OK otherwise False
        """

        if "registration_client_uri" in self:
            if not "registration_access_token":
                raise VerificationError((
                    "Only one of registration_client_uri"
                    " and registration_access_token present"))
        elif "registration_access_token" in self:
            raise VerificationError((
                "Only one of registration_client_uri"
                " and registration_access_token present"))

        return super(RegistrationResponse, self).verify(**kwargs)


class ClientRegistrationErrorResponse(message.ErrorResponse):
    c_allowed_values = {"error": ["invalid_redirect_uri",
                                  "invalid_client_metadata"]}


class IdToken(OpenIDSchema):
    c_param = OpenIDSchema.c_param.copy()
    c_param.update({
        "iss": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_REQUIRED_STRING,
        "aud": REQUIRED_LIST_OF_STRINGS,  # Array of strings or string
        "exp": SINGLE_REQUIRED_INT,
        "iat": SINGLE_REQUIRED_INT,
        "auth_time": SINGLE_OPTIONAL_INT,
        "nonce": SINGLE_OPTIONAL_STRING,
        "at_hash": SINGLE_OPTIONAL_STRING,
        "c_hash": SINGLE_OPTIONAL_STRING,
        "acr": SINGLE_OPTIONAL_STRING,
        "amr": OPTIONAL_LIST_OF_STRINGS,
        "azp": OPTIONAL_LIST_OF_STRINGS,  # Array of strings or string
        "sub_jwk": SINGLE_OPTIONAL_STRING
    })

    def verify(self, **kwargs):
        if "aud" in self:
            if "client_id" in kwargs:
                # check that I'm among the recipients
                if kwargs["client_id"] not in self["aud"]:
                    return False

        return super(IdToken, self).verify(**kwargs)


class RefreshSessionRequest(Message):
    c_param = {"id_token": SINGLE_REQUIRED_STRING,
               "redirect_url": SINGLE_REQUIRED_STRING,
               "state": SINGLE_REQUIRED_STRING}


class RefreshSessionResponse(Message):
    c_param = {"id_token": SINGLE_REQUIRED_STRING,
               "state": SINGLE_REQUIRED_STRING}


class CheckSessionRequest(Message):
    c_param = {"id_token": SINGLE_REQUIRED_STRING}


class CheckIDRequest(Message):
    c_param = {"access_token": SINGLE_REQUIRED_STRING}


class EndSessionRequest(Message):
    c_param = {"id_token": SINGLE_REQUIRED_STRING,
               "redirect_url": SINGLE_REQUIRED_STRING,
               "state": SINGLE_REQUIRED_STRING}


class EndSessionResponse(Message):
    c_param = {"state": SINGLE_REQUIRED_STRING}


class Claims(Message):
    c_param = {"*": SINGLE_OPTIONAL_JSON_WN}


class ClaimsRequest(Message):
    c_param = {
        "userinfo": OPTIONAL_MULTIPLE_Claims,
        "id_token": OPTIONAL_MULTIPLE_Claims
    }


# class UserInfoClaim(Message):
#     c_param = {"claims": OPTIONAL_MULTIPLE_Claims,
#                "preferred_locale": SINGLE_OPTIONAL_STRING}
#
#
# class IDTokenClaim(Message):
#     c_param = {"claims": OPTIONAL_MULTIPLE_Claims,
#                "max_age": SINGLE_OPTIONAL_INT}


class OpenIDRequest(AuthorizationRequest):
    pass


class ProviderConfigurationResponse(Message):
    c_param = {
        "version": SINGLE_REQUIRED_STRING,
        "issuer": SINGLE_REQUIRED_STRING,
        "authorization_endpoint": SINGLE_OPTIONAL_STRING,
        "token_endpoint": SINGLE_OPTIONAL_STRING,
        "userinfo_endpoint": SINGLE_OPTIONAL_STRING,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "registration_endpoint": SINGLE_OPTIONAL_STRING,
        "scopes_supported": OPTIONAL_LIST_OF_STRINGS,
        "response_types_supported": REQUIRED_LIST_OF_STRINGS,
        "response_modes_supported": OPTIONAL_LIST_OF_STRINGS,
        "grant_types_supported": REQUIRED_LIST_OF_STRINGS,
        "acr_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "subject_types_supported": REQUIRED_LIST_OF_STRINGS,
        "id_token_signing_alg_values_supported": REQUIRED_LIST_OF_STRINGS,
        "id_token_encryption_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "id_token_encryption_enc_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "userinfo_signing_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "userinfo_encryption_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "userinfo_encryption_enc_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "request_object_signing_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "request_object_encryption_alg_values_supported":
        OPTIONAL_LIST_OF_STRINGS,
        "request_object_encryption_enc_values_supported":
        OPTIONAL_LIST_OF_STRINGS,
        "token_endpoint_auth_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "token_endpoint_auth_signing_alg_values_supported":
        OPTIONAL_LIST_OF_STRINGS,
        "display_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "claim_types_supported": OPTIONAL_LIST_OF_STRINGS,
        "claims_supported": OPTIONAL_LIST_OF_STRINGS,
        "service_documentation": SINGLE_OPTIONAL_STRING,
        "claims_locales_supported": OPTIONAL_LIST_OF_STRINGS,
        "ui_locales_supported": OPTIONAL_LIST_OF_STRINGS,
        "claims_parameter_supported": SINGLE_OPTIONAL_STRING,
        "request_parameter_supported": SINGLE_OPTIONAL_STRING,
        "request_uri_parameter_supported": SINGLE_OPTIONAL_STRING,
        "require_request_uri_registration": SINGLE_OPTIONAL_STRING,
        "op_policy_uri": SINGLE_OPTIONAL_STRING,
        "op_tos_uri": SINGLE_OPTIONAL_STRING
        #"check_session_iframe": SINGLE_OPTIONAL_STRING,
        #"end_session_endpoint": SINGLE_OPTIONAL_STRING,
        #"jwk_encryption_url": SINGLE_OPTIONAL_STRING,
        #"x509_url": SINGLE_REQUIRED_STRING,
        #"x509_encryption_url": SINGLE_OPTIONAL_STRING,
    }
    c_default = {"version": "3.0",
                 "token_endpoint_auth_methods_supported": "client_secret_basic",
                 "claims_parameter_supported": "false",
                 "request_parameter_supported": "false",
                 "request_uri_parameter_supported": "true",
                 "require_request_uri_registration": "true",
                 "grant_types_supported": ["authorization_code", "implicit"]}

    def verify(self, **kwargs):
        if "scopes_supported" in self:
            assert "openid" in self["scopes_supported"]
            for scope in self["scopes_supported"]:
                check_char_set(scope, SCOPE_CHARSET)

        parts = urlparse(self["issuer"])
        assert parts.scheme == "https"
        assert not parts.query and not parts.fragment

        return super(ProviderConfigurationResponse, self).verify(**kwargs)


class AuthnToken(Message):
    c_param = {
        "iss": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_REQUIRED_STRING,
        "aud": REQUIRED_LIST_OF_STRINGS,  # Array of strings or string
        "jti": SINGLE_REQUIRED_STRING,
        "exp": SINGLE_REQUIRED_INT,
        "iat": SINGLE_OPTIONAL_INT,
    }


class UserInfoErrorResponse(message.ErrorResponse):
    c_allowed_values = {"error": ["invalid_schema", "invalid_request",
                                  "invalid_token", "insufficient_scope"]}


class DiscoveryRequest(Message):
    c_param = {"principal": SINGLE_REQUIRED_STRING,
               "service": SINGLE_REQUIRED_STRING}


class DiscoveryResponse(Message):
    c_param = {"locations": REQUIRED_LIST_OF_STRINGS}


class ResourceRequest(Message):
    c_param = {"access_token": SINGLE_OPTIONAL_STRING}

SCOPE2CLAIMS = {
    "openid": ["sub"],
    "profile": ["name", "given_name", "family_name", "middle_name",
                "nickname", "profile", "picture", "website", "gender",
                "birthdate", "zoneinfo", "locale", "updated_at",
                "preferred_username"],
    "email": ["email", "email_verified"],
    "address": ["address"],
    "phone": ["phone_number", "phone_number_verified"],
    "offline_access": []
}

MSG = {
    "RefreshAccessTokenRequest": RefreshAccessTokenRequest,
    "TokenErrorResponse": TokenErrorResponse,
    "AccessTokenResponse": AccessTokenResponse,
    "UserInfoRequest": UserInfoRequest,
    "AuthorizationResponse": AuthorizationResponse,
    "AuthorizationErrorResponse": AuthorizationErrorResponse,
    "AuthorizationRequest": AuthorizationRequest,
    "AccessTokenRequest": AccessTokenRequest,
    "AddressClaim": AddressClaim,
    "OpenIDSchema": OpenIDSchema,
    "RegistrationRequest": RegistrationRequest,
    "RegistrationResponse": RegistrationResponse,
    "ClientRegistrationErrorResponse": ClientRegistrationErrorResponse,
    "IdToken": IdToken,
    "RefreshSessionRequest": RefreshSessionRequest,
    "RefreshSessionResponse": RefreshSessionResponse,
    "CheckSessionRequest": CheckSessionRequest,
    "CheckIDRequest": CheckIDRequest,
    "EndSessionRequest": EndSessionRequest,
    "EndSessionResponse": EndSessionResponse,
    "Claims": Claims,
    # "UserInfoClaim": UserInfoClaim,
    # "IDTokenClaim": IDTokenClaim,
    "OpenIDRequest": OpenIDRequest,
    "ProviderConfigurationResponse": ProviderConfigurationResponse,
    "AuthnToken": AuthnToken,
    "UserInfoErrorResponse": UserInfoErrorResponse,
    "DiscoveryRequest": DiscoveryRequest,
    "DiscoveryResponse": DiscoveryResponse,
    "ResourceRequest": ResourceRequest,
}


def factory(msgtype):
    try:
        return MSG[msgtype]
    except KeyError:
        if msgtype == "ErrorResponse":
            return message.ErrorResponse
        elif msgtype == "Message":
            return message.Message
        else:
            raise PyoidcError("Unknown message type: %s" % msgtype)

if __name__ == "__main__":
    atr = AccessTokenResponse(access_token="access_token",
                              token_type="token_type")
    print atr
    print atr.verify()

    atr = AccessTokenRequest(code="code", client_id="client_id",
                             redirect_uri="redirect_uri")
    print atr
    print atr.verify()
    uue = atr.serialize()
    atr = AccessTokenRequest().deserialize(uue, "urlencoded")
    print atr