import time
from urlparse import urlparse

__author__ = 'rohe0002'

import urllib
import json
import logging

from oic.oauth2 import message
from oic.oauth2 import MissingRequiredAttribute
from oic.oauth2 import VerificationError
from oic.oauth2.message import Message
from oic.oauth2.message import SINGLE_OPTIONAL_STRING
from oic.oauth2.message import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2.message import SINGLE_REQUIRED_STRING
from oic.oauth2.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oic.oauth2.message import SINGLE_OPTIONAL_INT
from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS
from oic.oauth2.message import REQUIRED_LIST_OF_SP_SEP_STRINGS

import jwkest
from jwkest import jws

logger = logging.getLogger(__name__)

#noinspection PyUnusedLocal
def json_ser(val, format=None, lev=0):
    return json.dumps(val)

#noinspection PyUnusedLocal
def json_deser(val, format=None, lev=0):
    return json.loads(val)

SINGLE_OPTIONAL_BOOLEAN = (bool, False, None, None)
SINGLE_OPTIONAL_JSON = (dict, False, json_ser, json_deser)
SINGLE_REQUIRED_INT = (int, True, None, None)

def idtoken_deser(val, format="urlencoded"):
    # id_token are always serialized as a JWT
    return IdToken().deserialize(val, "jwt")

def idtokenclaim_deser(val, format="urlencoded"):
    if format in ["dict", "json"]:
        if not isinstance(val, basestring):
            val = json.dumps(val)
            format="json"
    return IDTokenClaim().deserialize(val, format)

def userinfo_deser(val, format="urlencoded"):
    if format in ["dict", "json"]:
        if not isinstance(val, basestring):
            val = json.dumps(val)
            format = "json"
    return UserInfoClaim().deserialize(val, format)

def address_deser(val, format="urlencoded"):
    if format in ["dict", "json"]:
        if not isinstance(val, basestring):
            val = json.dumps(val)
            format = "json"
    return AddressClaim().deserialize(val, format)

def claims_deser(val, format="urlencoded"):
    if format in ["dict", "json"]:
        if not isinstance(val, basestring):
            val = json.dumps(val)
            format = "json"
    return Claims().deserialize(val, format)

def msg_ser(inst, format, lev=0):
    if format in ["urlencoded", "json"]:
        if isinstance(inst, dict) or isinstance(inst, Message):
            res = inst.serialize(format, lev)
        else:
            res = inst
    elif format == "dict":
        if isinstance(inst, Message):
            res = inst.serialize(format, lev)
        elif isinstance(inst, dict):
            res = inst
        else:
            raise ValueError("%s" % type(inst))
    else:
        raise Exception("Unknown format")

    return res

def msg_list_ser(insts, format, lev=0):
    return [msg_ser(inst, format, lev) for inst in insts]

def claims_ser(val, format="urlencoded", lev=0):
    # everything in c_extension
    if isinstance(val, basestring):
        item = val
    elif isinstance(val, list):
        item = val[0]
    else:
        item = val

    if isinstance(item, Message):
        return item.serialize(method=format, lev=lev+1)

    if format == "urlencoded":
        res = urllib.urlencode(item)
    elif format == "json":
        if lev:
            res = item
        else:
            res = json.dumps(item)
    elif format == "dict":
        if isinstance(item, dict):
            res = item
        else:
            raise ValueError("%s" % type(item))
    else:
        raise Exception("Unknown format")

    return res

def registration_request_deser(val, format="urlencoded"):
    if format in ["dict", "json"]:
        if not isinstance(val, basestring):
            val = json.dumps(val)
            format = "json"
    return RegistrationRequest().deserialize(val, format)

OPTIONAL_ADDRESS = (Message, False, msg_ser, address_deser)
OPTIONAL_LOGICAL = (bool, False, None, None)
OPTIONAL_MULTIPLE_Claims = (Message, False, claims_ser, claims_deser)
SINGLE_OPTIONAL_USERINFO_CLAIM = (Message, False, msg_ser, userinfo_deser)
SINGLE_OPTIONAL_ID_TOKEN_CLAIM = (Message, False, msg_ser, idtokenclaim_deser)

SINGLE_OPTIONAL_JWT = (basestring, False, msg_ser, None)
SINGLE_OPTIONAL_IDTOKEN = (basestring, False, msg_ser, None)

SINGLE_OPTIONAL_REGISTRATION_REQUEST= (Message, False, msg_ser,
                                       registration_request_deser)

# ----------------------------------------------------------------------------


SCOPE_CHARSET = []
for set in ['\x21', ('\x23','\x5b'), ('\x5d','\x7E')]:
    if isinstance(set, tuple):
        c = set[0]
        while c <= set[1]:
            SCOPE_CHARSET.append(c)
            c = chr(ord(c) + 1)
    else:
        SCOPE_CHARSET.append(set)

def check_char_set(str, allowed):
    for c in str:
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
    c_param = {"access_token": SINGLE_OPTIONAL_STRING,
               "schema": SINGLE_REQUIRED_STRING,
               "id": SINGLE_OPTIONAL_STRING}

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

            hfunc = "HS"+ jwkest.unpack(self["id_token"])[0]["alg"][-3:]

            if "access_token" in self:
                try:
                    assert "at_hash" in idt
                except AssertionError:
                    raise MissingRequiredAttribute("Missing at_hash property")
                try:
                    assert idt["at_hash"] == jws.left_hash(
                        self["access_token"], hfunc )
                except AssertionError:
                    raise VerificationError("Failed to verify access_token hash")

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
                                      "invalid_openid_request_object"])


class AuthorizationRequest(message.AuthorizationRequest):
    c_param = message.AuthorizationRequest.c_param.copy()
    c_param.update({"request": SINGLE_OPTIONAL_STRING,
                    "request_uri": SINGLE_OPTIONAL_STRING,
                    "display": SINGLE_OPTIONAL_STRING,
                    "prompt": OPTIONAL_LIST_OF_STRINGS,
                    "nonce": SINGLE_OPTIONAL_STRING,
                    "scope": REQUIRED_LIST_OF_SP_SEP_STRINGS,
                    "id_token": SINGLE_OPTIONAL_STRING
                })
    c_allowed_values = message.AuthorizationRequest.c_allowed_values.copy()
    c_allowed_values = {
            "display": ["page", "popup", "touch", "wap"],
            "prompt": ["none", "login", "consent", "select_account"]
        }

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
            # Try to decode the JWT, checks the signature
            oidr = OpenIDRequest().from_jwt(str(self["request"]), **args)

            # verify that nothing is change in the original message
            for key, val in oidr.items():
                if key in self:
                    assert self[key] == val

            # replace the JWT with the parsed and verified instance
            self["request"] = oidr

        if "id_token" in self:
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

        return super(AuthorizationRequest, self).verify(**kwargs)

class AccessTokenRequest(message.AccessTokenRequest):
    c_param = message.AccessTokenRequest.c_param.copy()
    c_param.update({"client_id": SINGLE_REQUIRED_STRING,
                    "client_secret": SINGLE_OPTIONAL_STRING,
                    "client_assertion_type": SINGLE_OPTIONAL_STRING,
                    "client_assertion": SINGLE_OPTIONAL_STRING})

    c_allowed_values = {
        "client_assertion_type" : [
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"],
    }

class AddressClaim(Message):
    c_param = {
            "formatted": SINGLE_OPTIONAL_STRING,
            "street_address": SINGLE_OPTIONAL_STRING,
            "locality": SINGLE_OPTIONAL_STRING,
            "region": SINGLE_OPTIONAL_STRING,
            "postal_code": SINGLE_OPTIONAL_STRING,
            "country": SINGLE_OPTIONAL_STRING,
        }

class OpenIDSchema(Message):
    c_param= {
            "sub": SINGLE_REQUIRED_STRING,
            "name": SINGLE_OPTIONAL_STRING,
            "given_name": SINGLE_OPTIONAL_STRING,
            "family_name": SINGLE_OPTIONAL_STRING,
            "middle_name": SINGLE_OPTIONAL_STRING,
            "nickname": SINGLE_OPTIONAL_STRING,
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
            "address": OPTIONAL_ADDRESS,
            "updated_time": SINGLE_OPTIONAL_STRING,
            "preferred_username": SINGLE_OPTIONAL_STRING,
            "_claim_names": SINGLE_OPTIONAL_JSON,
            "_claim_sources": SINGLE_OPTIONAL_JSON,
        }

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
        "redirect_uris": REQUIRED_LIST_OF_SP_SEP_STRINGS,
        "application_type": SINGLE_OPTIONAL_STRING,
        "access_token": SINGLE_OPTIONAL_STRING,
        "contacts": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "client_name": SINGLE_OPTIONAL_STRING,
        "logo_url": SINGLE_OPTIONAL_STRING,
        "token_endpoint_auth_method": SINGLE_OPTIONAL_STRING,
        "policy_url": SINGLE_OPTIONAL_STRING,
        "tos_url": SINGLE_OPTIONAL_STRING,
        "jwk_url": SINGLE_OPTIONAL_STRING,
        "jwk_encryption_url": SINGLE_OPTIONAL_STRING,
        "x509_url": SINGLE_OPTIONAL_STRING,
        "x509_encryption_url": SINGLE_OPTIONAL_STRING,
        "sector_identifier_url": SINGLE_OPTIONAL_STRING,
        "subject_type": SINGLE_OPTIONAL_STRING,
        "request_object_signing_alg": SINGLE_OPTIONAL_STRING,
        "userinfo_signed_response_algs": SINGLE_OPTIONAL_STRING,
        "userinfo_encrypted_response_alg": SINGLE_OPTIONAL_STRING,
        "userinfo_encrypted_response_enc": SINGLE_OPTIONAL_STRING,
        "id_token_signed_response_algs": SINGLE_OPTIONAL_STRING,
        "id_token_encrypted_response_alg": SINGLE_OPTIONAL_STRING,
        "id_token_encrypted_response_enc": SINGLE_OPTIONAL_STRING,
        "default_max_age": SINGLE_OPTIONAL_INT,
        "require_auth_time": OPTIONAL_LOGICAL,
        "default_acr":SINGLE_OPTIONAL_STRING,
        "initiate_login_uri":SINGLE_OPTIONAL_STRING,
        "post_logout_redirect_url":SINGLE_OPTIONAL_STRING,
        #"client_id": SINGLE_OPTIONAL_STRING,
        #"client_secret": SINGLE_OPTIONAL_STRING,
    }
    c_default = {"application_type": "web"}
    c_allowed_values = {
            "operation" : ["register", "client_update"],
            "application_type": ["native", "web"],
            "subject_type": ["public", "pairwise"]
        }

    def verify(self, **kwargs):
        if "initiate_login_uri" in self:
            assert self["initiate_login_uri"].startswith("https:")

        return super(RegistrationRequest, self).verify(**kwargs)

class RegistrationResponse(Message):
    """
    Response to client_register registration requests
    """
    c_param = {
        "redirect_uris": REQUIRED_LIST_OF_SP_SEP_STRINGS,
        "application_type": SINGLE_OPTIONAL_STRING,
        "access_token": SINGLE_OPTIONAL_STRING,
        "contacts": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "client_name": SINGLE_OPTIONAL_STRING,
        "logo_url": SINGLE_OPTIONAL_STRING,
        "token_endpoint_auth_method": SINGLE_OPTIONAL_STRING,
        "policy_url": SINGLE_OPTIONAL_STRING,
        "tos_url": SINGLE_OPTIONAL_STRING,
        "jwk_url": SINGLE_OPTIONAL_STRING,
        "jwk_encryption_url": SINGLE_OPTIONAL_STRING,
        "x509_url": SINGLE_OPTIONAL_STRING,
        "x509_encryption_url": SINGLE_OPTIONAL_STRING,
        "sector_identifier_url": SINGLE_OPTIONAL_STRING,
        "subject_type": SINGLE_OPTIONAL_STRING,
        "request_object_signing_alg": SINGLE_OPTIONAL_STRING,
        "userinfo_signed_response_algs": SINGLE_OPTIONAL_STRING,
        "userinfo_encrypted_response_alg": SINGLE_OPTIONAL_STRING,
        "userinfo_encrypted_response_enc": SINGLE_OPTIONAL_STRING,
        "id_token_signed_response_algs": SINGLE_OPTIONAL_STRING,
        "id_token_encrypted_response_alg": SINGLE_OPTIONAL_STRING,
        "id_token_encrypted_response_enc": SINGLE_OPTIONAL_STRING,
        "default_max_age": SINGLE_OPTIONAL_INT,
        "require_auth_time": OPTIONAL_LOGICAL,
        "default_acr":SINGLE_OPTIONAL_STRING,
        "initiate_login_uri":SINGLE_OPTIONAL_STRING,
        "post_logout_redirect_url":SINGLE_OPTIONAL_STRING,
        "client_id": SINGLE_REQUIRED_STRING,
        "client_secret": SINGLE_OPTIONAL_STRING,
        "registration_access_token": SINGLE_REQUIRED_STRING,
        "expires_at": SINGLE_OPTIONAL_INT,
        "issued_at": SINGLE_OPTIONAL_INT
    }

class ClientRegistrationErrorResponse(message.ErrorResponse):
    c_allowed_values= {"error":["invalid_operation", "invalid_client_id",
                                "invalid_client_secret",
                                "invalid_redirect_uri",
                                "invalid_configuration_parameter"]}

class IdToken(OpenIDSchema):
    c_param = OpenIDSchema.c_param.copy()
    c_param.update({
        "iss": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_REQUIRED_STRING,
        "aud": REQUIRED_LIST_OF_STRINGS, # Array of strings or string
        "azp": SINGLE_OPTIONAL_STRING,
        "exp": SINGLE_REQUIRED_INT,
        "iat": SINGLE_REQUIRED_INT,
        "acr": SINGLE_OPTIONAL_STRING,
        "nonce": SINGLE_OPTIONAL_STRING,
        "auth_time": SINGLE_OPTIONAL_INT,
        "at_hash": SINGLE_OPTIONAL_STRING,
        "c_hash": SINGLE_OPTIONAL_STRING,
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
    c_param = {
            "id_token": SINGLE_REQUIRED_STRING,
            "redirect_url": SINGLE_REQUIRED_STRING,
            "state": SINGLE_REQUIRED_STRING}

class EndSessionResponse(Message):
    c_param = {"state": SINGLE_REQUIRED_STRING}

class Claims(Message):
    c_param = {"*": SINGLE_OPTIONAL_JSON}

class UserInfoClaim(Message):
    c_param = {"claims": OPTIONAL_MULTIPLE_Claims,
               "preferred_locale": SINGLE_OPTIONAL_STRING}

class IDTokenClaim(Message):
    c_param = {"claims": OPTIONAL_MULTIPLE_Claims,
               "max_age": SINGLE_OPTIONAL_INT}

class OpenIDRequest(message.AuthorizationRequest):
    c_param = message.AuthorizationRequest.c_param.copy()
    c_param.update({"userinfo": SINGLE_OPTIONAL_USERINFO_CLAIM,
                    "id_token": SINGLE_OPTIONAL_ID_TOKEN_CLAIM,
                    "iss": SINGLE_OPTIONAL_STRING,
                    "aud": OPTIONAL_LIST_OF_STRINGS, # Array of strings or string
                    #"nonce": SINGLE_OPTIONAL_STRING,
                    "registration": SINGLE_OPTIONAL_REGISTRATION_REQUEST})

class ProviderConfigurationResponse(Message):
    c_param = {
            "version": SINGLE_REQUIRED_STRING,
            "issuer": SINGLE_REQUIRED_STRING,
            "authorization_endpoint": SINGLE_OPTIONAL_STRING,
            "token_endpoint": SINGLE_OPTIONAL_STRING,
            "userinfo_endpoint": SINGLE_OPTIONAL_STRING,
            "check_session_iframe": SINGLE_OPTIONAL_STRING,
            "end_session_endpoint": SINGLE_OPTIONAL_STRING,
            "jwk_url": SINGLE_OPTIONAL_STRING,
            "jwk_encryption_url": SINGLE_OPTIONAL_STRING,
            "x509_url": SINGLE_REQUIRED_STRING,
            "x509_encryption_url": SINGLE_OPTIONAL_STRING,
            "registration_endpoint": SINGLE_OPTIONAL_STRING,
            "scopes_supported": OPTIONAL_LIST_OF_STRINGS,
            "response_types_supported": REQUIRED_LIST_OF_STRINGS,
            "acr_values_supported": OPTIONAL_LIST_OF_STRINGS,
            "subject_types_supported": REQUIRED_LIST_OF_STRINGS,
            "userinfo_signing_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
            "userinfo_encryption_alg_values_supported":
                                                    OPTIONAL_LIST_OF_STRINGS,
            "userinfo_encryption_enc_values_supported":
                                                    OPTIONAL_LIST_OF_STRINGS,
            "id_token_signing_alg_values_supported": REQUIRED_LIST_OF_STRINGS,
            "id_token_encryption_alg_values_supported":
                                                    OPTIONAL_LIST_OF_STRINGS,
            "id_token_encryption_enc_values_supported":
                                                    OPTIONAL_LIST_OF_STRINGS,
            "request_object_signing_alg_values_supported":
                                                    OPTIONAL_LIST_OF_STRINGS,
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
            "service_documentation": SINGLE_OPTIONAL_STRING
            }
    c_default = {"version": "3.0",
                 "token_endpoint_auth_methods_supported":"client_secret_basic"}

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
            "aud": REQUIRED_LIST_OF_STRINGS, # Array of strings or string
            "jti": SINGLE_REQUIRED_STRING,
            "exp": SINGLE_REQUIRED_INT,
            "iat": SINGLE_OPTIONAL_INT,
            "azp": SINGLE_OPTIONAL_INT,
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
                "birthdate", "zoneinfo", "locale", "updated_time",
                "preferred_username"],
    "email": ["email", "email_verified"],
    "address": ["address"],
    "phone": ["phone_number"],
    "offline_access": []
}

MSG = {
    "RefreshAccessTokenRequest" : RefreshAccessTokenRequest,
    "TokenErrorResponse" :TokenErrorResponse,
    "AccessTokenResponse": AccessTokenResponse,
    "UserInfoRequest": UserInfoRequest,
    "AuthorizationResponse" : AuthorizationResponse,
    "AuthorizationErrorResponse" : AuthorizationErrorResponse,
    "AuthorizationRequest": AuthorizationRequest,
    "AccessTokenRequest" : AccessTokenRequest,
    "AddressClaim": AddressClaim,
    "OpenIDSchema": OpenIDSchema,
    "RegistrationRequest": RegistrationRequest,
    "RegistrationResponse" : RegistrationResponse,
    "ClientRegistrationErrorResponse": ClientRegistrationErrorResponse,
    "IdToken": IdToken,
    "RefreshSessionRequest": RefreshSessionRequest,
    "RefreshSessionResponse": RefreshSessionResponse,
    "CheckSessionRequest": CheckSessionRequest,
    "CheckIDRequest": CheckIDRequest,
    "EndSessionRequest": EndSessionRequest,
    "EndSessionResponse": EndSessionResponse,
    "Claims": Claims,
    "UserInfoClaim": UserInfoClaim,
    "IDTokenClaim": IDTokenClaim,
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
        else:
            raise Exception("Unknown message type: %s" % msgtype)

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