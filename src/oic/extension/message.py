import requests
import six
import inspect

from future.backports.urllib.parse import urlparse
import sys

from oic.exception import InvalidRedirectUri
from oic.exception import MissingPage

from oic.oauth2.message import ErrorResponse
from oic.oauth2.message import Message
from oic.oauth2.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oic.oauth2.message import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS
from oic.oauth2.message import SINGLE_OPTIONAL_INT
from oic.oauth2.message import SINGLE_OPTIONAL_STRING
from oic.oauth2.message import SINGLE_REQUIRED_STRING

from oic.oic.message import JasonWebToken

from oic.utils.http_util import SUCCESSFUL
from oic.utils.jwt import JWT

__author__ = 'roland'


# RFC 7662
class TokenIntrospectionRequest(Message):
    c_param = {
        'token': SINGLE_REQUIRED_STRING,
        'token_type_hint': SINGLE_OPTIONAL_STRING,
        # The ones below are part of authentication information
        'client_id': SINGLE_OPTIONAL_STRING,
        'client_assertion_type': SINGLE_OPTIONAL_STRING,
        'client_assertion': SINGLE_OPTIONAL_STRING
    }


SINGLE_REQUIRED_BOOLEAN = (bool, True, None, None, False)


class TokenIntrospectionResponse(Message):
    c_param = {
        'active': SINGLE_REQUIRED_BOOLEAN,
        'scope': OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        'client_id': SINGLE_OPTIONAL_STRING,
        'username': SINGLE_OPTIONAL_STRING,
        'token_type': SINGLE_OPTIONAL_STRING,
        'exp': SINGLE_OPTIONAL_INT,
        'iat': SINGLE_OPTIONAL_INT,
        'nbf': SINGLE_OPTIONAL_INT,
        'sub': SINGLE_OPTIONAL_STRING,
        'aud': OPTIONAL_LIST_OF_STRINGS,
        'iss': SINGLE_OPTIONAL_STRING,
        'jti': SINGLE_OPTIONAL_STRING
    }


# RFC 7009
class TokenRevocationRequest(Message):
    c_param = {
        'token': SINGLE_REQUIRED_STRING,
        'token_type_hint': SINGLE_OPTIONAL_STRING,
        'client_id': SINGLE_OPTIONAL_STRING,
        'client_assertion_type': SINGLE_OPTIONAL_STRING,
        'client_assertion': SINGLE_OPTIONAL_STRING
    }


class SoftwareStatement(JasonWebToken):
    c_param = JasonWebToken.c_param.copy()
    c_param.update({
        "software_id": SINGLE_OPTIONAL_STRING,
        'client_name': SINGLE_OPTIONAL_STRING,
        'client_uri': SINGLE_OPTIONAL_STRING
    })


class StateJWT(JasonWebToken):
    c_param = JasonWebToken.c_param.copy()
    c_param.update({
        'aud': SINGLE_OPTIONAL_STRING,
        'rfp': SINGLE_REQUIRED_STRING,
        'kid': SINGLE_OPTIONAL_STRING,
        'target_link__uri': SINGLE_OPTIONAL_STRING,
        'as': SINGLE_OPTIONAL_STRING,
        'at_hash': SINGLE_OPTIONAL_STRING,
        'c_hash': SINGLE_OPTIONAL_STRING
    })


class ServerMetadata(Message):
    c_param = {
        'issuer': SINGLE_REQUIRED_STRING,
        'authorization_endpoint': SINGLE_OPTIONAL_STRING,
        'token_endpoint': SINGLE_OPTIONAL_STRING,
        'jwks_uri': SINGLE_REQUIRED_STRING,
        'registration_endpoint': SINGLE_OPTIONAL_STRING,
        'scopes_supported': OPTIONAL_LIST_OF_STRINGS,
        'response_types_supported': REQUIRED_LIST_OF_STRINGS,
        'response_modes_supported': OPTIONAL_LIST_OF_STRINGS,
        'grant_types_supported': OPTIONAL_LIST_OF_STRINGS,
        'token_endpoint_auth_methods_supported': OPTIONAL_LIST_OF_STRINGS,
        'token_endpoint_auth_signing_alg_values_supported':
            OPTIONAL_LIST_OF_STRINGS,
        'service_documentation': SINGLE_OPTIONAL_STRING,
        'ui_locales_supported': OPTIONAL_LIST_OF_STRINGS,
        'op_policy_uri': SINGLE_OPTIONAL_STRING,
        'op_tos_uri': SINGLE_OPTIONAL_STRING,
        'revocation_endpoint': SINGLE_OPTIONAL_STRING,
        'revocation_endpoint_auth_methods_supported': OPTIONAL_LIST_OF_STRINGS,
        'revocation_endpoint_auth_signing_alg_values_supported':
            OPTIONAL_LIST_OF_STRINGS,
        'introspection_endpoint': SINGLE_OPTIONAL_STRING,
        'introspection_endpoint_auth_methods_supported':
            OPTIONAL_LIST_OF_STRINGS,
        'introspection_endpoint_auth_signing_alg_values_supported':
            OPTIONAL_LIST_OF_STRINGS,
        'code_challenge_methods_supported': OPTIONAL_LIST_OF_STRINGS
    }


class RegistrationRequest(Message):
    c_param = {
        "redirect_uris": REQUIRED_LIST_OF_STRINGS,
        "client_name": SINGLE_OPTIONAL_STRING,
        "client_uri": SINGLE_OPTIONAL_STRING,
        "logo_uri": SINGLE_OPTIONAL_STRING,
        "contacts": OPTIONAL_LIST_OF_STRINGS,
        "tos_uri": SINGLE_OPTIONAL_STRING,
        "policy_uri": SINGLE_OPTIONAL_STRING,
        "token_endpoint_auth_method": SINGLE_OPTIONAL_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "grant_types": OPTIONAL_LIST_OF_STRINGS,
        "response_types": OPTIONAL_LIST_OF_STRINGS,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "software_id": SINGLE_OPTIONAL_STRING,
        "software_version": SINGLE_OPTIONAL_STRING,
        'software_statement': OPTIONAL_LIST_OF_STRINGS
    }

    def verify(self, **kwargs):
        if "initiate_login_uri" in self:
            assert self["initiate_login_uri"].startswith("https:")

        if "redirect_uris" in self:
            for uri in self["redirect_uris"]:
                if urlparse(uri).fragment:
                    raise InvalidRedirectUri(
                        "redirect_uri contains fragment: %s" % uri)

        for uri in ["client_uri", "logo_uri", "tos_uri", "policy_uri"]:
            if uri in self:
                try:
                    resp = requests.request("GET", str(self[uri]),
                                            allow_redirects=True,
                                            verify=False)
                except requests.ConnectionError:
                    raise MissingPage(self[uri])

                if resp.status_code not in SUCCESSFUL:
                    raise MissingPage(self[uri])

        # if "grant_types" in self and "response_types" in self:
        #     for typ in self["grant_types"]:
        #         if typ == "authorization_code":
        #             assert "code" in self["response_types"]
        #         elif typ == "implicit":
        #             assert "token" in self["response_types"]

        try:
            ss = self['software_statement']
        except:
            pass
        else:
            # need to get the client keys before I can verify any signature
            kj = kwargs['keyjar']
            # The case where jwks_uri is used
            # try:
            #     kj.add(,self['jwks_uri'])
            _ss = []
            for _s in ss:
                _ss.append(unpack_software_statement(_s, '', kwargs['keyjar']))
            self['__software_statement'] = _ss

        return super(RegistrationRequest, self).verify(**kwargs)


class ClientInfoResponse(RegistrationRequest):
    c_param = RegistrationRequest.c_param.copy()
    c_param.update({
        "client_id": SINGLE_REQUIRED_STRING,
        "client_secret": SINGLE_OPTIONAL_STRING,
        "client_id_issued_at": SINGLE_OPTIONAL_INT,
        "client_secret_expires_at": SINGLE_OPTIONAL_INT,
        "registration_access_token": SINGLE_REQUIRED_STRING,
        "registration_client_uri": SINGLE_REQUIRED_STRING
    })


class ClientRegistrationError(ErrorResponse):
    c_param = ErrorResponse.c_param.copy()
    c_param.update({"state": SINGLE_OPTIONAL_STRING})
    c_allowed_values = ErrorResponse.c_allowed_values.copy()
    c_allowed_values.update({"error": ["invalid_redirect_uri",
                                       "invalid_client_metadata",
                                       "invalid_client_id"]})


class ClientUpdateRequest(RegistrationRequest):
    c_param = RegistrationRequest.c_param.copy()
    c_param.update({
        "client_id": SINGLE_REQUIRED_STRING,
        "client_secret": SINGLE_OPTIONAL_STRING,
        'client_assertion_type': SINGLE_OPTIONAL_STRING,
        'client_assertion': SINGLE_OPTIONAL_STRING
    })


MSG = {
    "RegistrationRequest": RegistrationRequest,
    "ClientInfoResponse": ClientInfoResponse,
    "ClientRegistrationError": ClientRegistrationError,
    "ClientUpdateRequest": ClientUpdateRequest,
    "TokenRevocationRequest": TokenRevocationRequest,
    "TokenIntrospectionRequest": TokenIntrospectionRequest,
    "TokenIntrospectionResponse": TokenIntrospectionResponse,
    "SoftwareStatement": SoftwareStatement,
    'StateJWT': StateJWT
}


def factory(msgtype):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Message):
            try:
                if obj.__name__ == msgtype:
                    return obj
            except AttributeError:
                pass

    # check among standard OAuth2 messages
    from oic.oauth2 import message

    return message.factory(msgtype)


def make_software_statement(keyjar, iss, **kwargs):
    if six.PY2:
        params = inspect.getargspec(JWT.__init__).args
    else:
        params = list(inspect.signature(JWT.__init__).parameters.keys())

    params.remove('self')

    args = {}
    for param in params:
        try:
            args[param] = kwargs[param]
        except KeyError:
            pass
        else:
            del kwargs[param]

    _jwt = JWT(keyjar, msgtype=SoftwareStatement, iss=iss, **args)
    return _jwt.pack(**kwargs)


def unpack_software_statement(software_statement, iss, keyjar):
    _jwt = JWT(keyjar, iss=iss, msgtype=SoftwareStatement)
    return _jwt.unpack(software_statement)