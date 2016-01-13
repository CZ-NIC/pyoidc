from oic.oauth2 import Message, FormatError
from oic.oauth2.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oic.oauth2.message import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS
from oic.oauth2.message import SINGLE_OPTIONAL_INT
from oic.oauth2.message import SINGLE_OPTIONAL_STRING
from oic.oauth2.message import SINGLE_REQUIRED_STRING
from oic.oic.message import SINGLE_REQUIRED_INT

__author__ = 'roland'


# RFC 7662
class TokenIntrospectionRequest(Message):
    c_param = {
        'token': SINGLE_REQUIRED_STRING,
        'token_type_hint': SINGLE_OPTIONAL_STRING
    }


class TokenIntrospectionResponse(Message):
    c_param = {
        'active': SINGLE_REQUIRED_STRING,
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
        'token_type_hint': SINGLE_OPTIONAL_STRING
    }


class SoftwareStatement(Message):
    c_param = {
        "iss": SINGLE_REQUIRED_STRING,
        "aud": REQUIRED_LIST_OF_STRINGS,  # Array of strings or string
        "exp": SINGLE_REQUIRED_INT,
        "iat": SINGLE_OPTIONAL_INT,
        "nbf": SINGLE_OPTIONAL_INT,
        "cnf": SINGLE_OPTIONAL_INT
    }


class ASConfigurationResponse(Message):
    c_param = {
        "issuer": SINGLE_REQUIRED_STRING,
        "authorization_endpoint": SINGLE_OPTIONAL_STRING,
        "token_endpoint": SINGLE_OPTIONAL_STRING,
        'introspection_endpoint': SINGLE_OPTIONAL_STRING,
        'revocation_endpoint': SINGLE_OPTIONAL_STRING,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "registration_endpoint": SINGLE_OPTIONAL_STRING,
        "scopes_supported": OPTIONAL_LIST_OF_STRINGS,
        "response_types_supported": REQUIRED_LIST_OF_STRINGS,
        "response_modes_supported": OPTIONAL_LIST_OF_STRINGS,
        "grant_types_supported": REQUIRED_LIST_OF_STRINGS,
        "token_endpoint_auth_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "token_endpoint_auth_signing_alg_values_supported":
            OPTIONAL_LIST_OF_STRINGS,
        "service_documentation": SINGLE_OPTIONAL_STRING,
        "ui_locales_supported": OPTIONAL_LIST_OF_STRINGS,
        "op_policy_uri": SINGLE_OPTIONAL_STRING,
        "op_tos_uri": SINGLE_OPTIONAL_STRING,
    }
    c_default = {"version": "3.0"}


class StateJWT(Message):
    c_param = {
        'rfp': SINGLE_REQUIRED_STRING,
        'kid': SINGLE_OPTIONAL_STRING,
        'iat': SINGLE_OPTIONAL_INT,
        'exp': SINGLE_OPTIONAL_INT,
        'iss': SINGLE_OPTIONAL_STRING,
        'aud': SINGLE_OPTIONAL_STRING,
        'target_link__uri': SINGLE_OPTIONAL_STRING,
        'as': SINGLE_OPTIONAL_STRING,
        'jti': SINGLE_OPTIONAL_STRING,
        'at_hash': SINGLE_OPTIONAL_STRING,
        'c_hash': SINGLE_OPTIONAL_STRING
    }



MSG = {
    "TokenRevocationRequest": TokenRevocationRequest,
    "TokenIntrospectionRequest": TokenIntrospectionRequest,
    "TokenIntrospectionResponse": TokenIntrospectionResponse,
    "SoftwareStatement": SoftwareStatement,
    'ASConfigurationResponse': ASConfigurationResponse
}


def factory(msgtype):
    try:
        return MSG[msgtype]
    except KeyError:
        raise FormatError("Unknown message type: %s" % msgtype)
