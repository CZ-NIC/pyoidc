from oic.oauth2 import Message
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

MSG = {
    "TokenRevocationRequest": TokenRevocationRequest,
    "TokenIntrospectionRequest": TokenIntrospectionRequest,
    "TokenIntrospectionResponse": TokenIntrospectionResponse,
    "SoftwareStatement": SoftwareStatement,
}
