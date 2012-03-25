__author__ = 'rohe0002'

import urllib

from oic.oauth2.message import SCHEMA as OA2_SCHEMA

from oic.oauth2.message import Message
from oic.oauth2.message import join_spec
from oic.oauth2.message import SINGLE_OPTIONAL_STRING
from oic.oauth2.message import SINGLE_REQUIRED_STRING
from oic.oauth2.message import SINGLE_OPTIONAL_INT
from oic.oauth2.message import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS
from oic.oauth2.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
#from oic.oauth2.message import REQUIRED_LIST_OF_SP_SEP_STRINGS

import json

#noinspection PyUnusedLocal
def json_ser(val, format=None):
    return json.dumps(val)

#noinspection PyUnusedLocal
def json_deser(val, format=None):
    return json.loads(val)

SINGLE_OPTIONAL_JWT = SINGLE_OPTIONAL_STRING
SINGLE_OPTIONAL_BOOLEAN = (bool, False, None, None)
SINGLE_OPTIONAL_JSON = (dict, False, json_ser, json_deser)
SINGLE_REQUIRED_INT = (int, True, None, None)


def message(_type_, **kwargs):
    try:
        if isinstance(_type_, basestring):
            _name = lc_types[_type_.lower()]
            m = Message(_name, SCHEMA[lc_types[_type_.lower()]], **kwargs)
        else:
            m = Message(_type_["name"], _type_, **kwargs)
        return m
    except KeyError:
        raise Exception("Unknown message type")

def msg_deser(val, format, typ="", schema=None, **kwargs):
    if typ:
        return message(typ).deserialize(val, format, **kwargs)
    else:
        return Message(schema["name"], schema).deserialize(val, format,
                                                           **kwargs)

def idtoken_deser(val, format="urlencoded"):
    return msg_deser(val, format, "IdToken")

def idtokenclaim_deser(val, format="urlencoded"):
    if format in ["dict", "json"]:
        if isinstance(val, basestring):
            val = json.loads(val)
    return msg_deser(val, format, "IDTokenClaim")

def userinfo_deser(val, format="urlencoded"):
    if format in ["dict", "json"]:
        if isinstance(val, basestring):
            val = json.loads(val)
    return msg_deser(val, format, "UserInfoClaim")

def address_deser(val, format="urlencoded"):
    if format in ["dict", "json"]:
        if isinstance(val, basestring):
            val = json.loads(val)
    return msg_deser(val, format, "AddressClaim")

def claims_deser(val, format="urlencoded"):
    if format in ["dict", "json"]:
        if isinstance(val, basestring):
            val = json.loads(val)
    return msg_deser(val, format, "Claims")

def srvdir_deser(val, format="urlencoded"):
    if format in ["dict", "json"]:
        if isinstance(val, basestring):
            val = json.loads(val)
    return msg_deser(val, format, "SWDServiceRedirect")

def keyobj_list_deser(val_list, format="urlencoded"):
    return [msg_deser(val, format, "JWKKeyObject") for val in val_list]

def msg_ser(inst, format, lev=0):
    if format in ["urlencoded", "json"]:
        res = inst.serialize(format, lev)
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

OPTIONAL_ADDRESS = (Message, False, msg_ser, address_deser)
OPTIONAL_MULTIPLE_Claims = (Message, False, claims_ser, claims_deser)
SINGLE_OPTIONAL_USERINFO_CLAIM = (Message, False, msg_ser, userinfo_deser)
SINGLE_OPTIONAL_ID_TOKEN_CLAIM = (Message, False, msg_ser, idtokenclaim_deser)

REQUIRED_LIST_OF_KEYOBJECTS = ([Message], True, msg_list_ser,
                                          keyobj_list_deser)
SINGLE_OPTIONAL_SERVICE_REDIRECT = (Message, True, msg_ser, srvdir_deser)

# ----------------------------------------------------------------------------

def verify_id_token(self, **kwargs):
    if self.id_token:
        # Try to decode the JWT, checks the signature
        idt = message("IdToken").from_jwt(str(self.id_token), kwargs["key"])
        if not idt.verify(**kwargs):
            return False

    return super(self.__class__, self).verify(**kwargs)

def verify_idtoken(self, **kwargs):
    if self.aud:
        if "client_id" in kwargs:
            # check that it's for me
            if self.aud != kwargs["client_id"]:
                return False

    return super(self.__class__, self).verify(**kwargs)

# -----------------------------------------------------------------------------

MSGDEF = {
    "": {"param": {}},
    "AccessTokenResponse": {
        "param": {
            "id_token": SINGLE_OPTIONAL_STRING,
            },
        "parent": [OA2_SCHEMA["AccessTokenResponse"]]
    },
    "RefreshAccessTokenRequest": {
        "param": {},
        "parent": [OA2_SCHEMA["RefreshAccessTokenRequest"]]
    },
    "UserInfoRequest": {
        "param": {
            "access_token": SINGLE_OPTIONAL_STRING,
            "schema": SINGLE_OPTIONAL_STRING,
            "id": SINGLE_OPTIONAL_STRING,
        }
    },
    "AuthorizationResponse": {
        "param": {
            "code": SINGLE_OPTIONAL_STRING,
            "nonce": SINGLE_OPTIONAL_STRING,
            "access_token": SINGLE_OPTIONAL_STRING,
            "token_type": SINGLE_OPTIONAL_STRING,
        },
        "parent": [OA2_SCHEMA["AuthorizationResponse"], "AccessTokenResponse"],
        "verify": verify_id_token,
    },
    "AuthorizationErrorResponse": {
        "param": {},
        "parent": [OA2_SCHEMA["AuthorizationErrorResponse"]],
        "allowed_values": {
            "error": ["invalid_request_redirect_uri", "interaction_required",
                      "invalid_request_uri", "invalid_openid_request_object"]
        }
    },
    "TokenErrorResponse": {
        "param": {},
        "parent": [OA2_SCHEMA["TokenErrorResponse"]],
    },
    "AuthorizationRequest": {
        "param": {
            "request": SINGLE_OPTIONAL_JWT,
            #"request_uri": SINGLE_OPTIONAL_STRING,
            "display": SINGLE_OPTIONAL_STRING,
            "prompt": OPTIONAL_LIST_OF_STRINGS,
            "nonce": SINGLE_REQUIRED_STRING
        },
        "parent": [OA2_SCHEMA["AuthorizationRequest"]],
        "allowed_values": {
            "display": ["page", "popup", "touch", "wap", "embedded"],
            "prompt": ["none", "login", "consent", "select_account"]
        }
    },
    "AccessTokenRequest": {
        "param": {
            "client_id": SINGLE_REQUIRED_STRING,
            "client_secret": SINGLE_OPTIONAL_STRING,
            "client_assertion_type": SINGLE_OPTIONAL_STRING,
            "client_assertion": SINGLE_OPTIONAL_STRING
        },
        "parent": [OA2_SCHEMA["AccessTokenRequest"]],
    },
    "AddressClaim": {
        "param": {
            "formatted": SINGLE_OPTIONAL_STRING,
            "street_address": SINGLE_OPTIONAL_STRING,
            "locality": SINGLE_OPTIONAL_STRING,
            "region": SINGLE_OPTIONAL_STRING,
            "postal_code": SINGLE_OPTIONAL_STRING,
            "country": SINGLE_OPTIONAL_STRING,
        },
    },
    "OpenIDSchema": {
        "param": {
            "user_id": SINGLE_OPTIONAL_STRING,
            "name": SINGLE_OPTIONAL_STRING,
            "given_name": SINGLE_OPTIONAL_STRING,
            "family_name": SINGLE_OPTIONAL_STRING,
            "middle_name": SINGLE_OPTIONAL_STRING,
            "nickname": SINGLE_OPTIONAL_STRING,
            "profile": SINGLE_OPTIONAL_STRING,
            "picture": SINGLE_OPTIONAL_STRING,
            "website": SINGLE_OPTIONAL_STRING,
            "email": SINGLE_OPTIONAL_STRING,
            "verified": SINGLE_OPTIONAL_BOOLEAN,
            "gender": SINGLE_OPTIONAL_STRING,
            "birthday": SINGLE_OPTIONAL_STRING,
            "zoneinfo": SINGLE_OPTIONAL_STRING,
            "locale": SINGLE_OPTIONAL_STRING,
            "phone_number": SINGLE_OPTIONAL_STRING,
            "address": OPTIONAL_ADDRESS,
            "updated_time": SINGLE_OPTIONAL_STRING,
            "_claim_names": SINGLE_OPTIONAL_JSON,
            "_claim_sources": SINGLE_OPTIONAL_JSON,
        },
    },
    "RegistrationRequest": {
        "param": {
            "type": SINGLE_REQUIRED_STRING,
            "client_id": SINGLE_OPTIONAL_STRING,
            "client_secret": SINGLE_OPTIONAL_STRING,
            "access_token": SINGLE_OPTIONAL_STRING,
            "contacts": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
            "application_type": SINGLE_OPTIONAL_STRING,
            "application_name": SINGLE_OPTIONAL_STRING,
            "logo_url": SINGLE_OPTIONAL_STRING,
            "redirect_uris": OPTIONAL_LIST_OF_STRINGS,
            "token_endpoint_auth_type": SINGLE_OPTIONAL_STRING,
            "policy_url": SINGLE_OPTIONAL_STRING,
            "jwk_url": SINGLE_OPTIONAL_STRING,
            "jwk_encryption_url": SINGLE_OPTIONAL_STRING,
            "x509_url": SINGLE_OPTIONAL_STRING,
            "x509_encryption_url": SINGLE_OPTIONAL_STRING,
            "sector_identifier_url": SINGLE_OPTIONAL_STRING,
            "user_id_type": SINGLE_OPTIONAL_STRING,
            "require_signed_request_object": SINGLE_OPTIONAL_STRING,
            "userinfo_signed_response_algs": SINGLE_OPTIONAL_STRING,
            "userinfo_encrypted_response_algs": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
            "id_token_signed_response_algs": SINGLE_OPTIONAL_STRING,
            "id_token_encrypted_response_algs": OPTIONAL_LIST_OF_SP_SEP_STRINGS,

        },
        "allowed_values": {
            "type" : ["client_associate", "client_update"],
            "application_type": ["native", "web"]
        }

    },
    "RegistrationResponse": {
        "param": {
            "client_id": SINGLE_REQUIRED_STRING,
            "client_secret": SINGLE_REQUIRED_STRING,
            "expires_at": SINGLE_REQUIRED_INT,
        },
    },
    "ClientRegistrationErrorResponse": {
        "param": {},
        "parent": [OA2_SCHEMA["ErrorResponse"]],
        "allowed_values": {
            "error": ["invalid_type", "invalid_client_id",
                      "invalid_client_secret",
                      "invalid_configuration_parameter"]
        }
    },
    "IdToken": {
        "param": {
            "iss": SINGLE_REQUIRED_STRING,
            "user_id": SINGLE_REQUIRED_STRING,
            "aud": SINGLE_REQUIRED_STRING,
            "exp": SINGLE_REQUIRED_INT,
            "acr": SINGLE_OPTIONAL_STRING,
            "nonce": SINGLE_OPTIONAL_STRING,
            "auth_time": SINGLE_OPTIONAL_INT,
        },
        "verify": verify_idtoken
    },
    "RefreshSessionRequest": {
        "param": {
            "id_token": SINGLE_REQUIRED_STRING,
            "redirect_url": SINGLE_REQUIRED_STRING,
            "state": SINGLE_REQUIRED_STRING
        },
    },
    "RefreshSessionResponse": {
        "param": {
            "id_token": SINGLE_REQUIRED_STRING,
            "state": SINGLE_REQUIRED_STRING
        },
    },
    "CheckSessionRequest": {
        "param": {
            "id_token": SINGLE_REQUIRED_STRING,
        },
    },
    "CheckIDRequest": {
        "param": {
            "access_token": SINGLE_REQUIRED_STRING,
        },
    },
    "EndSessionRequest": {
        "param": {
            "id_token": SINGLE_REQUIRED_STRING,
            "redirect_url": SINGLE_REQUIRED_STRING,
            "state": SINGLE_REQUIRED_STRING
        },
    },
    "EndSessionResponse": {
        "param": {
            "state": SINGLE_REQUIRED_STRING
        },
    },
    "Claims": {
        "param": {"*": SINGLE_OPTIONAL_JSON }
    },
    "UserInfoClaim": {
        "param": {
            "claims": OPTIONAL_MULTIPLE_Claims,
            "preferred_locale": SINGLE_OPTIONAL_STRING
        }
    },
    "IDTokenClaim": {
        "param": {
            "claims": OPTIONAL_MULTIPLE_Claims,
            "max_age": SINGLE_OPTIONAL_INT
        }
    },
    "OpenIDRequest": {
        "param": {
            "userinfo": SINGLE_OPTIONAL_USERINFO_CLAIM,
            "id_token": SINGLE_OPTIONAL_ID_TOKEN_CLAIM,
            "iss": SINGLE_OPTIONAL_STRING,
            "aud": SINGLE_OPTIONAL_STRING,
        },
        "parent": ["AuthorizationRequest"]
    },
    "ProviderConfigurationResponse": {
        "param": {
            "version": SINGLE_OPTIONAL_STRING,
            "issuer": SINGLE_OPTIONAL_STRING,
            "authorization_endpoint": SINGLE_OPTIONAL_STRING,
            "token_endpoint": SINGLE_OPTIONAL_STRING,
            "userinfo_endpoint": SINGLE_OPTIONAL_STRING,
            "check_id_endpoint": SINGLE_OPTIONAL_STRING,
            "refresh_session_endpoint": SINGLE_OPTIONAL_STRING,
            "end_session_endpoint": SINGLE_OPTIONAL_STRING,
            "registration_endpoint": SINGLE_OPTIONAL_STRING,
            "jwk_url": SINGLE_OPTIONAL_STRING,
            "x509_url": SINGLE_OPTIONAL_STRING,
            "jwk_encryption_url": SINGLE_OPTIONAL_STRING,
            "x509_encryption_url": SINGLE_OPTIONAL_STRING,
            "scopes_supported": OPTIONAL_LIST_OF_STRINGS,
            "response_types_supported": OPTIONAL_LIST_OF_STRINGS,
            "acrs_supported": OPTIONAL_LIST_OF_STRINGS,
            "user_id_types_supported": OPTIONAL_LIST_OF_STRINGS,
            "userinfo_algs_supported": OPTIONAL_LIST_OF_STRINGS,
            "id_token_algs_supported": OPTIONAL_LIST_OF_STRINGS,
            "request_object_algs_supported": OPTIONAL_LIST_OF_STRINGS,
            "token_endpoint_auth_types_supported": OPTIONAL_LIST_OF_STRINGS,
            "token_endpoint_auth_algs_supported": OPTIONAL_LIST_OF_STRINGS,
        },
        "default": {"version": "3.0"}
    },
    "JWKKeyObject": {
        "param": {
            "algorithm": SINGLE_REQUIRED_STRING,
            "use": SINGLE_OPTIONAL_STRING,
            "keyid": SINGLE_OPTIONAL_STRING,
        }
    },
    "JWKEllipticKeyObject": {
        "param": {
            "curve": SINGLE_REQUIRED_STRING,
            "x": SINGLE_OPTIONAL_STRING,
            "y": SINGLE_OPTIONAL_STRING
        },
        "parent": ["JWKKeyObject"],
        "default": {"algorithm": "EC"}
    },
    "JWKRSAKeyObject": {
        "param": {
            "exponent": SINGLE_REQUIRED_STRING,
            "modulus": SINGLE_OPTIONAL_STRING
        },
        "parent": ["JWKKeyObject"],
        "default": {"algorithm": "RSA"}
    },
    "JWKContainerObject":{
        "param": {"keyvalues": REQUIRED_LIST_OF_KEYOBJECTS}
    },
    "IssuerRequest":{
        "param": {
            "service": SINGLE_REQUIRED_STRING,
            "principal": SINGLE_REQUIRED_STRING,
        }
    },
    "SWDServiceRedirect":{
        "param": {
            "location": SINGLE_REQUIRED_STRING,
            "expires": SINGLE_OPTIONAL_INT
        }
    },
    "IssuerResponse":{
        "param": {
            "locations": OPTIONAL_LIST_OF_STRINGS,
            "SWD_service_redirect": SINGLE_OPTIONAL_SERVICE_REDIRECT
        }
    },
    "AuthnToken":{
        "param": {
            "iss": SINGLE_REQUIRED_STRING,
            "prn": SINGLE_REQUIRED_STRING,
            "aud": SINGLE_REQUIRED_STRING,
            "jti": SINGLE_REQUIRED_STRING,
            "exp": SINGLE_REQUIRED_INT,
            "iat": SINGLE_OPTIONAL_INT
        }
    },
    "UserInfoErrorResponse":{
        "param": {},
        "allowed_values": {"error": ["invalid_schema", "invalid_request",
                                     "invalid_token", "insufficient_scope"]
        },
        "parent": [OA2_SCHEMA["ErrorResponse"]]
    },
    "DiscoveryRequest": {
        "param": {
            "principal": SINGLE_REQUIRED_STRING,
            "service": SINGLE_REQUIRED_STRING
        }
    },
    "DiscoveryResponse": {
        "param": {
            "locations": REQUIRED_LIST_OF_STRINGS
        }
    }
}

def inherit(spec, parent):
    for p in parent:
        if isinstance(p, dict):
            _spec = p
        else:
            _spec = MSGDEF[p]
        spec = join_spec(spec, _spec)

    return spec

SCHEMA = {}
for key, _spec in MSGDEF.items():
    if "parent" in _spec:
        SCHEMA[key] = inherit(_spec, _spec["parent"])
    else:
        SCHEMA[key] = _spec
    SCHEMA[key]["mod"] = __name__
    SCHEMA[key]["name"] = key

lc_types = dict((x.lower(), x) for x in SCHEMA.keys())

SCOPE2CLAIMS = {
    "openid": ["user_id"],
    "profile": ["name", "given_name", "family_name", "middle_name",
                "nickname", "profile", "picture", "website", "gender",
                "birthday", "zoneinfo", "locale", "updated_time"],
    "email": ["email", "verified"],
    "address": ["address"],
    "phone": ["phone_number"]
}

if __name__ == "__main__":
    atr = message("AccessTokenResponse", access_token="access_token",
                  token_type="token_type")
    print atr
    print atr.verify()

    atr = message("AccessTokenRequest", code="code", client_id="client_id",
                  redirect_uri="redirect_uri")
    print atr
    print atr.verify()
    uue = atr.serialize()
    atr = msg_deser("AccessTokenRequest", uue, "urlencoded")
    print atr