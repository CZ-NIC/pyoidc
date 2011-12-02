#!/usr/bin/env python

from oic import oauth2
import json
import jwt
import tempfile
import os
import os.path
import urlparse
import urllib

from oic.oauth2 import SINGLE_OPTIONAL_STRING
from oic.oauth2 import SINGLE_REQUIRED_STRING
from oic.oauth2 import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2 import SINGLE_OPTIONAL_INT
from oic.oauth2 import HTTP_ARGS
from oic.utils.time_util import time_sans_frac

def to_json(dic):
    return json.dumps(dic)

#noinspection PyUnusedLocal
def from_json(str, extended=None):
    return json.loads(str)

SINGLE_OPTIONAL_JWT = SINGLE_OPTIONAL_STRING
SINGLE_OPTIONAL_BOOLEAN = (bool, False, None, None)
SINGLE_OPTIONAL_JSON = (dict, False, to_json, from_json)
SINGLE_REQUIRED_INT = (int, True, None, None)

def base_deser(cls, val, format, extended=False):
    if format == "urlencoded":
        res = cls.set_urlencoded(val, extended)
    elif format == "json":
        res = cls.set_json(val, extended)
    elif format == "dict":
        res = cls(**val)
    else:
        raise Exception("Unknown format")

    return res

def base_ser(cls, format, extended=False):
    if format == "urlencoded":
        res = cls.get_urlencoded(extended)
    elif format == "json":
        res = cls.get_json(extended)
    elif format == "dict":
        if isinstance(cls, oauth2.Base):
            res = cls.dictionary()
        elif isinstance(cls, dict):
            res = cls
        else:
            raise ValueError("%s" % type(cls))
    else:
        raise Exception("Unknown format")

    return res

def idtoken_ser(val, format="urlencoded", extended=False):
    return base_ser(val, format, extended)

def idtoken_deser(val, format="urlencoded", extended=False):
    return base_deser(IdToken, val, format, extended)

def idtokenclaim_ser(val, format="urlencoded", extended=False):
    return base_ser(val, format, extended)

def idtokenclaim_deser(val, format="urlencoded", extended=False):
    return base_deser(IDTokenClaim, val, format, extended)

def userinfo_ser(val, format="urlencoded", extended=False):
    return base_ser(val, format, extended)

def userinfo_deser(val, format="urlencoded", extended=False):
    return base_deser(UserInfoClaim, val, format, extended)

#noinspection PyUnusedLocal
def claims_ser(val, format="urlencoded", extended=False):
    # everything in c_extension
    if format == "urlencoded":
        res = [urllib.urlencode(v.c_extension) for v in val]
    elif format == "json":
        res = [json.dumps(v.c_extension) for v in val]
    elif format == "dict":
        if isinstance(val[0], oauth2.Base):
            res = [v.c_extension for v in val]
        elif isinstance(val[0], dict):
            res = val
        else:
            raise ValueError("%s" % type(val[0]))
    else:
        raise Exception("Unknown format")

    return res

def parse_qs(str):
    res = {}
    for key, vals in urlparse.parse_qs(str).items():
        val = vals[0]
        if val == "None":
            res[key] = None
        elif val[0] == "{" and val[-1] == "}":
            res[key] = eval(val)
        else:
            res[key] = val

    return res

#noinspection PyUnusedLocal
def claims_deser(val, format="urlencoded", extended=False):
    if format == "urlencoded":
        if isinstance(val, list):
            pass
        else:
            val = eval(val)

        res = [CLAIMS(**parse_qs(v)) for v in val]
    elif format == "json":
        res = [CLAIMS(**json.loads(v)) for v in val]
    elif format == "dict":
        res = [CLAIMS(**v) for v in val]
    else:
        raise Exception("Unknown format")

    return res

class AccessTokenResponse(oauth2.AccessTokenResponse):
    c_attributes = oauth2.AccessTokenResponse.c_attributes.copy()
    c_attributes["id_token"] = SINGLE_OPTIONAL_STRING
    c_attributes["domain"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 access_token=None,
                 token_type=None,
                 expires_in=None,
                 refresh_token=None,
                 scope=None,
                 id_token=None,
                 domain=None,
                 **kwargs):
        oauth2.AccessTokenResponse.__init__(self,
                                            access_token,
                                            token_type,
                                            expires_in,
                                            refresh_token,
                                            scope,
                                            **kwargs)
        self.id_token = id_token
        self.domain = domain

class AuthorizationResponse(oauth2.AuthorizationResponse, AccessTokenResponse):
    c_attributes = oauth2.AuthorizationResponse.c_attributes.copy()
    c_attributes["nonce"] = SINGLE_OPTIONAL_STRING
    # Add all the AccessTokenResponse properties
    c_attributes.update(AccessTokenResponse.c_attributes)
    # Change these two from required to optional
    c_attributes["access_token"] = SINGLE_OPTIONAL_STRING
    c_attributes["token_type"] = SINGLE_OPTIONAL_STRING
#    c_attributes["expires_in"] = SINGLE_OPTIONAL_INT
#    c_attributes["refresh_token"] = SINGLE_OPTIONAL_STRING
#    c_attributes["scope"] = OPTIONAL_LIST_OF_STRINGS
#    c_attributes["id_token"] = SINGLE_OPTIONAL_JWT

    def __init__(self,
                 code = None,
                 state=None,
                 nonce= None,
                 access_token=None,
                 token_type=None,
                 expires_in=None,
                 refresh_token=None,
                 scope=None,
                 id_token=None,
                 domain=None,
                 **kwargs):
        AccessTokenResponse.__init__(self, access_token, token_type,
                                     expires_in, refresh_token, scope,
                                     id_token, domain)
        oauth2.AuthorizationResponse.__init__(self, code, state, **kwargs)
        self.nonce = nonce
#        self.access_token = access_token
#        self.token_type = token_type
#        self.expires_in = expires_in
#        self.refresh_token = refresh_token
#        self.scope = scope or []
#        self.id_token = id_token


class AuthorizationErrorResponse(oauth2.AuthorizationErrorResponse):
    c_attributes = oauth2.AuthorizationErrorResponse.c_attributes.copy()

    #noinspection PyCallByClass
    def __init__(self,
                 error=None,
                 error_description=None,
                 error_uri=None,
                 state=None,
                 **kwargs):
        oauth2.AuthorizationErrorResponse.__init__(self, **kwargs)
        self.error = error
        self.error_description = error_description
        self.error_uri = error_uri
        self.state = state

    def verify(self):
        if self.error:
            if self.error in ["invalid_request_redirect_uri",
                                  "login_required",
                                  "session_selection_required",
                                  "approval_required",
                                  "user_mismatched"]:
                return True

        return oauth2.AuthorizationErrorResponse.verify(self)

class TokenErrorResponse(oauth2.TokenErrorResponse):
    c_attributes = oauth2.TokenErrorResponse.c_attributes.copy()

    def __init__(self,
                 error=None,
                 error_description=None,
                 error_uri=None,
                 **kwargs):
        oauth2.TokenErrorResponse.__init__(self,
                                           error,
                                           error_description,
                                           error_uri,
                                           **kwargs)

    def verify(self):
        if self.error:
            if self.error in ["invalid_authorization_code"]:
                return True

        return oauth2.TokenErrorResponse.verify(self)

class AccessTokenRequest(oauth2.AccessTokenRequest):
    c_attributes = oauth2.AccessTokenRequest.c_attributes.copy()
    c_attributes["client_id"] = SINGLE_REQUIRED_STRING
    c_attributes["secret_type"] = SINGLE_OPTIONAL_STRING
    c_attributes["client_secret"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 grant_type=None,
                 code=None,
                 redirect_uri=None,
                 client_id=None,
                 secret_type=None,
                 client_secret=None,
                 **kwargs):
        oauth2.AccessTokenRequest.__init__(self, grant_type, code,
                                           redirect_uri, **kwargs)
        self.client_id = client_id
        self.secret_type = secret_type
        self.client_secret = client_secret

class AuthorizationRequest(oauth2.AuthorizationRequest):
    c_attributes = oauth2.AuthorizationRequest.c_attributes.copy()
    c_attributes["request"] = SINGLE_OPTIONAL_JWT
    c_attributes["request_uri"] = SINGLE_OPTIONAL_STRING
    c_attributes["display"] = SINGLE_OPTIONAL_STRING
    c_attributes["prompt"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["nonce"] = SINGLE_OPTIONAL_STRING
    c_attributes["id_token_audience"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 response_type=None,
                 client_id=None,
                 redirect_uri=None,
                 scope=None,
                 state=None,
                 request=None,
                 request_uri=None,
                 display=None,
                 prompt=None,
                 nonce=None,
                 id_token_audience=None,
                 **kwargs):
        oauth2.AuthorizationRequest.__init__(self, response_type, client_id,
                                             redirect_uri, scope, state,
                                             **kwargs)
        self.request = request
        self.request_uri = request_uri
        self.display = display
        self.prompt = prompt or []
        self.nonce = nonce
        self.id_token_audience = id_token_audience

    def verify(self):
        if self.display:
            assert self.display in ["none", "popup", "mobile"]
        if self.prompt:
            for val in self.prompt:
                assert val in ["login", "consent", "select_account"]

        return oauth2.AuthorizationRequest.verify(self)

class RefreshAccessTokenRequest(oauth2.RefreshAccessTokenRequest):
    pass

class UserInfoRequest(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["access_token"] = SINGLE_OPTIONAL_STRING
    c_attributes["schema"] = SINGLE_OPTIONAL_STRING
    c_attributes["id"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 access_token=None,
                 schema=None,
                 id=None,
                 **kwargs
                 ):
        oauth2.Base.__init__(self, **kwargs)
        self.access_token=access_token
        self.schema=schema
        self.id=id

class UserInfoResponse(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["id"] = SINGLE_OPTIONAL_STRING
    c_attributes["name"] = SINGLE_OPTIONAL_STRING
    c_attributes["given_name"] = SINGLE_OPTIONAL_STRING
    c_attributes["family_name"] = SINGLE_OPTIONAL_STRING
    c_attributes["middle_name"] = SINGLE_OPTIONAL_STRING
    c_attributes["nickname"] = SINGLE_OPTIONAL_STRING
    c_attributes["profile"] = SINGLE_OPTIONAL_STRING
    c_attributes["picture"] = SINGLE_OPTIONAL_STRING
    c_attributes["website"] = SINGLE_OPTIONAL_STRING
    c_attributes["email"] = SINGLE_OPTIONAL_STRING
    c_attributes["verified"] = SINGLE_OPTIONAL_BOOLEAN
    c_attributes["gender"] = SINGLE_OPTIONAL_STRING
    c_attributes["birthday"] = SINGLE_OPTIONAL_STRING
    c_attributes["zoneinfo"] = SINGLE_OPTIONAL_STRING
    c_attributes["locale"] = SINGLE_OPTIONAL_STRING
    c_attributes["phone_number"] = SINGLE_OPTIONAL_STRING
    c_attributes["address"] = SINGLE_OPTIONAL_JSON
    c_attributes["update_time"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 id=None,
                 name=None,
                 given_name=None,
                 family_name=None,
                 middle_name=None,
                 nickname=None,
                 profile=None,
                 picture=None,
                 website=None,
                 email=None,
                 verified=False,
                 gender=None,
                 birthday=None,
                 zoneinfo=None,
                 locale=None,
                 phone_number=None,
                 address=None,
                 update_time=None,
                 **kwargs
                ):
        oauth2.Base.__init__(self, **kwargs)
        self.id = id
        self.name = name
        self.given_name = given_name
        self.family_name = family_name
        self.middle_name = middle_name
        self.nickname = nickname
        self.profile = profile
        self.picture = picture
        self.website = website
        self.email = email
        self.verified = verified
        self.gender = gender
        self.birthday = birthday
        self.zoneinfo = zoneinfo
        self.locale = locale
        self.phone_number = phone_number
        self.address = address
        self.update_time = update_time

class RegistrationRequest(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["type"] = SINGLE_REQUIRED_STRING
    c_attributes["client_id"] = SINGLE_OPTIONAL_STRING
    c_attributes["client_secret"] = SINGLE_OPTIONAL_STRING
    c_attributes["contact"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["application_type"] = SINGLE_OPTIONAL_STRING
    c_attributes["application_name"] = SINGLE_OPTIONAL_STRING
    c_attributes["logo_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["redirect_uri"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["js_origin_uri"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["jwk_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["x509_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["sector_identifier"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 type=None,
                 client_id=None,
                 client_secret=None,
                 contact=None,
                 application_type=None,
                 application_name=None,
                 logo_url=None,
                 redirect_uri=None,
                 js_origin_uri=None,
                 jwk_url=None,
                 x509_url=None,
                 sector_identifier=None,
                 **kwargs
                ):
        oauth2.Base.__init__(self, **kwargs)
        self.type = type
        self.client_id=client_id
        self.client_secret=client_secret
        self.contact=contact or []
        self.application_type=application_type
        self.application_name=application_name
        self.logo_url=logo_url
        self.redirect_uri=redirect_uri or []
        self.js_origin_uri=js_origin_uri or []
        self.jwk_url=jwk_url
        self.x509_url=x509_url
        self.sector_identifier=sector_identifier

    def verify(self):
        assert self.type in ["client_associate", "client_update"]
        assert self.application_type in ["native", "web"]

        return oauth2.Base.verify(self)

class RegistrationResponse(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["client_id"] = SINGLE_REQUIRED_STRING
    c_attributes["client_secret"] = SINGLE_REQUIRED_STRING
    c_attributes["expires_in"] = SINGLE_REQUIRED_INT

    def __init__(self,
                 client_id=None,
                 client_secret=None,
                 expires_in=0,
                 **kwargs
                ):
        oauth2.Base.__init__(self, **kwargs)
        self.client_id=client_id
        self.client_secret=client_secret
        self.expires_in=expires_in

class IdToken(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["iss"] = SINGLE_REQUIRED_STRING
    #c_attributes["client_id"] = SINGLE_REQUIRED_STRING
    c_attributes["user_id"] = SINGLE_REQUIRED_STRING
    c_attributes["aud"] = SINGLE_REQUIRED_STRING
    c_attributes["exp"] = SINGLE_REQUIRED_STRING
    c_attributes["nonce"] = SINGLE_OPTIONAL_STRING
    c_attributes["issued_to"] = SINGLE_OPTIONAL_STRING
    c_attributes["auth_time"] = SINGLE_OPTIONAL_STRING
    c_attributes["max_age"] = SINGLE_OPTIONAL_INT
    c_attributes["iso29115"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 iss=None,
                 #client_id=None,
                 user_id=None,
                 aud=None,
                 exp=None,
                 nonce=None,
                 issued_to=None,
                 auth_time=None,
                 max_age=None,
                 iso29115=None,
                 **kwargs
                ):
        oauth2.Base.__init__(self, **kwargs)
        self.iss=iss
        #self.client_id=client_id
        self.user_id=user_id
        self.aud=aud
        self.exp=exp
        self.nonce=nonce
        self.issued_to=issued_to
        self.auth_time=auth_time
        self.max_age=max_age
        self.iso29115=iso29115

class RefreshSessionRequest(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["id_token"] = SINGLE_REQUIRED_STRING
    c_attributes["redirect_url"] = SINGLE_REQUIRED_STRING
    c_attributes["state"] = SINGLE_REQUIRED_STRING

    def __init__(self,
                 id_token=None,
                 redirect_url=None,
                 state=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.id_token = id_token
        self.redirect_url = redirect_url
        self.state = state

class RefreshSessionResponse(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["id_token"] = SINGLE_REQUIRED_STRING
    c_attributes["state"] = SINGLE_REQUIRED_STRING

    def __init__(self,
                 id_token=None,
                 state=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.id_token = id_token
        self.state = state

class CheckSessionRequest(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["id_token"] = SINGLE_REQUIRED_STRING

    def __init__(self,
                 id_token=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.id_token = id_token

class CheckIDRequest(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["id_token"] = SINGLE_REQUIRED_STRING

    def __init__(self,
                 id_token=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.id_token = id_token

class EndSessionRequest(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["id_token"] = SINGLE_REQUIRED_STRING
    c_attributes["redirect_url"] = SINGLE_REQUIRED_STRING
    c_attributes["state"] = SINGLE_REQUIRED_STRING

    def __init__(self,
                 id_token=None,
                 redirect_url=None,
                 state=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.id_token = id_token
        self.redirect_url = redirect_url
        self.state = state

class EndSessionResponse(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["state"] = SINGLE_REQUIRED_STRING

    def __init__(self,
                 state=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.state = state

class CLAIMS(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()

    def __init__(self, **kwargs):
        oauth2.Base.__init__(self, **kwargs)

OPTIONAL_MULTIPLE_CLAIMS = ([CLAIMS], False, claims_ser, claims_deser)

class UserInfoClaim(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["claims"] = OPTIONAL_MULTIPLE_CLAIMS
    c_attributes["format"] = SINGLE_OPTIONAL_STRING
    c_attributes["locale"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 claims=None,
                 format=None,
                 locale=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.claims = claims or []
        self.format = format
        self.locale = locale

    def verify(self):
        if self.format:
            assert self.format in ["unsigned", "signed", "encrypted"]

        return oauth2.Base.verify(self)

class IDTokenClaim(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["claims"] = OPTIONAL_MULTIPLE_CLAIMS
    c_attributes["max_age"] = SINGLE_OPTIONAL_INT
    c_attributes["iso29115"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 claims=None,
                 max_age=None,
                 iso29115=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.claims = claims
        self.max_age = max_age
        self.iso29115 = iso29115

SINGLE_OPTIONAL_USERINFO_CLAIM = (UserInfoClaim, False, userinfo_ser,
                                  userinfo_deser)
SINGLE_OPTIONAL_ID_TOKEN_CLAIM = (IDTokenClaim, False, idtokenclaim_ser,
                                  idtokenclaim_deser)

class OpenIDRequest(AuthorizationRequest):
    c_attributes = AuthorizationRequest.c_attributes.copy()
    c_attributes["user_info"] = SINGLE_OPTIONAL_USERINFO_CLAIM
    c_attributes["id_token"] = SINGLE_OPTIONAL_ID_TOKEN_CLAIM
    c_attributes["iss"] = SINGLE_OPTIONAL_STRING
    c_attributes["aud"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 response_type=None,
                 client_id=None,
                 redirect_uri=None,
                 scope=None,
                 state=None,
                 user_info=None,
                 id_token=None,
                 iss=None,
                 aud=None,
                 **kwargs):
        AuthorizationRequest.__init__(self,
                                      response_type,
                                      client_id,
                                      redirect_uri,
                                      scope,
                                      state,
                                       **kwargs)
        self.user_info = user_info
        self.id_token = id_token
        self.iss = iss
        self.aud = aud

class ProviderConfigurationResponse(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["version"] = SINGLE_OPTIONAL_STRING
    c_attributes["issuer"] = SINGLE_OPTIONAL_STRING
    c_attributes["authorization_endpoint"] = SINGLE_OPTIONAL_STRING
    c_attributes["token_endpoint"] = SINGLE_OPTIONAL_STRING
    c_attributes["user_info_endpoint"] = SINGLE_OPTIONAL_STRING
    c_attributes["check_session_endpoint"] = SINGLE_OPTIONAL_STRING
    c_attributes["refresh_session_endpoint"] = SINGLE_OPTIONAL_STRING
    c_attributes["end_session_endpoint"] = SINGLE_OPTIONAL_STRING
    c_attributes["registration_endpoint"] = SINGLE_OPTIONAL_STRING
    c_attributes["jwk_document"] = SINGLE_OPTIONAL_STRING
    c_attributes["x509_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["scopes_supported"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["flows_supported"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["iso29115_supported"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["identifiers_supported"] = OPTIONAL_LIST_OF_STRINGS

    def __init__(self,
                 version="3.0",
                 issuer=None,
                 authorization_endpoint=None,
                 token_endpoint=None,
                 user_info_endpoint=None,
                 check_session_endpoint=None,
                 refresh_session_endpoint=None,
                 end_session_endpoint=None,
                 jwk_document=None,
                 x509_url=None,
                 registration_endpoint=None,
                 scopes_supported=None,
                 flows_supported=None,
                 iso29115_supported=None,
                 identifiers_supported=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.version = version
        self.issuer = issuer
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.user_info_endpoint = user_info_endpoint
        self.check_session_endpoint = check_session_endpoint
        self.refresh_session_endpoint = refresh_session_endpoint
        self.end_session_endpoint = end_session_endpoint
        self.jwk_document = jwk_document
        self.x509_url = x509_url
        self.registration_endpoint = registration_endpoint
        self.scopes_supported = scopes_supported
        self.flows_supported = flows_supported
        self.iso29115_supported = iso29115_supported
        self.identifiers_supported = identifiers_supported

class JWKKeyObject(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["algorithm"] = SINGLE_REQUIRED_STRING
    c_attributes["use"] = SINGLE_OPTIONAL_STRING
    c_attributes["keyid"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 algorithm=None,
                 use=None,
                 keyid=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.algorithm = algorithm
        self.use = use
        self.keyid = keyid

class JWKEllipticKeyObject(JWKKeyObject):
    c_attributes = JWKKeyObject.c_attributes.copy()
    c_attributes["curve"] = SINGLE_REQUIRED_STRING
    c_attributes["x"] = SINGLE_OPTIONAL_STRING
    c_attributes["y"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 algorithm=None,
                 use=None,
                 keyid=None,
                 curve=None,
                 x=None,
                 y=None,
                 **kwargs):
        JWKKeyObject.__init__(self, algorithm, use, keyid, **kwargs)
        self.curve = curve
        self.x = x
        self.y = y

def key_object_list_deserializer(items, format="json", extended=False):
    if format == "urlencoded":
        return [JWKKeyObject.set_urlencoded(item,
                                        extended=extended) for item in items]
    elif format == "json":
        return [JWKKeyObject.set_json(txt=item) for item in items]
    elif format=="dict":
        return [JWKKeyObject(**item) for item in items]

def key_object_list_serializer(objs, format="json", extended=False):
    if format == "json":
        return [obj.get_json(extended=extended) for obj in objs]
    elif format == "urlencoded":
        return [obj.get_urlencoded(extended=extended) for obj in objs]
    elif format == "dict":
        return [obj.dictionary(extended=extended) for obj in objs]

REQUIRED_LIST_OF_KEYOBJECTS = ([JWKKeyObject], True, key_object_list_serializer,
                                               key_object_list_deserializer)

class JWKContainerObject(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["keyvalues"] = REQUIRED_LIST_OF_KEYOBJECTS

    def __init__(self,
                 keyvalues=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.keyvalues = keyvalues

