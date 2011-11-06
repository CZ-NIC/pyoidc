#!/usr/bin/env python

from oic import oauth2
import json
import jwt
import tempfile
import time
import os
import os.path
import sys
import urlparse
import urllib

from oic.oauth2 import SINGLE_OPTIONAL_STRING
from oic.oauth2 import SINGLE_REQUIRED_STRING
from oic.oauth2 import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2 import HTTP_ARGS

def to_json(dic):
    return json.dumps(dic)

def from_json(str):
    return json.loads(str)

SINGLE_OPTIONAL_JWT = SINGLE_OPTIONAL_STRING
SINGLE_OPTIONAL_BOOLEAN = (bool, False, None, None)
SINGLE_OPTIONAL_JSON = (dict, False, to_json, from_json)
SINGLE_REQUIRED_INT = (int, True, None, None)

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
#    c_attributes["access_token"] = SINGLE_REQUIRED_STRING
#    c_attributes["token_type"] = SINGLE_REQUIRED_STRING
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
            if not self.error in ["invalid_request_redirect_uri",
                                  "login_required",
                                  "session_selection_required",
                                  "approval_required",
                                  "user_mismatched"]:
                raise ValueError("'%s' not an allowed error type" % self.error)

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
            if not self.error in ["invalid_authorization_code"]:
                raise ValueError("'%s' not an allowed error type" % self.error)

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
        self.prompt = prompt
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
    c_attributes["redirect_url"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["js_origin_url"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["jwk_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["sector_identifier"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 type=None,
                 client_id=None,
                 client_secret=None,
                 contact=None,
                 application_type=None,
                 application_name=None,
                 logo_url=None,
                 redirect_url=None,
                 js_origin_url=None,
                 jwk_url=None,
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
        self.redirect_url=redirect_url or []
        self.js_origin_url=js_origin_url or []
        self.jwk_url=jwk_url
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
    c_attributes["max_age"] = SINGLE_OPTIONAL_STRING
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

#noinspection PyUnusedLocal
def claims_ser(vals, format="dict", extended=False):
    if format == "dict":
        return [val.dictionary() for val in vals]

#noinspection PyUnusedLocal
def claims_deser(vals, format="dict", extended=False):
    if format == "dict":
        return [CLAIMS(**val) for val in vals]

OPTIONAL_MULTIPLE_CLAIMS = ([CLAIMS], False, None, None)

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
        self.claims = claims
        self.format = format
        self.locale = locale

    def verify(self):
        if self.format:
            assert self.format in ["unsigned", "signed", "encrypted"]
            
        return oauth2.Base.verify(self)

class IDTokenClaim(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["claims"] = OPTIONAL_MULTIPLE_CLAIMS
    c_attributes["max_age"] = SINGLE_OPTIONAL_STRING
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

SINGLE_OPTIONAL_USERINFO_CLAIM = (UserInfoClaim, False, None, None)
SINGLE_OPTIONAL_ID_TOKEN_CLAIM = (IDTokenClaim, False, None, None)

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

#version	string	Version of the provider response. "3.0" is the default.
#issuer	string	The https: URL with no path component the OP asserts as it's issuer identifyer
#authorization_endpoint	string	URL of the OP's Authentication and Authorization Endpoint [OpenID.Messages]
#token_endpoint	string	URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Messages]
#user_info_endpoint	string	URL of the OP's UserInfo Endpoint [OpenID.Messages]
#check_session_endpoint	string	URL of the OP's Check Session Endpoint [OpenID.Session]
#refresh_session_endpoint	string	URL of the OP's Refresh Session Endpoint [OpenID.Session]
#end_session_endpoint	string	URL of the OP's End Session Endpoint [OpenID.Session]
#jwk_document	string	URL of the OP's JSON Web Key [JWK] document
#certs_url	string	URL of the OP's X.509 certificates in PEM format.
#registration_endpoint	string	URL of the OP's Dynamic Client Registration Endpoint [OpenID.Registration]
#scopes_supported	array	A JSON array containing a list of the OAuth 2.0 [OAuth2.0] scopes that this server supports. The server MUST support the openid scope.
#flows_supported	array	A JSON array containing a list of the OAuth 2.0 flows that this server supports. The server MUST support the code flow.
#iso29115_supported	array	A JSON array containing a list of the ISO 29115 assurance contexts that this server supports.
#identifiers_supported	array	A JSON array containing a list of the user identifier types that this server supports

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
    c_attributes["jwk_document"] = SINGLE_OPTIONAL_STRING
    c_attributes["certs_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["registration_endpoint"] = SINGLE_OPTIONAL_STRING
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
                 certs_url=None,
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
        self.certs_url = certs_url
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
                        extended=extended).dictionary() for item in items]
    elif format == "json" or format=="dict":
        return items

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

# =============================================================================

class Client(oauth2.Client):
    def __init__(self, client_id=None, cache=None, timeout=None,
                 proxy_info=None, follow_redirects=True,
                 disable_ssl_certificate_validation=False):
        oauth2.Client.__init__(self, client_id, cache, timeout, proxy_info,
                       follow_redirects, disable_ssl_certificate_validation)

        self.file_store = "./file/"
        self.file_uri = "http://localhost/"
        # OpenID connect specific endpoints
        self.userinfo_endpoint = None
        self.check_session = None
        self.refresh_session=None
        self.end_session=None

    def set_from_authorization_response(self, aresp):
        self.authorization_response = aresp
        self.grant_expiration_time = time.time()+self.expire_in
        self.authorization_code = aresp.code
        for prop in AuthorizationResponse.c_attributes.keys():
            setattr(self, prop, getattr(aresp, prop))

    def parse_authorization_response(self, rcls=AuthorizationResponse,
                                     url="", query=""):
        aresp = oauth2.Client.parse_authorization_response(self, rcls, url,
                                                           query)

        self.set_from_authorization_response(aresp)
        return aresp

    def parse_access_token_response(self, cls=AccessTokenResponse, info="",
                                    format="json", extended=False):
        """
        if format is urlencoded then the id_token is in the fragment
        This is a quirkiness specific to OpenID Connect.

        :param cls: The AccessTokenResponse class to use
        :param info: The information returned
        :param format: the format of the returned info
        :param extended: Whether parameter extensions should be allowed
        :return: A instance of the 'cls' class.
            Will raise an exception on any error.
        """
        instance = oauth2.Client.parse_access_token_response(self, cls, info,
                                                            format, extended)
        if format == "urlencoded" and '?' in info:
            #fragment is the 6th part
            instance.id_token = urllib.unquote_plus(urlparse.urlparse(info)[6])

        return instance

    #noinspection PyMethodOverriding
    def do_authorization_request(self, cls=AuthorizationRequest,
                                 method="GET", oic_method="query_parameter",
                                 **kwargs):
        """
        Send an AuthorizationRequest

        :param cls: The AuthorizationRequest class to use
        :param method: The HTTP method to use (GET or POST)
        :param oic_method: The OIC method that should be used
        :return: The HTTP response
        """

        uri = self._endpoint("authorization_endpoint", **kwargs)

        if oic_method == "query_parameter":
            ar = self.get_authorization_request(cls, **kwargs)
        elif oic_method == "request_parameter":
            ar = self.get_authorization_request_with_request(cls, **kwargs)
        elif oic_method == "request_file":
            ar, request = self.get_authorization_request_on_side(cls,
                                                                  **kwargs)
            # create temporary file that is publicly accessible
            (fd, path) = tempfile.mkstemp(dir=self.file_store, text=True)
            fh = os.fdopen(fd, "w")
            fh.write(request)
            fh.close()
            # Path as seen from the outside
            ar.request_uri = self.file_uri + os.path.split(path)[1]
        else:
            raise Exception("Unknown OIC authorization method: %s" % oic_method)

        path = uri + '?' + ar.get_urlencoded()

        print >> sys.stderr, path
        
        h_args = dict([(k, v) for k,v in kwargs.items() if k in HTTP_ARGS])

        return self.http.request(path, method, **h_args)

    def do_access_token_request(self, reqcls=AccessTokenRequest,
                                respcls=AccessTokenResponse,
                                method="POST", **kwargs):
        return oauth2.Client.do_access_token_request(self, reqcls, respcls,
                                                     method, **kwargs)

    def do_access_token_refresh(self, reqcls=RefreshAccessTokenRequest,
                                respcls=AccessTokenResponse,
                                method="POST", **kwargs):
        return oauth2.Client.do_access_token_refresh(self, reqcls, respcls,
                                                     method, **kwargs)

    def get_open_id_request(self, cls=AuthorizationRequest, claims=None,
                            uinfo_format="", locale="",
                            id_token_restriction=None,
                            **kwargs):

        claims = CLAIMS(**claims)
        user_info = UserInfoClaim(claims, format=uinfo_format, locale=locale)
        id_token = IDTokenClaim(**id_token_restriction)

        ar = self.get_authorization_request(cls, **kwargs)

        return OpenIDRequest(ar.response_type, ar.client_id, ar.redirect_uri,
                             ar.scope, ar.state, user_info, id_token)


    def do_user_info_request(self, method="GET", **kwargs):
        uir = UserInfoRequest()
        if self.access_token_is_valid():
            uir.access_token = self.access_token.access_token
        else:
            # raise oauth2.OldAccessToken
            try:
                self.do_access_token_refresh()
            except Exception:
                raise
            
        uri = self._endpoint("userinfo_endpoint", **kwargs)

        if method == "GET":
            path = uri + '?' + uir.get_urlencoded()
            body=None
        elif method == "POST":
            path = uri
            body = uir.get_urlencoded()
        else:
            raise Exception("Unsupported HTTP method: '%s'" % method)

        print >> sys.stderr, path

        h_args = dict([(k, v) for k,v in kwargs.items() if k in HTTP_ARGS])
        if body:
            h_args["body"] = body

        try:
            response, content = self.http.request(path, method, **h_args)
        except oauth2.MissingRequiredAttribute:
            raise

        if response.status == 200:
            assert "application/json" in response["content-type"]
        elif response.status == 500:
            raise Exception("ERROR: Something went wrong: %s" % content)
        else:
            raise Exception("ERROR: Something went wrong [%s]" % response.status)

        return UserInfoResponse.set_json(txt=content, extended=True)


class Server(oauth2.Server):
    def __init__(self, jwt_keys=None):
        oauth2.Server.__init__(self)

        self.jwt_keys = jwt_keys or {}

    def _parse_urlencoded(self, url=None, query=None):
        if url:
            parts = urlparse.urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        return urlparse.parse_qs(query)

    def parse_authorization_request(self, rcls=AuthorizationRequest,
                                    url=None, query=None, extended=False):
        return oauth2.Server.parse_authorization_request(self, rcls, url,
                                                         query, extended)

    def parse_token_request(self, rcls=AccessTokenRequest, body=None):
        return oauth2.Server.parse_token_request(self, rcls, body)

    def parse_refresh_token_request(self, rcls=RefreshAccessTokenRequest,
                                    body=None):
        return oauth2.Server.parse_refresh_token_request(self, rcls, body)

    def parse_check_session_request(self, url=None, query=None):
        param = self._parse_urlencoded(url, query)
        assert "id_token" in param # ignore the rest
        # have to start decoding the jwt in order to find out which
        # key to verify the JWT signature with
        info = json.loads(jwt.decode(param["id_token"][0], verify=False))

        print info
        # in there there should be information about the client_id
        # Use that to find the key and do the signature verify

        return IdToken.set_jwt(param["id_token"][0],
                               key=self.jwt_keys[info["iss"]])


    def parse_open_id_request(self, data, format="json", extended=False):
        if format == "json":
            oidr = OpenIDRequest.set_json(data, extended)
        elif format == "urlencoded":
            if '?' in data:
                parts = urlparse.urlparse(data)
                scheme, netloc, path, params, query, fragment = parts[:6]
            else:
                query = data
            oidr = OpenIDRequest.set_urlencoded(query, extended)
        else:
            raise Exception("Unknown package format: '%s'" %  format)

        assert oidr.verify()
        return oidr

    def parse_user_info_request(self, url=None, query=None, extended=False):
        if url:
            parts = urlparse.urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        return UserInfoRequest.set_urlencoded(query, extended)

    def parse_refresh_session_request(self, url=None, query=None,
                                      extended=False):
        if url:
            parts = urlparse.urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        return RefreshSessionRequest.set_urlencoded(query, extended)
