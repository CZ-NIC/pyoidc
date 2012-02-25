#!/usr/bin/env python

from oic import oauth2
import json
import urlparse
import urllib

#from oic.utils import jwt

from oic.oauth2 import SINGLE_OPTIONAL_STRING
from oic.oauth2 import SINGLE_REQUIRED_STRING
from oic.oauth2 import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2 import SINGLE_OPTIONAL_INT
#from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS
from oic.oauth2.message import Base

#noinspection PyUnusedLocal
def json_ser(val, format=None, extended=False):
    return json.dumps(val)

#noinspection PyUnusedLocal
def json_deser(val, format, extended=None):
    return json.loads(val)

SINGLE_OPTIONAL_JWT = SINGLE_OPTIONAL_STRING
SINGLE_OPTIONAL_BOOLEAN = (bool, False, None, None)
SINGLE_OPTIONAL_JSON = (dict, False, json_ser, json_deser)
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

def base_ser(inst, format, extended=False):
    if format == "urlencoded":
        res = inst.get_urlencoded(extended)
    elif format == "json":
        res = inst.get_json(extended)
    elif format == "dict":
        if isinstance(inst, oauth2.Base):
            res = inst.dictionary()
        elif isinstance(inst, dict):
            res = inst
        else:
            raise ValueError("%s" % type(inst))
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
    if format=="dict":
        res = UserInfoClaim.from_dictionary(val, extended)
    elif format == "urlencoded":
        res = UserInfoClaim.set_urlencoded(val, extended)
    elif format == "json":
        res = UserInfoClaim.set_json(val, extended)
    else:
        raise Exception("Unknown format")

    return res

#noinspection PyUnusedLocal
def claims_ser(val, format="urlencoded", extended=False):
    # everything in c_extension
    if isinstance(val, basestring):
        item = val
    elif isinstance(val, list):
        item = val[0]
    else:
        item = val

    if format == "urlencoded":
        if isinstance(item, Base):
            res = urllib.urlencode(item.c_extension)
        else:
            res = urllib.urlencode(item)
    elif format == "json":
        if isinstance(item, Base):
            res = json.dumps(item.c_extension)
        else:
            res = json.dumps(item)
    elif format == "dict":
        if isinstance(item, oauth2.Base):
            res = item.c_extension
        elif isinstance(item, dict):
            res = item
        else:
            raise ValueError("%s" % type(item))
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
            val = val[0]

        res = Claims(**parse_qs(val))
    elif format == "json":
        res = Claims(**json.loads(val))
    elif format == "dict":
        res = Claims(**val)
    else:
        raise Exception("Unknown format")

    return res

#noinspection PyUnusedLocal
def address_deser(val, format="urlencoded", extended=False):
    if format == "urlencoded":
#        if isinstance(val, list):
#            pass
#        else:
#            val = eval(val)
#
        res = AddressClaim(**parse_qs(val))
    elif format == "json":
        res = AddressClaim(**json.loads(val))
    elif format == "dict":
        res = AddressClaim(**val)
    else:
        raise Exception("Unknown format")

    return res

class AccessTokenResponse(oauth2.AccessTokenResponse):
    c_attributes = oauth2.AccessTokenResponse.c_attributes.copy()
    c_attributes["id_token"] = SINGLE_OPTIONAL_STRING
    #c_attributes["domain"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 access_token=None,
                 token_type=None,
                 expires_in=None,
                 refresh_token=None,
                 scope=None,
                 state=None,
                 id_token=None,
    #             domain=None,
                 **kwargs):
        oauth2.AccessTokenResponse.__init__(self,
                                            access_token,
                                            token_type,
                                            expires_in,
                                            refresh_token,
                                            scope,
                                            state,
                                            **kwargs)
        self.id_token = id_token
    #    self.domain = domain

    def verify(self, **kwargs):
        if self.id_token:
            # Try to decode the JWT, checks the signature
            try:
                idt = IdToken.set_jwt(str(self.id_token), kwargs["key"])
            except Exception, _err:
                raise Exception(_err.__class__.__name__)

            if not idt.verify(**kwargs):
                return False

        return oauth2.AccessTokenResponse.verify(self, **kwargs)

class AuthorizationResponse(oauth2.AuthorizationResponse, AccessTokenResponse):
    c_attributes = oauth2.AuthorizationResponse.c_attributes.copy()
    # code is actually optional
    c_attributes["code"] = SINGLE_OPTIONAL_STRING
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
        self.access_token = access_token
        self.token_type = token_type
        self.expires_in = expires_in
        self.refresh_token = refresh_token
        self.scope = scope or []
        self.id_token = id_token

    def verify(self, **kwargs):
        if self.id_token:
            # Try to decode the JWT, checks the signature
            idt = IdToken.set_jwt(str(self.id_token), kwargs["key"])
            if not idt.verify(**kwargs):
                return False

        return oauth2.AuthorizationResponse.verify(self, **kwargs)

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

    def verify(self, **kwargs):
        if self.error:
            if self.error in ["invalid_request_redirect_uri",
                                  "interaction_required",
                                  "invalid_request_uri",
                                  "invalid_openid_request_object"]:
                return True

        return oauth2.AuthorizationErrorResponse.verify(self, **kwargs)

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

    def verify(self, **kwargs):
        if self.error:
            if self.error in ["invalid_authorization_code"]:
                return True

        return oauth2.TokenErrorResponse.verify(self, **kwargs)

class AccessTokenRequest(oauth2.AccessTokenRequest):
    c_attributes = oauth2.AccessTokenRequest.c_attributes.copy()
    c_attributes["client_id"] = SINGLE_REQUIRED_STRING
    c_attributes["client_secret"] = SINGLE_OPTIONAL_STRING
    c_attributes["client_assertion_type"] = SINGLE_OPTIONAL_STRING
    c_attributes["client_assertion"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 grant_type="authorization_code",
                 code=None,
                 redirect_uri=None,
                 client_id=None,
                 client_secret=None,
                 client_assertion_type=None,
                 client_assertion=None,
                 **kwargs):
        oauth2.AccessTokenRequest.__init__(self, grant_type, code,
                                           redirect_uri, **kwargs)
        self.client_id = client_id
        self.client_secret = client_secret
        self.client_assertion_type = client_assertion_type
        self.client_assertion = client_assertion

class AuthorizationRequest(oauth2.AuthorizationRequest):
    c_attributes = oauth2.AuthorizationRequest.c_attributes.copy()
    c_attributes["request"] = SINGLE_OPTIONAL_JWT
    c_attributes["request_uri"] = SINGLE_OPTIONAL_STRING
    c_attributes["display"] = SINGLE_OPTIONAL_STRING
    c_attributes["prompt"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["nonce"] = SINGLE_REQUIRED_STRING
    #c_attributes["id_token_audience"] = SINGLE_OPTIONAL_STRING

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
                 #id_token_audience=None,
                 **kwargs):
        oauth2.AuthorizationRequest.__init__(self, response_type, client_id,
                                             redirect_uri, scope, state,
                                             **kwargs)
        self.request = request
        self.request_uri = request_uri
        self.display = display
        self.prompt = prompt or []
        self.nonce = nonce
        #self.id_token_audience = id_token_audience

    def verify(self, **kwargs):
        if self.display:
            assert self.display in ["page", "popup", "touch", "wap",
                                    "embedded"]
        if self.prompt:
            for val in self.prompt:
                assert val in ["none", "login", "consent", "select_account"]

        return oauth2.AuthorizationRequest.verify(self, **kwargs)

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

class AddressClaim(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["formatted"] = SINGLE_OPTIONAL_STRING
    c_attributes["street_address"] = SINGLE_OPTIONAL_STRING
    c_attributes["locality"] = SINGLE_OPTIONAL_STRING
    c_attributes["region"] = SINGLE_OPTIONAL_STRING
    c_attributes["postal_code"] = SINGLE_OPTIONAL_STRING
    c_attributes["country"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 formatted=None,
                 street_address=None,
                 locality=None,
                 region=None,
                 postal_code=None,
                 country=None,
                 **kwargs
        ):
        oauth2.Base.__init__(self, **kwargs)
        self.formatted=formatted
        self.street_address=street_address
        self.locality=locality
        self.region=region
        self.postal_code=postal_code
        self.country=country

#noinspection PyUnusedLocal
def address_deser(val, format="urlencoded", extended=False):
    res = None

    if format == "urlencoded":
        res = [AddressClaim(**parse_qs(val))]
    elif format == "json":
        _val = json.loads(val)
        if isinstance(_val, list):
            res = [AddressClaim(**v) for v in _val]
        elif isinstance(_val, dict):
            res = [AddressClaim(**_val)]
    elif format == "dict":
        if isinstance(val, list):
            res = [AddressClaim(**v) for v in val]
        elif isinstance(val, dict):
            res = [AddressClaim(**val)]
        else:
            raise AttributeError("expected struct got '%s'" % type(val))
    else:
        raise Exception("unknown format")

    return res

OPTIONAL_ADDRESS = (AddressClaim, False, claims_ser, address_deser)

class OpenIDSchema(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["user_id"] = SINGLE_OPTIONAL_STRING
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
    c_attributes["address"] = OPTIONAL_ADDRESS
    c_attributes["updated_time"] = SINGLE_OPTIONAL_STRING
    c_attributes["_claim_names"] = SINGLE_OPTIONAL_JSON
    c_attributes["_claim_sources"] = SINGLE_OPTIONAL_JSON

    def __init__(self,
                 user_id=None,
                 name=None,
                 given_name=None,
                 family_name=None,
                 middle_name=None,
                 nickname=None,
                 profile=None,
                 picture=None,
                 website=None,
                 email=None,
                 verified=None,
                 gender=None,
                 birthday=None,
                 zoneinfo=None,
                 locale=None,
                 phone_number=None,
                 address=None,
                 updated_time=None,
                 _claim_names=None,
                 _claim_sources=None,
                 **kwargs
                ):
        oauth2.Base.__init__(self, **kwargs)
        self.user_id = user_id
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
        self.updated_time = updated_time
        self._claim_names = _claim_names
        self._claim_sources = _claim_sources


class RegistrationRequest(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["type"] = SINGLE_REQUIRED_STRING
    c_attributes["client_id"] = SINGLE_OPTIONAL_STRING
    c_attributes["client_secret"] = SINGLE_OPTIONAL_STRING
    c_attributes["access_token"] = SINGLE_OPTIONAL_STRING
    c_attributes["contacts"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["application_type"] = SINGLE_OPTIONAL_STRING
    c_attributes["application_name"] = SINGLE_OPTIONAL_STRING
    c_attributes["logo_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["redirect_uris"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["token_endpoint_auth_type"] = SINGLE_OPTIONAL_STRING
    c_attributes["policy_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["jwk_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["jwk_encryption_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["x509_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["x509_encryption_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["sector_identifier_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["user_id_type"] = SINGLE_OPTIONAL_STRING
    c_attributes["require_signed_request_object"] = SINGLE_OPTIONAL_STRING
    c_attributes["userinfo_signed_response_algs"] = SINGLE_OPTIONAL_STRING
    c_attributes["userinfo_encrypted_response_algs"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["id_token_signed_response_algs"] = SINGLE_OPTIONAL_STRING
    c_attributes["id_token_encrypted_response_algs"] = OPTIONAL_LIST_OF_STRINGS

    def __init__(self,
                 type=None,
                 client_id=None,
                 client_secret=None,
                 access_token=None,
                 contacts=None,
                 application_type=None,
                 application_name=None,
                 logo_url=None,
                 redirect_uris=None,
                 token_endpoint_auth_type=None,
                 policy_url=None,
                 jwk_url=None,
                 jwk_encryption_url=None,
                 x509_url=None,
                 x509_encryption_url=None,
                 sector_identifier_url=None,
                 user_id_type=None,
                 require_signed_request_object=None,
                 userinfo_signed_response_algs=None,
                 userinfo_encrypted_response_algs=None,
                 id_token_signed_response_algs=None,
                 id_token_encrypted_response_algs=None,
                 **kwargs
                ):
        oauth2.Base.__init__(self, **kwargs)
        self.type = type
        self.client_id=client_id
        self.client_secret=client_secret
        self.contacts=contacts or []
        self.application_type=application_type
        self.application_name=application_name
        self.logo_url=logo_url
        self.redirect_uris=redirect_uris or []
        self.jwk_url=jwk_url
        self.jwk_encryption_url=jwk_encryption_url
        self.x509_url=x509_url
        self.x509_encryption_url=x509_encryption_url
        self.sector_identifier_url=sector_identifier_url
        self.user_id_type=user_id_type
        self.require_signed_request_object=require_signed_request_object
        self.userinfo_signed_response_algs=userinfo_signed_response_algs
        self.userinfo_encrypted_response_algs=userinfo_encrypted_response_algs
        self.id_token_signed_response_algs=id_token_signed_response_algs
        self.id_token_encrypted_response_algs=id_token_encrypted_response_algs
        self.access_token=access_token
        self.token_endpoint_auth_type=token_endpoint_auth_type
        self.policy_url=policy_url


    def verify(self, **kwargs):
        assert self.type in ["client_associate", "client_update"]
        if self.application_type:
            assert self.application_type in ["native", "web"]

        return oauth2.Base.verify(self, **kwargs)

class RegistrationResponse(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["client_id"] = SINGLE_REQUIRED_STRING
    c_attributes["client_secret"] = SINGLE_REQUIRED_STRING
    c_attributes["expires_at"] = SINGLE_REQUIRED_INT

    def __init__(self,
                 client_id=None,
                 client_secret=None,
                 expires_at=0,
                 **kwargs
                ):
        oauth2.Base.__init__(self, **kwargs)
        self.client_id=client_id
        self.client_secret=client_secret
        self.expires_at=expires_at

class ClientRegistrationErrorResponse(oauth2.ErrorResponse):
    c_attributes = oauth2.ErrorResponse.c_attributes.copy()

    def __init__(self,
                 error=None,
                 error_description=None,
                 error_uri=None,
                 **kwargs):
        oauth2.ErrorResponse.__init__(self, error, error_description,
                                      error_uri, **kwargs)

    def verify(self, **kwargs):
        if self.error:
            assert self.error in ["invalid_type", "invalid_client_id",
                                  "invalid_client_secret",
                                  "invalid_configuration_parameter"]

        return oauth2.ErrorResponse.verify(self, **kwargs)

class IdToken(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["iss"] = SINGLE_REQUIRED_STRING
    #c_attributes["client_id"] = SINGLE_REQUIRED_STRING
    c_attributes["user_id"] = SINGLE_REQUIRED_STRING
    c_attributes["aud"] = SINGLE_REQUIRED_STRING
    c_attributes["exp"] = SINGLE_REQUIRED_INT
    c_attributes["acr"] = SINGLE_OPTIONAL_STRING
    c_attributes["nonce"] = SINGLE_OPTIONAL_STRING
    c_attributes["auth_time"] = SINGLE_OPTIONAL_STRING
    #c_attributes["max_age"] = SINGLE_OPTIONAL_INT
    #c_attributes["issued_to"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 iss=None,
                 #client_id=None,
                 user_id=None,
                 aud=None,
                 exp=None,
                 acr=None,
                 nonce=None,
                 auth_time=None,
#                 issued_to=None,
#                 max_age=None,
                 **kwargs
                ):
        oauth2.Base.__init__(self, **kwargs)
        self.iss=iss
        #self.client_id=client_id
        self.user_id=user_id
        self.aud=aud
        self.exp=exp
        self.acr=acr
        self.nonce=nonce
        self.auth_time=auth_time
        #self.issued_to=issued_to
        #self.max_age=max_age

    def verify(self, **kwargs):
        if self.aud:
            if "client_id" in kwargs:
                # check that it's for me
                if self.aud != kwargs["client_id"]:
                    return False

        return oauth2.Base.verify(self, **kwargs)

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

    def verify(self, **kwargs):
        if self.id_token:
            # Try to decode the JWT, checks the signature
            idt = IdToken.set_jwt(str(self.id_token), kwargs["key"])
            if not idt.verify(**kwargs):
                return False

        return oauth2.AuthorizationResponse.verify(self, **kwargs)

class CheckSessionRequest(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["id_token"] = SINGLE_REQUIRED_STRING

    def __init__(self,
                 id_token=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.id_token = id_token

# The same as CheckSessionRequest
class CheckIDRequest(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["access_token"] = SINGLE_REQUIRED_STRING

    def __init__(self,
                 access_token=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.access_token = access_token

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

class Claims(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()

    def __init__(self, **kwargs):
        oauth2.Base.__init__(self, **kwargs)

OPTIONAL_MULTIPLE_Claims = (Claims, False, claims_ser, claims_deser)

class UserInfoClaim(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["claims"] = OPTIONAL_MULTIPLE_Claims
    #c_attributes["format"] = SINGLE_OPTIONAL_STRING
    c_attributes["preferred_locale"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 claims=None,
                 #format=None,
                 preferred_locale=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.claims = claims
        #self.format = format
        self.preferred_locale = preferred_locale

    def verify(self, **kwargs):
        if self.format:
            assert self.format in ["unsigned", "signed", "encrypted"]

        return oauth2.Base.verify(self, **kwargs)

class IDTokenClaim(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["claims"] = OPTIONAL_MULTIPLE_Claims
    c_attributes["max_age"] = SINGLE_OPTIONAL_INT

    def __init__(self,
                 claims=None,
                 max_age=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.claims = claims
        self.max_age = max_age

SINGLE_OPTIONAL_USERINFO_CLAIM = (UserInfoClaim, False, userinfo_ser,
                                  userinfo_deser)
SINGLE_OPTIONAL_ID_TOKEN_CLAIM = (IDTokenClaim, False, idtokenclaim_ser,
                                  idtokenclaim_deser)

class OpenIDRequest(AuthorizationRequest):
    c_attributes = AuthorizationRequest.c_attributes.copy()
    c_attributes["user_info"] = SINGLE_OPTIONAL_USERINFO_CLAIM
    c_attributes["id_token"] = SINGLE_OPTIONAL_ID_TOKEN_CLAIM
    # If signed it should contain these
    c_attributes["iss"] = SINGLE_OPTIONAL_STRING
    c_attributes["aud"] = SINGLE_OPTIONAL_STRING

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
                 #id_token_audience=None,
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
                                      request,
                                      request_uri,
                                      display,
                                      prompt,
                                      nonce,
                                      #id_token_audience,
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
    c_attributes["userinfo_endpoint"] = SINGLE_OPTIONAL_STRING
    c_attributes["check_id_endpoint"] = SINGLE_OPTIONAL_STRING
    c_attributes["refresh_session_endpoint"] = SINGLE_OPTIONAL_STRING
    c_attributes["end_session_endpoint"] = SINGLE_OPTIONAL_STRING
    c_attributes["registration_endpoint"] = SINGLE_OPTIONAL_STRING
    c_attributes["jwk_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["x509_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["jwk_encryption_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["x509_encryption_url"] = SINGLE_OPTIONAL_STRING
    c_attributes["scopes_supported"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["response_types_supported"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["acrs_supported"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["user_id_types_supported"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["userinfo_algs_supported"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["id_token_algs_supported"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["request_object_algs_supported"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["token_endpoint_auth_types_supported"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["token_endpoint_auth_algs_supported"] = OPTIONAL_LIST_OF_STRINGS

    def __init__(self,
                 version="3.0",
                 issuer=None,
                 authorization_endpoint=None,
                 token_endpoint=None,
                 userinfo_endpoint=None,
                 check_id_endpoint=None,
                 refresh_session_endpoint=None,
                 end_session_endpoint=None,
                 jwk_url=None,
                 jwk_encryption_url=None,
                 x509_url=None,
                 x509_encryption_url=None,
                 registration_endpoint=None,
                 scopes_supported=None,
                 response_types_supported=None,
                 acrs_supported=None,
                 user_id_types_supported=None,
                 userinfo_algs_supported=None,
                 id_token_algs_supported=None,
                 request_object_algs_supported=None,
                 token_endpoint_auth_types_supported=None,
                 token_endpoint_auth_algs_supported=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.version = version
        self.issuer = issuer
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = userinfo_endpoint
        self.check_id_endpoint = check_id_endpoint
        self.refresh_session_endpoint = refresh_session_endpoint
        self.end_session_endpoint = end_session_endpoint
        self.jwk_url = jwk_url
        self.x509_url = x509_url
        self.jwk_encryption_url = jwk_encryption_url
        self.x509_encryption_url = x509_encryption_url
        self.registration_endpoint = registration_endpoint
        self.scopes_supported = scopes_supported
        self.response_types_supported=response_types_supported
        self.acrs_supported=acrs_supported
        self.user_id_types_supported=user_id_types_supported
        self.userinfo_algs_supported=userinfo_algs_supported
        self.id_token_algs_supported=id_token_algs_supported
        self.request_object_algs_supported=request_object_algs_supported
        self.token_endpoint_auth_types_supported=token_endpoint_auth_types_supported
        self.token_endpoint_auth_algs_supported=token_endpoint_auth_algs_supported


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
                 algorithm="EC",
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

class JWKRSAKeyObject(JWKKeyObject):
    c_attributes = JWKKeyObject.c_attributes.copy()
    c_attributes["exponent"] = SINGLE_REQUIRED_STRING
    c_attributes["modulus"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 algorithm="RSA",
                 use=None,
                 keyid=None,
                 exponent=None,
                 modulus=None,
                 **kwargs):
        JWKKeyObject.__init__(self, algorithm, use, keyid, **kwargs)
        self.exponent = exponent
        self.modulus = modulus

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

class IssuerRequest(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["service"] = SINGLE_REQUIRED_STRING
    c_attributes["principal"] = SINGLE_REQUIRED_STRING

    def __init__(self,
                 service=None,
                 principal=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.service = service
        self.principal = principal

class SWDServiceRedirect(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["location"] = SINGLE_REQUIRED_STRING
    c_attributes["expires"] = SINGLE_OPTIONAL_INT

    def __init__(self,
                 location=None,
                 expires=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.location = location
        self.expires = expires

def swd_deser(val, format="json", extended=False):
    return base_deser(SWDServiceRedirect, val, format, extended)

def swd_ser(val, format="json", extended=False):
    return base_ser(val, format, extended)

SINGLE_OPTIONAL_SERVICE_REDIRECT = (SWDServiceRedirect, False, swd_ser, swd_deser)

class IssuerResponse(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["locations"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["SWD_service_redirect"] = SINGLE_OPTIONAL_SERVICE_REDIRECT

    def __init__(self,
                 locations=None,
                 SWD_service_redirect=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.locations = locations
        self.SWD_service_redirect = SWD_service_redirect

class AuthnToken(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["iss"] = SINGLE_REQUIRED_STRING
    c_attributes["prn"] = SINGLE_REQUIRED_STRING
    c_attributes["aud"] = SINGLE_REQUIRED_STRING
    c_attributes["jti"] = SINGLE_REQUIRED_STRING
    c_attributes["exp"] = SINGLE_REQUIRED_INT
    c_attributes["iat"] = SINGLE_OPTIONAL_INT

    def __init__(self,
                 iss=None,
                 prn=None,
                 aud=None,
                 jti=None,
                 exp=None,
                 iat=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.iss = iss
        self.prn = prn
        self.aud = aud
        self.jti = jti
        self.exp = exp
        self.iat = iat

class UserInfoErrorResponse(oauth2.ErrorResponse):
    c_attributes = oauth2.ErrorResponse.c_attributes.copy()

    def __init__(self,
             error=None,
             error_description=None,
             error_uri=None,
             **kwargs):
        oauth2.ErrorResponse.__init__(self, error, error_description,
                                      error_uri, **kwargs)

    def verify(self, **kwargs):
        if self.error:
            assert self.error in ["invalid_schema", "invalid_request",
                                  "invalid_token", "insufficient_scope"]

        return oauth2.ErrorResponse.verify(self, **kwargs)

def factory(cls, **argv):
    _dict = {}
    for attr in cls.c_attributes:
        try:
            _dict[attr] = argv[attr]
        except KeyError:
            pass

    return cls(**_dict)

SCOPE2CLAIMS = {
    "openid": ["user_id"],
    "profile": ["name", "given_name", "family_name", "middle_name",
                "nickname", "profile", "picture", "website", "gender",
                "birthday", "zoneinfo", "locale", "updated_time"],
    "email": ["email", "verified"],
    "address": ["address"],
    "phone": ["phone_number"]
}