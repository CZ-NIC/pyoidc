import os
from oic.utils.keystore import get_signing_key
from oic.jwt.jws import alg2keytype

__author__ = 'rohe0002'

import urlparse
import json
import logging

from oic.oauth2.message import ErrorResponse

from oic.oic.message import IdToken
from oic.oic.message import AuthorizationResponse
from oic.oic.message import AccessTokenResponse
from oic.oic.message import Claims
from oic.oic.message import UserInfoClaim
from oic.oic.message import IDTokenClaim
from oic.oic.message import AccessTokenRequest
from oic.oic.message import RefreshAccessTokenRequest
from oic.oic.message import UserInfoRequest
from oic.oic.message import AuthorizationRequest
from oic.oic.message import OpenIDRequest
from oic.oic.message import RegistrationRequest
from oic.oic.message import RefreshSessionRequest
from oic.oic.message import RegistrationResponseCU
from oic.oic.message import RegistrationResponseCARS
from oic.oic.message import CheckSessionRequest
from oic.oic.message import CheckIDRequest
from oic.oic.message import EndSessionRequest
from oic.oic.message import OpenIDSchema
from oic.oic.message import ProviderConfigurationResponse
from oic.oic.message import IssuerRequest
from oic.oic.message import AuthnToken
from oic.oic.message import TokenErrorResponse
from oic.oic.message import ClientRegistrationErrorResponse
from oic.oic.message import UserInfoErrorResponse
from oic.oic.message import AuthorizationErrorResponse

from oic import oauth2

from oic.oauth2 import AUTHN_METHOD as OAUTH2_AUTHN_METHOD
from oic.oauth2 import HTTP_ARGS
from oic.oauth2 import rndstr
from oic.oauth2.consumer import ConfigurationError

#from oic.oic.message import *

from oic.oic.exception import AccessDenied

from oic import jwt
from oic.jwt import jws
from oic.utils import time_util
#from oic.utils import jwt

#from oic.utils.time_util import time_sans_frac
from oic.utils.time_util import utc_now
from oic.utils.time_util import epoch_in_a_while

logger = logging.getLogger(__name__)

ENDPOINTS = ["authorization_endpoint", "token_endpoint",
             "userinfo_endpoint", "refresh_session_endpoint",
             "check_session_endpoint", "end_session_endpoint",
             "registration_endpoint", "check_id_endpoint"]

RESPONSE2ERROR = {
    "AuthorizationResponse": [AuthorizationErrorResponse,
                              TokenErrorResponse],
    "AccessTokenResponse": [TokenErrorResponse],
    "IdToken": [ErrorResponse],
    "RegistrationResponse": [ClientRegistrationErrorResponse],
    "OpenIDSchema": [UserInfoErrorResponse]
}

REQUEST2ENDPOINT = {
    "AuthorizationRequest": "authorization_endpoint",
    "OpenIDRequest": "authorization_endpoint",
    "AccessTokenRequest": "token_endpoint",
    "RefreshAccessTokenRequest": "token_endpoint",
    "UserInfoRequest": "userinfo_endpoint",
    "CheckSessionRequest": "check_session_endpoint",
    "CheckIDRequest": "check_id_endpoint",
    "EndSessionRequest": "end_session_endpoint",
    "RefreshSessionRequest": "refresh_session_endpoint",
    "RegistrationRequest": "registration_endpoint",
    # ---
    "ResourceRequest": "resource_endpoint"
}

# -----------------------------------------------------------------------------
MAX_AUTHENTICATION_AGE = 86400
JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
OIDCONF_PATTERN = "%s/.well-known/openid-configuration"

AUTHN_METHOD = OAUTH2_AUTHN_METHOD.copy()
OIC_DEF_SIGN_ALG = "RS256"

def assertion_jwt(cli, keys, audience, algorithm=OIC_DEF_SIGN_ALG):
    at = AuthnToken(iss = cli.client_id, prn = cli.client_id,
                    aud = audience, jti = rndstr(8),
                    exp = int(epoch_in_a_while(minutes=10)), iat = utc_now())
    return at.to_jwt(key=keys, algorithm=algorithm)

#noinspection PyUnusedLocal
def client_secret_jwt(cli, cis, request_args=None, http_args=None, **kwargs):

    # signing key is the client secret
    signing_key = cli.keystore.get_sign_key()

    # audience is the OP endpoint
    audience = cli._endpoint(REQUEST2ENDPOINT[cis.type()])

    try:
        algorithm = kwargs["algorithm"]
    except KeyError:
        algorithm = cli.behaviour["require_signed_request_object"]

    cis["client_assertion"] = assertion_jwt(cli, signing_key, audience,
                                            algorithm)
    cis["client_assertion_type"] = JWT_BEARER

    try:
        del cis["client_secret"]
    except KeyError:
        pass

    return {}

#noinspection PyUnusedLocal
def private_key_jwt(cli, cis, request_args=None, http_args=None, **kwargs):

    # signing key is the clients rsa key for instance
    signing_key = cli.keystore.get_sign_key()

    # audience is the OP endpoint
    audience = cli._endpoint(REQUEST2ENDPOINT[cis.type()])
    try:
        algorithm = kwargs["algorithm"]
    except KeyError:
        algorithm = OIC_DEF_SIGN_ALG

    cis["client_assertion"] = assertion_jwt(cli, signing_key, audience,
                                            algorithm)
    cis["client_assertion_type"] = JWT_BEARER

    try:
        del cis["client_secret"]
    except KeyError:
        pass

    return {}

AUTHN_METHOD.update({"client_secret_jwt": client_secret_jwt,
                     "private_key_jwt": private_key_jwt})

# -----------------------------------------------------------------------------
ACR_LISTS = [
    ["0", "1", "2", "3", "4"],
]

def verify_acr_level(req, level):
    if req is None:
        return level
    elif "values" in req:
        for _r in req["values"]:
            for alist in ACR_LISTS:
                try:
                    if alist.index(_r) <= alist.index(level):
                        return level
                except ValueError:
                    pass
    else: #Required or Optional
        return level

    raise AccessDenied

def deser_id_token(inst, str=""):
    if not str:
        return None

    jws.verify(str, keystore = inst.keystore)
    jso = json.loads(jwt.unpack(str)[1])

    return IdToken().from_dict(jso)

# -----------------------------------------------------------------------------
def make_openid_request(arq, keys=None, userinfo_claims=None,
                        idtoken_claims=None, algorithm=None,
                        **kwargs):
    """
    Construct the specification of what I want returned.
    The request will be signed

    :param arq: The Authorization request
    :param keys: Keys to use for signing/encrypting
    :param userinfo_claims: UserInfo claims
    :param idtoken_claims: IdToken claims
    :param algorithm: Which signing/encrypting algorithm to use
    :return: JWT encoded OpenID request
    """

    oir_args = {}

    if userinfo_claims is not None:
        # UserInfoClaims
        claim = Claims(**userinfo_claims["claims"])

        uic_args = {}
        for prop, val in userinfo_claims.items():
            if prop == "claims":
                continue
            if prop in UserInfoClaim.c_param.keys():
                uic_args[prop] = val

        uic = UserInfoClaim(claims=claim, **uic_args)
    else:
        uic = None

    if uic:
        oir_args["userinfo"] = uic

    if idtoken_claims is not None:
        #IdTokenClaims
        try:
            _max_age = idtoken_claims["max_age"]
        except KeyError:
            _max_age=MAX_AUTHENTICATION_AGE

        id_token = IDTokenClaim(max_age=_max_age)
        if "claims" in idtoken_claims:
            idtclaims = Claims(**idtoken_claims["claims"])
            id_token["claims"] = idtclaims
    else: # uic must be != None
        id_token = IDTokenClaim(max_age=MAX_AUTHENTICATION_AGE)

    if id_token:
        oir_args["id_token"] = id_token

    for prop in OpenIDRequest.c_param.keys():
        try:
            oir_args[prop] = arq[prop]
        except KeyError:
            pass

    for attr in ["scope", "response_type"]:
        if attr in oir_args:
            oir_args[attr] = " ".join(oir_args[attr])

    oir = OpenIDRequest(**oir_args)

    return oir.to_jwt(key=keys, algorithm=algorithm)

class Token(oauth2.Token):
    pass

class Grant(oauth2.Grant):
    _authz_resp = AuthorizationResponse
    _acc_resp = AccessTokenResponse
    _token_class = Token

    def add_token(self, resp):
        tok = self._token_class(resp)
        if tok.access_token:
            self.tokens.append(tok)
        else:
            _tmp = getattr(tok, "id_token", None)
            if _tmp:
                self.tokens.append(tok)

PREFERENCE2PROVIDER = {
    "token_endpoint_auth_type": "token_endpoint_auth_types_supported",
    "require_signed_request_object": "request_object_algs_supported",
    "userinfo_signed_response_alg": "userinfo_algs_supported",
    "userinfo_encrypted_response_alg": "userinfo_algs_supported",
    "id_token_signed_response_alg": "id_token_algs_supported",
    "id_token_encrypted_response_alg": "id_token_algs_supported",
    "default_acr": "acrs_supported",
    "user_id_type": "user_id_types_supported",
    "token_endpoint_auth_alg": "token_endpoint_auth_algs_supported",
}

PROVIDER_DEFAULT = {
    "token_endpoint_auth_type": "client_secret_basic",
    "id_token_signed_response_alg": "RS256",
}

#noinspection PyMethodOverriding
class Client(oauth2.Client):
    _endpoints = ENDPOINTS

    def __init__(self, client_id=None, ca_certs=None, grant_expire_in=600,
                 jwt_keys=None, client_timeout=0, client_prefs=None):

        oauth2.Client.__init__(self, client_id, ca_certs, grant_expire_in,
                               client_timeout=client_timeout,
                               jwt_keys=jwt_keys)

        self.file_store = "./file/"
        self.file_uri = "http://localhost/"

        # OpenID connect specific endpoints
        for endpoint in ENDPOINTS:
            setattr(self, endpoint, "")

        self.id_token=None
        self.log = None

        self.request2endpoint = REQUEST2ENDPOINT
        self.response2error = RESPONSE2ERROR
        self.grant_class = Grant
        self.token_class = Token
        self.authn_method = AUTHN_METHOD
        self.provider_info = {}
        self.client_prefs = client_prefs or {}
        self.behaviour = {"require_signed_request_object": OIC_DEF_SIGN_ALG}

    def _get_id_token(self, **kwargs):
        try:
            return kwargs["id_token"]
        except KeyError:
            grant = self.get_grant(**kwargs)

        if grant:
            try:
                _scope = kwargs["scope"]
            except KeyError:
                _scope = None

            for token in grant.tokens:
                if token.scope and _scope:
                    flag = True
                    for item in _scope:
                        try:
                            assert item in token.scope
                        except AssertionError:
                            flag = False
                            break
                    if not flag:
                        break
                if token.id_token:
                    return token.id_token

        return None

    #noinspection PyUnusedLocal
    def construct_AuthorizationRequest(self, request=AuthorizationRequest,
                                       request_args=None, extra_args=None,
                                       **kwargs):

        if request_args is not None:
            if "nonce" not in request_args:
                request_args["nonce"] = rndstr(12)
        else:
            request_args = {"nonce": rndstr(12)}

        return oauth2.Client.construct_AuthorizationRequest(self, request,
                                                            request_args,
                                                            extra_args,
                                                            **kwargs)

    def construct_OpenIDRequest(self, request=OpenIDRequest,
                                request_args=None, extra_args=None, **kwargs):

        if request_args is not None:
            for arg in ["idtoken_claims", "userinfo_claims"]:
                if arg in request_args:
                    kwargs[arg] = request_args[arg]
                    del request_args[arg]
            if "nonce" not in request_args:
                _rt = request_args["response_type"]
                if "token" in _rt or "id_token" in _rt:
                    request_args["nonce"] = rndstr(12)
        elif "response_type" in kwargs:
            if "token" in kwargs["response_type"]:
                request_args = {"nonce": rndstr(12)}
        else: # Never wrong to specify a nonce
            request_args = {"nonce": rndstr(12)}

        if "idtoken_claims" in kwargs or "userinfo_claims" in kwargs:
            request_param = "request"
            if "request_method" in kwargs:
                if kwargs["request_method"] == "file":
                    request_param = "request_uri"
                    del kwargs["request_method"]
        else:
            request_param = None

        areq = oauth2.Client.construct_AuthorizationRequest(self, request,
                                                            request_args,
                                                            extra_args,
                                                            **kwargs)

        if request_param:
            alg = self.behaviour["require_signed_request_object"]
            if "algorithm" not in kwargs:
                kwargs["algorithm"] = alg

            if "keys" not in kwargs and alg:
                atype = alg2keytype(alg)
                kwargs["keys"] = get_signing_key(self.keystore, atype, "")

            _req = make_openid_request(areq, **kwargs)

            if request_param == "request":
                areq["request"] = _req
            else:
                _filedir = kwargs["local_dir"]
                _webpath = kwargs["base_path"]
                _name = rndstr(10)
                filename = os.path.join(_filedir, _name)
                while os.path.exists(filename):
                    _name = rndstr(10)
                    filename = os.path.join(_filedir, _name)
                fid = open(filename, mode="w")
                fid.write(_req)
                fid.close()
                _webname = "%s%s" % (_webpath,_name)
                areq["request_uri"] = _webname

        return areq

    #noinspection PyUnusedLocal
    def construct_AccessTokenRequest(self, request=AccessTokenRequest,
                                     request_args=None, extra_args=None,
                                     **kwargs):

        return oauth2.Client.construct_AccessTokenRequest(self, request,
                                                          request_args,
                                                          extra_args, **kwargs)

    def construct_RefreshAccessTokenRequest(self,
                                            request=RefreshAccessTokenRequest,
                                            request_args=None, extra_args=None,
                                            **kwargs):

        return oauth2.Client.construct_RefreshAccessTokenRequest(self, request,
                                                                 request_args,
                                                                 extra_args,
                                                                 **kwargs)

    def construct_UserInfoRequest(self, request=UserInfoRequest,
                                  request_args=None, extra_args=None,
                                  **kwargs):

        if request_args is None:
            request_args = {}

        if "access_token" in request_args:
            pass
        else:
            if "scope" not in kwargs:
                kwargs["scope"] = "openid"
            token = self.get_token(**kwargs)
            if token is None:
                raise Exception("No valid token available")

            request_args["access_token"] = token.access_token

        return self.construct_request(request, request_args, extra_args)

    #noinspection PyUnusedLocal
    def construct_RegistrationRequest(self, request=RegistrationRequest,
                                      request_args=None, extra_args=None,
                                      **kwargs):

        return self.construct_request(request, request_args, extra_args)

    #noinspection PyUnusedLocal
    def construct_RefreshSessionRequest(self,
                                        request=RefreshSessionRequest,
                                        request_args=None, extra_args=None,
                                        **kwargs):

        return self.construct_request(request, request_args, extra_args)

    def _id_token_based(self, request, request_args=None, extra_args=None,
                        **kwargs):

        if request_args is None:
            request_args = {}

        try:
            _prop = kwargs["prop"]
        except KeyError:
            _prop = "id_token"

        if _prop in request_args:
            pass
        else:
            id_token = self._get_id_token(**kwargs)
            if id_token is None:
                raise Exception("No valid id token available")

            request_args[_prop] = id_token

        return self.construct_request(request, request_args, extra_args)

    def construct_CheckSessionRequest(self, request=CheckSessionRequest,
                                      request_args=None, extra_args=None,
                                      **kwargs):

        return self._id_token_based(request, request_args, extra_args, **kwargs)

    def construct_CheckIDRequest(self, request=CheckIDRequest,
                                 request_args=None,
                                 extra_args=None, **kwargs):

        # access_token is where the id_token will be placed
        return self._id_token_based(request, request_args, extra_args,
                                    prop="access_token", **kwargs)

    def construct_EndSessionRequest(self, request=EndSessionRequest,
                                    request_args=None, extra_args=None,
                                    **kwargs):

        if request_args is None:
            request_args = {}

        if "state" in kwargs:
            request_args["state"] = kwargs["state"]
        elif "state" in request_args:
            kwargs["state"] = request_args["state"]

        #        if "redirect_url" not in request_args:
        #            request_args["redirect_url"] = self.redirect_url

        return self._id_token_based(request, request_args, extra_args, 
                                    **kwargs)

    # ------------------------------------------------------------------------

    def authorization_request_info(self, request_args=None, extra_args=None,
                                   **kwargs):
        return self.request_info(AuthorizationRequest, "GET",
                                 request_args, extra_args, **kwargs)

    # ------------------------------------------------------------------------

    def do_authorization_request(self, request=AuthorizationRequest,
                                 state="", body_type="", method="GET",
                                 request_args=None, extra_args=None,
                                 http_args=None,
                                 resp_request=AuthorizationResponse):

        return oauth2.Client.do_authorization_request(self, request, state,
                                                      body_type, method,
                                                      request_args,
                                                      extra_args, http_args,
                                                      resp_request)


    def do_access_token_request(self, request=AccessTokenRequest,
                                scope="", state="", body_type="json",
                                method="POST", request_args=None,
                                extra_args=None, http_args=None,
                                resp_request=AccessTokenResponse,
                                authn_method="", **kwargs):

        return oauth2.Client.do_access_token_request(self, request, scope, state,
                                                     body_type, method,
                                                     request_args, extra_args,
                                                     http_args, resp_request,
                                                     authn_method, **kwargs)

    def do_access_token_refresh(self, request=RefreshAccessTokenRequest,
                                state="", body_type="json", method="POST",
                                request_args=None, extra_args=None,
                                http_args=None,
                                resp_request=AccessTokenResponse,
                                **kwargs):

        return oauth2.Client.do_access_token_refresh(self, request, state,
                                                     body_type, method,
                                                     request_args,
                                                     extra_args, http_args,
                                                     resp_request, **kwargs)

    def do_registration_request(self, request=RegistrationRequest,
                                scope="", state="", body_type="json",
                                method="POST", request_args=None,
                                extra_args=None, http_args=None,
                                resp_request=None):

        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        if resp_request is None:
            if request_args["type"] == "client_associate" or \
               request_args["type"] == "rotate_secret":
                resp_request = RegistrationResponseCARS
            else:
                resp_request = RegistrationResponseCU

        response = self.request_and_return(url, resp_request, method, body,
                                           body_type, state=state,
                                           http_args=http_args)

        #        if isinstance(response, Message):
        #            if "token_endpoint_auth_type" not in response:
        #                response["token_endpoint_auth_type"] = "client_secret_basic"

        return response

    def do_check_session_request(self, request=CheckSessionRequest,
                                 scope="",
                                 state="", body_type="json", method="GET",
                                 request_args=None, extra_args=None,
                                 http_args=None,
                                 resp_request=IdToken):

        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_request, method, body,
                                       body_type, state=state,
                                       http_args=http_args)

    def do_check_id_request(self, request=CheckIDRequest, scope="",
                            state="", body_type="json", method="GET",
                            request_args=None, extra_args=None,
                            http_args=None,
                            resp_request=IdToken):

        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_request, method, body,
                                       body_type, state=state,
                                       http_args=http_args)

    def do_end_session_request(self, request=EndSessionRequest, scope="",
                               state="", body_type="", method="GET",
                               request_args=None, extra_args=None,
                               http_args=None, resp_request=None):

        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_request, method, body,
                                       body_type, state=state,
                                       http_args=http_args)

    def user_info_request(self, method="GET", state="", scope="", **kwargs):
        uir = UserInfoRequest()
        if "token" in kwargs:
            if kwargs["token"]:
                uir["access_token"] = kwargs["token"]
                token = Token()
                token.type = "Bearer"
                token.access_token = kwargs["token"]
                kwargs["behavior"] = "use_authorization_header"
            else:
                # What to do ? Need a callback
                token = None
        else:
            token = self.grant[state].get_token(scope)

            if token.is_valid():
                uir["access_token"] = token.access_token
            else:
                # raise oauth2.OldAccessToken
                if self.log:
                    self.log.info("do access token refresh")
                try:
                    self.do_access_token_refresh(token=token)
                    token = self.grant[state].get_token(scope)
                    uir["access_token"] = token.access_token
                except Exception:
                    raise

        try:
            uir["schema"] = kwargs["schema"]
        except KeyError:
            pass

        uri = self._endpoint("userinfo_endpoint", **kwargs)
        # If access token is a bearer token it might be sent in the
        # authorization header
        # 3-ways of sending the access_token:
        # - POST with token in authorization header
        # - POST with token in message body
        # - GET with token in authorization header
        if "behavior" in kwargs:
            _behav = kwargs["behavior"]
            # use_authorization_header, token_in_message_body
            if "use_authorization_header" in _behav and token.type == "Bearer":
                if "headers" in kwargs:
                    kwargs["headers"].append(("Authorization", token.access_token))
                else:
                    kwargs["headers"] = [("Authorization", token.access_token)]
            if not "token_in_message_body" in _behav:
                # remove the token from the request
                uir["access_token"] = None

        path, body, kwargs = self.get_or_post(uri, method, uir, **kwargs)

        h_args = dict([(k, v) for k,v in kwargs.items() if k in HTTP_ARGS])

        return path, body, method, h_args

    def do_user_info_request(self, method="POST", state="", scope="openid",
                             request="openid", **kwargs):

        kwargs["request"] = request
        path, body, method, h_args = self.user_info_request(method, state,
                                                            scope, **kwargs)

        try:
            resp = self.http_request(path, method, data=body, **h_args)
        except oauth2.MissingRequiredAttribute:
            raise

        if resp.status_code == 200:
            try:
                assert "application/json" in resp.headers["content-type"]
                format = "json"
            except AssertionError:
                assert "application/jwt" in resp.headers["content-type"]
                format = "jwt"
        elif resp.status_code == 500:
            raise Exception("ERROR: Something went wrong: %s" % resp.text)
        else:
            raise Exception("ERROR: Something went wrong [%s]" % resp.status_code)

        if format == "json":
            return OpenIDSchema().from_json(txt=resp.text)
        else:
            algo = self.client_prefs["userinfo_signed_response_alg"]
            # Keys of the OP ?
            keys = get_signing_key(self.keystore, alg2keytype(algo))
            return OpenIDSchema().from_jwt(resp.text, keys)

    def get_userinfo_claims(self, access_token, endpoint, method="POST",
                            schema_class=OpenIDSchema, **kwargs):

        uir = UserInfoRequest(access_token=access_token)
        try:
            uir["schema"] = kwargs["schema"]
        except KeyError:
            pass


        h_args = dict([(k, v) for k,v in kwargs.items() if k in HTTP_ARGS])

        if "authn_method" in kwargs:
            http_args = self.init_authentication_method(**kwargs)
        else:
            # If nothing defined this is the default
            http_args = self.init_authentication_method(uir, "bearer_header",
                                                        **kwargs)

        h_args.update(http_args)
        path, body, kwargs = self.get_or_post(endpoint, method, uir, **kwargs)

        try:
            resp = self.http_request(path, method, data=body, **h_args)
        except oauth2.MissingRequiredAttribute:
            raise

        if resp.status_code == 200:
            assert "application/json" in resp.headers["content-type"]
        elif resp.status_code == 500:
            raise Exception("ERROR: Something went wrong: %s" % resp.text)
        else:
            raise Exception("ERROR: Something went wrong [%s]" % resp.status_code)

        return schema_class().from_json(txt=resp.text)

    def provider_config(self, issuer, keys=True, endpoints=True):
        if issuer.endswith("/"):
            _issuer = issuer[:-1]
        else:
            _issuer = issuer

        url = OIDCONF_PATTERN % _issuer

        pcr = None
        r = self.http_request(url)
        if r.status_code == 200:
            pcr = ProviderConfigurationResponse().from_json(r.text)
        elif r.status_code == 302:
            while r.status_code == 302:
                r = self.http_request(r.headers["location"])
                if r.status_code == 200:
                    pcr = ProviderConfigurationResponse().from_json(r.text)
                    break

        if pcr is None:
            raise Exception("Trying '%s', status %s" % (url, r.status_code))

        if "issuer" in pcr:
            if pcr["issuer"].endswith("/"):
                _pcr_issuer = pcr["issuer"][:-1]
            else:
                _pcr_issuer = pcr["issuer"]

            try:
                assert _issuer == _pcr_issuer
            except AssertionError:
                raise Exception("provider info issuer mismatch '%s' != '%s'" % (
                    _issuer, _pcr_issuer))

            self.provider_info[_pcr_issuer] = pcr

        if endpoints:
            for key, val in pcr.items():
                if key.endswith("_endpoint"):
                    setattr(self, key, val)

        if keys:
            self.keystore.load_keys(pcr, _issuer)

        return pcr

    def unpack_aggregated_claims(self, userinfo):
        if userinfo._claim_sources:
            for csrc, spec in userinfo._claim_sources.items():
                if "JWT" in spec:
                    if not csrc in self.keystore:
                        self.provider_config(csrc, endpoints=False)

                    keycol = self.keystore.pairkeys(csrc)["ver"]
                    info = json.loads(jws.verify(str(spec["JWT"]), keycol))
                    attr = [n for n, s in userinfo._claim_names.items() if s ==
                                                                           csrc]
                    assert attr == info.keys()

                    for key, vals in info.items():
                        userinfo[key] = vals

        return userinfo

    def fetch_distributed_claims(self, userinfo, callback=None):
        for csrc, spec in userinfo._claim_sources.items():
            if "endpoint" in spec:
                #pcr = self.provider_config(csrc, keys=False, endpoints=False)

                if "access_token" in spec:
                    _uinfo = self.do_user_info_request(
                        token=spec["access_token"],
                        userinfo_endpoint=spec["endpoint"])
                else:
                    _uinfo = self.do_user_info_request(token=callback(csrc),
                                                       userinfo_endpoint=spec["endpoint"])

                attr = [n for n, s in userinfo._claim_names.items() if s ==
                                                                       csrc]
                assert attr == _uinfo.keys()

                for key, vals in _uinfo.items():
                    userinfo[key] = vals

        return userinfo

    def verify_alg_support(self, alg, usage, other):
        """
        Verifies that the algorithm to be used are supported by the other side.

        :param alg: The algorithm specification
        :param usage: In which context the 'alg' will be used.
            The following values are supported:
            - userinfo
            - id_token
            - request_object
            - token_endpoint_auth
        :param other: The identifier for the other side
        :return: True or False
        """

        try:
            _pcr = self.provider_info[other]
            supported = _pcr["%s_algs_supported" % usage]
        except KeyError:
            try:
                supported = getattr(self, "%s_algs_supported" % usage)
            except AttributeError:
                supported = None

        if supported is None:
            return True
        else:
            if alg in supported:
                return True
            else:
                return False

    def match_preferences(self, pcr=None, issuer=None):
        """
        Match the clients preferences against what the provider can do.

        :param pcr: Provider configuration response if available
        :param issuer: The issuer identifier
        """
        if not pcr:
            pcr = self.provider_info[issuer]

        for _pref, _prov in PREFERENCE2PROVIDER.items():
            try:
                vals = self.client_prefs[_pref]
            except KeyError:
                continue

            try:
                _pvals = pcr[_prov]
            except KeyError:
                try:
                    self.behaviour[_pref] = PROVIDER_DEFAULT[_pref]
                except KeyError:
                    #self.behaviour[_pref]= vals[0]
                    self.behaviour[_pref] = None
                continue

            for val in vals:
                if val in _pvals:
                    self.behaviour[_pref]= val
                    break

            if _pref not in self.behaviour:
                raise ConfigurationError("OP couldn't match preferences")

        for key, val in self.client_prefs.items():
            if key not in PREFERENCE2PROVIDER:
                self.behaviour[key] = val

#noinspection PyMethodOverriding
class Server(oauth2.Server):
    def __init__(self, jwt_keys=None, ca_certs=None):
        oauth2.Server.__init__(self, jwt_keys, ca_certs)

    def _parse_urlencoded(self, url=None, query=None):
        if url:
            parts = urlparse.urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        return urlparse.parse_qs(query)

    def parse_token_request(self, request=AccessTokenRequest,
                            body=None):
        return oauth2.Server.parse_token_request(self, request, body)

    def parse_authorization_request(self, request=AuthorizationRequest,
                                    url=None, query=None, keys=None):
        if url:
            parts = urlparse.urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        return self._parse_request(request, query, "urlencoded", keys)

    def parse_jwt_request(self, request=AuthorizationRequest, txt="",
                          keys=None, verify=True):

        return oauth2.Server.parse_jwt_request(self, request, txt, keys, verify)

    def parse_refresh_token_request(self,
                                    request=RefreshAccessTokenRequest,
                                    body=None):
        return oauth2.Server.parse_refresh_token_request(self, request, body)

    def parse_check_session_request(self, url=None, query=None):
        """

        """
        param = self._parse_urlencoded(url, query)
        assert "id_token" in param # ignore the rest
        return deser_id_token(self, param["id_token"][0])

    def parse_check_id_request(self, url=None, query=None):
        """

        """
        param = self._parse_urlencoded(url, query)
        assert "access_token" in param # ignore the rest
        return deser_id_token(self, param["access_token"][0])

    def _parse_request(self, request, data, format, client_id=None):
        if format == "json":
            request = request().from_json(data)
        elif format == "jwt":
            request = request().from_jwt(data, keystore=self.keystore)
        elif format == "urlencoded":
            if '?' in data:
                parts = urlparse.urlparse(data)
                scheme, netloc, path, params, query, fragment = parts[:6]
            else:
                query = data
            request = request().from_urlencoded(query)
        else:
            raise Exception("Unknown package format: '%s'" %  format)

        # get the verification keys
        if client_id:
            keys = self.keystore.get_verify_key(owner=client_id)
            for typ, val in self.keystore.get_verify_key(owner=".").items():
                try:
                    keys[typ].extend(val)
                except KeyError:
                    keys[typ] = val
        else:
            keys = None

        request.verify(key=keys, keystore=self.keystore)
        return request

    def parse_open_id_request(self, data, format="urlencoded", client_id=None):
        return self._parse_request(OpenIDRequest, data, format, client_id)

    def parse_user_info_request(self, data, format="urlencoded"):
        return self._parse_request(UserInfoRequest, data, format)

    def parse_refresh_session_request(self, url=None, query=None):
        if url:
            parts = urlparse.urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        return RefreshSessionRequest().from_urlencoded(query)

    def parse_registration_request(self, data, format="urlencoded"):
        return self._parse_request(RegistrationRequest, data, format)

    def parse_end_session_request(self, query, format="urlencoded"):
        esr = self._parse_request(EndSessionRequest, query,
                                  format)
        # if there is a id_token in there it is as a string
        esr["id_token"] = deser_id_token(self, esr["id_token"])
        return esr

    def parse_issuer_request(self, info, format="urlencoded"):
        return self._parse_request(IssuerRequest, info, format)

    def id_token_claims(self, session):
        """
        Pick the IdToken claims from the request

        :param session: Session information
        :return: The IdToken claims
        """
        try:
            oidreq = OpenIDRequest().deserialize(session["oidreq"], "json")
            itc = oidreq["id_token"]
            logger.debug("ID Token claims: %s" % itc)
            return itc
        except KeyError:
            return None

    def make_id_token(self, session, loa="2", issuer="",
                      alg="RS256", code=None, access_token=None,
                      user_info=None):
        """

        :param session: Session information
        :param loa: Level of Assurance/Authentication context
        :param issuer: My identifier
        :param alg: Which signing algorithm to use for the IdToken
        :param code: Access grant
        :param access_token: Access Token
        :param user_info: If user info are to be part of the IdToken
        :return: IDToken instance
        """
        #defaults
        inawhile = {"days": 1}
        # Handle the idtoken_claims
        extra = {}
        itc = self.id_token_claims(session)
        if itc:
            try:
                inawhile = {"seconds": itc["max_age"]}
            except KeyError:
                inawhile = {}
            if "claims" in itc:
                for key, val in itc["claims"].items():
                    if key == "auth_time":
                        extra["auth_time"] = time_util.utc_time_sans_frac()
                    elif key == "acr":
                        #["2","http://id.incommon.org/assurance/bronze"]
                        extra["acr"] = verify_acr_level(val, loa)

        if user_info is None:
            _args = {}
        else:
            _args = user_info.to_dict()

        # Make sure that there are no name clashes
        for key in ["iss", "user_id", "aud", "exp", "acr", "nonce",
                    "auth_time"]:
            try:
                del _args[key]
            except KeyError:
                pass

        halg = "HS%s" % alg[-3:]

        if code:
            _args["c_hash"] = jws.left_hash(code, halg)
        if access_token:
            _args["at_hash"] = jws.left_hash(access_token, halg)

        idt = IdToken(iss=issuer, user_id=session["user_id"],
                      aud = session["client_id"],
                      exp = time_util.epoch_in_a_while(**inawhile), acr=loa,
                      **_args)

        for key, val in extra.items():
            idt[key] = val

        if "nonce" in session:
            idt.nonce = session["nonce"]

        return idt
