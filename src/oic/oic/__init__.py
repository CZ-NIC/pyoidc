import logging
import os

from jwkest.jwe import JWE

from jwkest import jws

from jwkest import jwe

from six.moves.urllib.parse import urlparse, parse_qs
from oic.oauth2.exception import AuthnToOld
from oic.oauth2.message import ErrorResponse, Message
from oic.oauth2.util import get_or_post
from oic.oic.message import IdToken, ClaimsRequest
from oic.oic.message import RegistrationResponse
from oic.oic.message import AuthorizationResponse
from oic.oic.message import AccessTokenResponse
from oic.oic.message import Claims
from oic.oic.message import AccessTokenRequest
from oic.oic.message import RefreshAccessTokenRequest
from oic.oic.message import UserInfoRequest
from oic.oic.message import AuthorizationRequest
from oic.oic.message import OpenIDRequest
from oic.oic.message import RegistrationRequest
from oic.oic.message import RefreshSessionRequest
from oic.oic.message import CheckSessionRequest
from oic.oic.message import CheckIDRequest
from oic.oic.message import EndSessionRequest
from oic.oic.message import OpenIDSchema
from oic.oic.message import ProviderConfigurationResponse
from oic.oic.message import AuthnToken
from oic.oic.message import TokenErrorResponse
from oic.oic.message import ClientRegistrationErrorResponse
from oic.oic.message import UserInfoErrorResponse
from oic.oic.message import AuthorizationErrorResponse
from oic import oauth2
from oic.oauth2 import MissingRequiredAttribute
from oic.oauth2 import OtherError
from oic.oauth2 import HTTP_ARGS
from oic.oauth2 import rndstr
from oic.oauth2.consumer import ConfigurationError
from oic.exception import AccessDenied
from oic.exception import IssuerMismatch
from oic.exception import PyoidcError
from oic.exception import MissingParameter
from oic.utils import time_util
from oic.utils.keyio import KeyJar
from oic.utils.webfinger import OIC_ISSUER
from oic.utils.webfinger import WebFinger

__author__ = 'rohe0002'

logger = logging.getLogger(__name__)

ENDPOINTS = ["authorization_endpoint", "token_endpoint",
             "userinfo_endpoint", "refresh_session_endpoint",
             "end_session_endpoint", "registration_endpoint",
             "check_id_endpoint"]

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
    "RotateSecret": "registration_endpoint",
    # ---
    "ResourceRequest": "resource_endpoint"
}

# -----------------------------------------------------------------------------

JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
SAML2_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:saml2-bearer"

OIDCONF_PATTERN = "%s/.well-known/openid-configuration"

# This should probably be part of the configuration
MAX_AUTHENTICATION_AGE = 86400
DEF_SIGN_ALG = {"id_token": "RS256",
                "openid_request_object": "RS256",
                "client_secret_jwt": "HS256",
                "private_key_jwt": "RS256"}


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
    else:  # Required or Optional
        return level

    raise AccessDenied("", req)


def deser_id_token(inst, txt=""):
    if not txt:
        return None
    else:
        return IdToken().from_jwt(txt, keyjar=inst.keyjar)


# -----------------------------------------------------------------------------
def make_openid_request(arq, keys=None, userinfo_claims=None,
                        idtoken_claims=None, request_object_signing_alg=None,
                        **kwargs):
    """
    Construct the specification of what I want returned.
    The request will be signed

    :param arq: The Authorization request
    :param keys: Keys to use for signing/encrypting
    :param userinfo_claims: UserInfo claims
    :param idtoken_claims: IdToken claims
    :param request_object_signing_alg: Which signing algorithm to use
    :return: JWT encoded OpenID request
    """

    oir_args = {}
    for prop in OpenIDRequest.c_param.keys():
        try:
            oir_args[prop] = arq[prop]
        except KeyError:
            pass

    for attr in ["scope", "response_type"]:
        if attr in oir_args:
            oir_args[attr] = " ".join(oir_args[attr])

    c_args = {}
    if userinfo_claims is not None:
        # UserInfoClaims
        c_args["userinfo"] = Claims(**userinfo_claims)

    if idtoken_claims is not None:
        # IdTokenClaims
        c_args["id_token"] = Claims(**idtoken_claims)

    if c_args:
        oir_args["claims"] = ClaimsRequest(**c_args)

    oir = OpenIDRequest(**oir_args)

    return oir.to_jwt(key=keys, algorithm=request_object_signing_alg)


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
    # "require_signed_request_object": "request_object_algs_supported",
    "request_object_signing_alg": "request_object_signing_alg_values_supported",
    "request_object_encryption_alg":
        "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc":
        "request_object_encryption_enc_values_supported",
    "userinfo_signed_response_alg": "userinfo_signing_alg_values_supported",
    "userinfo_encrypted_response_alg":
        "userinfo_encryption_alg_values_supported",
    "userinfo_encrypted_response_enc":
        "userinfo_encryption_enc_values_supported",
    "id_token_signed_response_alg": "id_token_signing_alg_values_supported",
    "id_token_encrypted_response_alg":
        "id_token_encryption_alg_values_supported",
    "id_token_encrypted_response_enc":
        "id_token_encryption_enc_values_supported",
    "default_acr_values": "acr_values_supported",
    # "require_auth_time":"",
    "subject_type": "subject_types_supported",
    "token_endpoint_auth_method": "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg":
        "token_endpoint_auth_signing_alg_values_supported",
    "response_types": "response_types_supported"
    # "request_object_signing_alg": "request_object_signing_alg_values_supported
}

PROVIDER2PREFERENCE = dict([(v, k) for k, v in PREFERENCE2PROVIDER.items()])

PROVIDER_DEFAULT = {
    "token_endpoint_auth_method": "client_secret_basic",
    "id_token_signed_response_alg": "RS256",
}

PARAMMAP = {
    "sign": "%s_signed_response_alg",
    "alg": "%s_encrypted_response_alg",
    "enc": "%s_encrypted_response_enc",
}


def claims_match(value, claimspec):
    if claimspec is None:
        return True

    for key, val in claimspec.items():
        if key == "value":
            if value != val:
                return False
        elif key == "values":
            if value not in val:
                return False
                # Whether it's essential or not doesn't change anything here
    return True


# noinspection PyMethodOverriding
class Client(oauth2.Client):
    _endpoints = ENDPOINTS

    def __init__(self, client_id=None, ca_certs=None,
                 client_prefs=None, client_authn_method=None, keyjar=None,
                 verify_ssl=True):

        oauth2.Client.__init__(self, client_id, ca_certs,
                               client_authn_method=client_authn_method,
                               keyjar=keyjar, verify_ssl=verify_ssl)

        self.file_store = "./file/"
        self.file_uri = "http://localhost/"

        # OpenID connect specific endpoints
        for endpoint in ENDPOINTS:
            setattr(self, endpoint, "")

        self.id_token = None
        self.log = None

        self.request2endpoint = REQUEST2ENDPOINT
        self.response2error = RESPONSE2ERROR

        self.grant_class = Grant
        self.token_class = Token
        self.provider_info = None
        self.registration_response = None
        self.client_prefs = client_prefs or {}

        self.behaviour = {}

        self.wf = WebFinger(OIC_ISSUER)
        self.wf.httpd = self
        self.allow = {}
        self.post_logout_redirect_uris = []
        self.registration_expires = 0
        self.registration_access_token = None
        self.id_token_max_age = 0

        # Default key by kid for different key types
        # For instance {"RSA":"abc"}
        self.kid = {"sig": {}, "enc": {}}

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

    def request_object_encryption(self, msg, **kwargs):
        try:
            encalg = kwargs["request_object_encryption_alg"]
        except KeyError:
            try:
                encalg = self.behaviour["request_object_encryption_alg"]
            except KeyError:
                return msg

        try:
            encenc = kwargs["request_object_encryption_enc"]
        except KeyError:
            try:
                encenc = self.behaviour["request_object_encryption_enc"]
            except KeyError:
                raise MissingRequiredAttribute(
                    "No request_object_encryption_enc specified")

        _jwe = JWE(msg, alg=encalg, enc=encenc)
        _kty = jwe.alg2keytype(encalg)

        try:
            _kid = kwargs["enc_kid"]
        except KeyError:
            _kid = ""

        if "target" not in kwargs:
            raise MissingRequiredAttribute("No target specified")

        if _kid:
            _keys = self.keyjar.get_encrypt_key(_kty, owner=kwargs["target"],
                                                kid=_kid)
            _jwe["kid"] = _kid
        else:
            _keys = self.keyjar.get_encrypt_key(_kty, owner=kwargs["target"])

        return _jwe.encrypt(_keys)

    def construct_AuthorizationRequest(self, request=AuthorizationRequest,
                                       request_args=None, extra_args=None,
                                       request_param=None, **kwargs):

        if request_args is not None:
            # if "claims" in request_args:
            # kwargs["claims"] = request_args["claims"]
            #     del request_args["claims"]
            if "nonce" not in request_args:
                _rt = request_args["response_type"]
                if "token" in _rt or "id_token" in _rt:
                    request_args["nonce"] = rndstr(12)
        elif "response_type" in kwargs:
            if "token" in kwargs["response_type"]:
                request_args = {"nonce": rndstr(12)}
        else:  # Never wrong to specify a nonce
            request_args = {"nonce": rndstr(12)}

        if "request_method" in kwargs:
            if kwargs["request_method"] == "file":
                request_param = "request_uri"
            else:
                request_param = "request"
            del kwargs["request_method"]

        areq = oauth2.Client.construct_AuthorizationRequest(self, request,
                                                            request_args,
                                                            extra_args,
                                                            **kwargs)

        if request_param:
            alg = None
            for arg in ["request_object_signing_alg", "algorithm"]:
                try:  # Trumps everything
                    alg = kwargs[arg]
                except KeyError:
                    pass
                else:
                    break

            if not alg:
                try:
                    alg = self.behaviour["request_object_signing_alg"]
                except KeyError:
                    alg = "none"

            kwargs["request_object_signing_alg"] = alg

            if "keys" not in kwargs and alg and alg != "none":
                _kty = jws.alg2keytype(alg)
                try:
                    _kid = kwargs["sig_kid"]
                except KeyError:
                    _kid = self.kid["sig"].get(_kty, None)

                kwargs["keys"] = self.keyjar.get_signing_key(_kty, kid=_kid)

            _req = make_openid_request(areq, **kwargs)

            # Should the request be encrypted
            _req = self.request_object_encryption(_req, **kwargs)

            if request_param == "request":
                areq["request"] = _req
            else:
                _filedir = kwargs["local_dir"]
                if not os.path.isdir(_filedir):
                    os.makedirs(_filedir)
                _webpath = kwargs["base_path"]
                _name = rndstr(10) + ".jwt"
                filename = os.path.join(_filedir, _name)
                while os.path.exists(filename):
                    _name = rndstr(10)
                    filename = os.path.join(_filedir, _name)
                fid = open(filename, mode="w")
                fid.write(_req)
                fid.close()
                _webname = "%s%s" % (_webpath, _name)
                areq["request_uri"] = _webname

        return areq

    # noinspection PyUnusedLocal
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
                raise PyoidcError("No valid token available")

            request_args["access_token"] = token.access_token

        return self.construct_request(request, request_args, extra_args)

    # noinspection PyUnusedLocal
    def construct_RegistrationRequest(self, request=RegistrationRequest,
                                      request_args=None, extra_args=None,
                                      **kwargs):

        return self.construct_request(request, request_args, extra_args)

    # noinspection PyUnusedLocal
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
                raise PyoidcError("No valid id token available")

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

        # if "redirect_url" not in request_args:
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
                                 response_cls=AuthorizationResponse):

        algs = self.sign_enc_algs("id_token")

        return oauth2.Client.do_authorization_request(self, request, state,
                                                      body_type, method,
                                                      request_args,
                                                      extra_args, http_args,
                                                      response_cls,
                                                      algs=algs)

    def do_access_token_request(self, request=AccessTokenRequest,
                                scope="", state="", body_type="json",
                                method="POST", request_args=None,
                                extra_args=None, http_args=None,
                                response_cls=AccessTokenResponse,
                                authn_method="client_secret_basic", **kwargs):

        return oauth2.Client.do_access_token_request(self, request, scope,
                                                     state, body_type, method,
                                                     request_args, extra_args,
                                                     http_args, response_cls,
                                                     authn_method, **kwargs)

    def do_access_token_refresh(self, request=RefreshAccessTokenRequest,
                                state="", body_type="json", method="POST",
                                request_args=None, extra_args=None,
                                http_args=None,
                                response_cls=AccessTokenResponse,
                                **kwargs):

        return oauth2.Client.do_access_token_refresh(self, request, state,
                                                     body_type, method,
                                                     request_args,
                                                     extra_args, http_args,
                                                     response_cls, **kwargs)

    def do_registration_request(self, request=RegistrationRequest,
                                scope="", state="", body_type="json",
                                method="POST", request_args=None,
                                extra_args=None, http_args=None,
                                response_cls=None):

        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        if response_cls is None:
            response_cls = RegistrationResponse

        response = self.request_and_return(url, response_cls, method, body,
                                           body_type, state=state,
                                           http_args=http_args)

        return response

    def do_check_session_request(self, request=CheckSessionRequest,
                                 scope="",
                                 state="", body_type="json", method="GET",
                                 request_args=None, extra_args=None,
                                 http_args=None,
                                 response_cls=IdToken):

        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, response_cls, method, body,
                                       body_type, state=state,
                                       http_args=http_args)

    def do_check_id_request(self, request=CheckIDRequest, scope="",
                            state="", body_type="json", method="GET",
                            request_args=None, extra_args=None,
                            http_args=None,
                            response_cls=IdToken):

        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, response_cls, method, body,
                                       body_type, state=state,
                                       http_args=http_args)

    def do_end_session_request(self, request=EndSessionRequest, scope="",
                               state="", body_type="", method="GET",
                               request_args=None, extra_args=None,
                               http_args=None, response_cls=None):

        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, response_cls, method, body,
                                       body_type, state=state,
                                       http_args=http_args)

    def user_info_request(self, method="GET", state="", scope="", **kwargs):
        uir = UserInfoRequest()
        logger.debug("[user_info_request]: kwargs:%s" % (kwargs,))
        if "token" in kwargs:
            if kwargs["token"]:
                uir["access_token"] = kwargs["token"]
                token = Token()
                token.token_type = "Bearer"
                token.access_token = kwargs["token"]
                kwargs["behavior"] = "use_authorization_header"
            else:
                # What to do ? Need a callback
                token = None
        elif "access_token" in kwargs and kwargs["access_token"]:
            uir["access_token"] = kwargs["access_token"]
            del kwargs["access_token"]
            token = None
        else:
            token = self.grant[state].get_token(scope)

            if token.is_valid():
                uir["access_token"] = token.access_token
                if token.token_type == "Bearer" and method == "GET":
                    kwargs["behavior"] = "use_authorization_header"
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

        uri = self._endpoint("userinfo_endpoint", **kwargs)
        # If access token is a bearer token it might be sent in the
        # authorization header
        # 3-ways of sending the access_token:
        # - POST with token in authorization header
        # - POST with token in message body
        # - GET with token in authorization header
        if "behavior" in kwargs:
            _behav = kwargs["behavior"]
            _token = uir["access_token"]
            try:
                _ttype = kwargs["token_type"]
            except KeyError:
                try:
                    _ttype = token.token_type
                except AttributeError:
                    raise MissingParameter("Unspecified token type")

            # use_authorization_header, token_in_message_body
            if "use_authorization_header" in _behav and _ttype == "Bearer":
                bh = "Bearer %s" % _token
                if "headers" in kwargs:
                    kwargs["headers"].update({"Authorization": bh})
                else:
                    kwargs["headers"] = {"Authorization": bh}

            if "token_in_message_body" not in _behav:
                # remove the token from the request
                del uir["access_token"]

        path, body, kwargs = get_or_post(uri, method, uir, **kwargs)

        h_args = dict([(k, v) for k, v in kwargs.items() if k in HTTP_ARGS])

        return path, body, method, h_args

    def do_user_info_request(self, method="POST", state="", scope="openid",
                             request="openid", **kwargs):

        kwargs["request"] = request
        path, body, method, h_args = self.user_info_request(method, state,
                                                            scope, **kwargs)

        logger.debug("[do_user_info_request] PATH:%s BODY:%s H_ARGS: %s" % (
            path, body, h_args))

        try:
            resp = self.http_request(path, method, data=body, **h_args)
        except oauth2.MissingRequiredAttribute:
            raise

        if resp.status_code == 200:
            try:
                assert "application/json" in resp.headers["content-type"]
                sformat = "json"
            except AssertionError:
                assert "application/jwt" in resp.headers["content-type"]
                sformat = "jwt"
        elif resp.status_code == 500:
            raise PyoidcError("ERROR: Something went wrong: %s" % resp.text)
        else:
            raise PyoidcError("ERROR: Something went wrong [%s]: %s" % (
                resp.status_code, resp.text))

        try:
            _schema = kwargs["user_info_schema"]
        except KeyError:
            _schema = OpenIDSchema

        logger.debug("Reponse text: '%s'" % resp.text)

        _txt = resp.text
        if sformat == "json":
            res = _schema().from_json(txt=_txt)
        else:
            res = _schema().from_jwt(_txt, keyjar=self.keyjar,
                                     sender=self.provider_info["issuer"])

        self.store_response(res, _txt)

        return res

    def get_userinfo_claims(self, access_token, endpoint, method="POST",
                            schema_class=OpenIDSchema, **kwargs):

        uir = UserInfoRequest(access_token=access_token)

        h_args = dict([(k, v) for k, v in kwargs.items() if k in HTTP_ARGS])

        if "authn_method" in kwargs:
            http_args = self.init_authentication_method(**kwargs)
        else:
            # If nothing defined this is the default
            http_args = self.init_authentication_method(uir, "bearer_header",
                                                        **kwargs)

        h_args.update(http_args)
        path, body, kwargs = get_or_post(endpoint, method, uir, **kwargs)

        try:
            resp = self.http_request(path, method, data=body, **h_args)
        except oauth2.MissingRequiredAttribute:
            raise

        if resp.status_code == 200:
            assert "application/json" in resp.headers["content-type"]
        elif resp.status_code == 500:
            raise PyoidcError("ERROR: Something went wrong: %s" % resp.text)
        else:
            raise PyoidcError(
                "ERROR: Something went wrong [%s]: %s" % (resp.status_code,
                                                          resp.text))

        res = schema_class().from_json(txt=resp.text)
        self.store_response(res, resp.txt)
        return res

    def handle_provider_config(self, pcr, issuer, keys=True, endpoints=True):
        """
        Deal with Provider Config Response
        :param pcr: The ProviderConfigResponse instance
        :param issuer: The one I thought should be the issuer of the config
        :param keys: Should I deal with keys
        :param endpoints: Should I deal with endpoints, that is store them
        as attributes in self.
        """

        if "issuer" in pcr:
            _pcr_issuer = pcr["issuer"]
            if pcr["issuer"].endswith("/"):
                if issuer.endswith("/"):
                    _issuer = issuer
                else:
                    _issuer = issuer + "/"
            else:
                if issuer.endswith("/"):
                    _issuer = issuer[:-1]
                else:
                    _issuer = issuer

            try:
                _ = self.allow["issuer_mismatch"]
            except KeyError:
                try:
                    assert _issuer == _pcr_issuer
                except AssertionError:
                    raise IssuerMismatch("'%s' != '%s'" % (_issuer,
                                                           _pcr_issuer),
                                         pcr)

            self.provider_info = pcr
        else:
            _pcr_issuer = issuer

        if endpoints:
            for key, val in pcr.items():
                if key.endswith("_endpoint"):
                    setattr(self, key, val)

        if keys:
            if self.keyjar is None:
                self.keyjar = KeyJar(verify_ssl=self.verify_ssl)

            self.keyjar.load_keys(pcr, _pcr_issuer)

    def provider_config(self, issuer, keys=True, endpoints=True,
                        response_cls=ProviderConfigurationResponse,
                        serv_pattern=OIDCONF_PATTERN):
        if issuer.endswith("/"):
            _issuer = issuer[:-1]
        else:
            _issuer = issuer

        url = serv_pattern % _issuer

        pcr = None
        r = self.http_request(url)
        if r.status_code == 200:
            try:
                pcr = response_cls().from_json(r.text)
            except:
                logger.error("Faulty provider config response: {}".format(r.text))
        elif r.status_code == 302 or r.status_code == 301:
            while r.status_code == 302 or r.status_code == 301:
                r = self.http_request(r.headers["location"])
                if r.status_code == 200:
                    pcr = response_cls().from_json(r.text)
                    break

        # logger.debug("Provider info: %s" % pcr)
        if pcr is None:
            raise PyoidcError("Trying '%s', status %s" % (url, r.status_code))

        self.store_response(pcr, r.text)

        self.handle_provider_config(pcr, issuer, keys, endpoints)

        return pcr

    def unpack_aggregated_claims(self, userinfo):
        if userinfo["_claim_sources"]:
            for csrc, spec in userinfo["_claim_sources"].items():
                if "JWT" in spec:
                    aggregated_claims = Message().from_jwt(
                        spec["JWT"].encode("utf-8"),
                        keyjar=self.keyjar, sender=csrc)
                    claims = [value for value, src in
                              userinfo["_claim_names"].items() if src == csrc]
                    assert claims == aggregated_claims.keys()

                    for key, vals in aggregated_claims.items():
                        userinfo[key] = vals

        return userinfo

    def fetch_distributed_claims(self, userinfo, callback=None):
        for csrc, spec in userinfo["_claim_sources"].items():
            if "endpoint" in spec:
                if "access_token" in spec:
                    _uinfo = self.do_user_info_request(
                        token=spec["access_token"],
                        userinfo_endpoint=spec["endpoint"])
                else:
                    _uinfo = self.do_user_info_request(
                        token=callback(csrc),
                        userinfo_endpoint=spec["endpoint"])

                claims = [value for value, src in
                          userinfo["_claim_names"].items() if src == csrc]
                assert claims == _uinfo.keys()

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
            _pcr = self.provider_info
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
            pcr = self.provider_info

        regreq = RegistrationRequest

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
                    # self.behaviour[_pref]= vals[0]
                    if isinstance(pcr.c_param[_prov][0], list):
                        self.behaviour[_pref] = []
                    else:
                        self.behaviour[_pref] = None
                continue

            if isinstance(vals, basestring):
                if vals in _pvals:
                    self.behaviour[_pref] = vals
            else:
                vtyp = regreq.c_param[_pref]

                if isinstance(vtyp[0], list):
                    self.behaviour[_pref] = []
                    for val in vals:
                        if val in _pvals:
                            self.behaviour[_pref].append(val)
                else:
                    for val in vals:
                        if val in _pvals:
                            self.behaviour[_pref] = val
                            break

            if _pref not in self.behaviour:
                raise ConfigurationError(
                    "OP couldn't match preference:%s" % _pref, pcr)

        for key, val in self.client_prefs.items():
            if key in self.behaviour:
                continue

            try:
                vtyp = regreq.c_param[key]
                if isinstance(vtyp[0], list):
                    pass
                elif isinstance(val, list) and not isinstance(val, basestring):
                    val = val[0]
            except KeyError:
                pass
            if key not in PREFERENCE2PROVIDER:
                self.behaviour[key] = val

    def store_registration_info(self, reginfo):
        self.registration_response = reginfo
        if "token_endpoint_auth_method" not in self.registration_response:
            self.registration_response[
                "token_endpoint_auth_method"] = "client_secret_post"
        self.client_id = reginfo["client_id"]
        try:
            self.client_secret = reginfo["client_secret"]
        except KeyError:  # Not required
            pass
        else:
            try:
                self.registration_expires = reginfo["client_secret_expires_at"]
            except KeyError:
                pass
        try:
            self.registration_access_token = reginfo[
                "registration_access_token"]
        except KeyError:
            pass

    def handle_registration_info(self, response):
        if response.status_code == 200:
            resp = RegistrationResponse().deserialize(response.text, "json")
            self.store_response(resp, response.text)
            self.store_registration_info(resp)
        else:
            err = ErrorResponse().deserialize(response.text, "json")
            raise PyoidcError("Registration failed: %s" % err.to_json())

        return resp

    def registration_read(self, url="", registration_access_token=None):
        if not url:
            url = self.registration_response["registration_client_uri"]

        if not registration_access_token:
            registration_access_token = self.registration_access_token

        headers = [("Authorization", "Bearer %s" % registration_access_token)]
        rsp = self.http_request(url, "GET", headers=headers)

        return self.handle_registration_info(rsp)

    def create_registration_request(self, **kwargs):
        """
        Create a registration request

        :param kwargs: parameters to the registration request
        :return:
        """
        req = RegistrationRequest()

        for prop in req.parameters():
            try:
                req[prop] = kwargs[prop]
            except KeyError:
                try:
                    req[prop] = self.behaviour[prop]
                except KeyError:
                    pass

        if "post_logout_redirect_uris" not in req:
            try:
                req[
                    "post_logout_redirect_uris"] = self.post_logout_redirect_uris
            except AttributeError:
                pass

        if "redirect_uris" not in req:
            try:
                req["redirect_uris"] = self.redirect_uris
            except AttributeError:
                raise MissingRequiredAttribute("redirect_uris", req)

        return req

    def register(self, url, **kwargs):
        """
        Register the client at an OP

        :param url: The OPs registration endpoint
        :param kwargs: parameters to the registration request
        :return:
        """
        req = self.create_registration_request(**kwargs)

        headers = {"content-type": "application/json"}

        rsp = self.http_request(url, "POST", data=req.to_json(),
                                headers=headers)

        return self.handle_registration_info(rsp)

    def normalization(self, principal, idtype="mail"):
        if idtype == "mail":
            (local, domain) = principal.split("@")
            subject = "acct:%s" % principal
        elif idtype == "url":
            p = urlparse(principal)
            domain = p.netloc
            subject = principal
        else:
            domain = ""
            subject = principal

        return subject, domain

    def discover(self, principal):
        # subject, host = self.normalization(principal)
        return self.wf.discovery_query(principal)

    def sign_enc_algs(self, typ):
        resp = {}
        for key, val in PARAMMAP.items():
            try:
                resp[key] = self.registration_response[val % typ]
            except (TypeError, KeyError):
                if key == "sign":
                    resp[key] = DEF_SIGN_ALG["id_token"]
        return resp

    def _verify_id_token(self, id_token, nonce="", acr_values=None, auth_time=0,
                         max_age=0):
        """
        If the JWT alg Header Parameter uses a MAC based algorithm s uch as
        HS256, HS384, or HS512, the octets of the UTF-8 representation of the
        client_secret corresponding to the client_id contained in the aud
        (audience) Claim are used as the key to validate the signature. For MAC
        based algorithms, the behavior is unspecified if the aud is
        multi-valued or if an azp value is present that is different than the
        aud value.

        :param id_token: The ID Token tp check
        :param nonce: The nonce specified in the authorization request
        :param acr_values: Asked for acr values
        :param auth_time: An auth_time claim
        :param max_age: Max age of authentication
        """

        try:
            assert self.provider_info["issuer"] == id_token["iss"]
        except AssertionError:
            raise OtherError("issuer != iss")

        _now = time_util.utc_time_sans_frac()

        try:
            assert _now < id_token["exp"]
        except AssertionError:
            raise OtherError("Passed best before date")

        if self.id_token_max_age:
            try:
                assert _now < int(id_token["iat"]) + self.id_token_max_age
            except AssertionError:
                raise OtherError("I think this ID token is to old")

        if nonce:
            try:
                assert nonce == id_token["nonce"]
            except AssertionError:
                raise OtherError("nonce mismatch")

        if acr_values:
            try:
                assert id_token["acr"] in acr_values
            except AssertionError:
                raise OtherError("acr mismatch")

        if max_age:
            try:
                assert _now < int(id_token["auth_time"]) + max_age
            except AssertionError:
                raise AuthnToOld("To old authentication")

        if auth_time:
            if not claims_match(id_token["auth_time"],
                                {"auth_time": auth_time}):
                raise AuthnToOld("To old authentication")

    def verify_id_token(self, id_token, authn_req):
        kwa = {}
        try:
            kwa["nonce"] = authn_req["nonce"]
        except KeyError:
            pass

        for param in ["acr_values", "max_age"]:
            try:
                kwa[param] = authn_req[param]
            except KeyError:
                pass

        self._verify_id_token(id_token, **kwa)


# noinspection PyMethodOverriding
class Server(oauth2.Server):
    def __init__(self, keyjar=None, ca_certs=None, verify_ssl=True):
        oauth2.Server.__init__(self, keyjar, ca_certs, verify_ssl)

    @staticmethod
    def _parse_urlencoded(url=None, query=None):
        if url:
            parts = urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        return parse_qs(query)

    def parse_token_request(self, request=AccessTokenRequest,
                            body=None):
        return oauth2.Server.parse_token_request(self, request, body)

    def parse_authorization_request(self, request=AuthorizationRequest,
                                    url=None, query=None, keys=None):
        if url:
            parts = urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        return self._parse_request(request, query, "urlencoded")

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
        assert "id_token" in param  # ignore the rest
        return deser_id_token(self, param["id_token"][0])

    def parse_check_id_request(self, url=None, query=None):
        """

        """
        param = self._parse_urlencoded(url, query)
        assert "access_token" in param  # ignore the rest
        return deser_id_token(self, param["access_token"][0])

    def _parse_request(self, request, data, sformat, client_id=None):
        if sformat == "json":
            request = request().from_json(data)
        elif sformat == "jwt":
            request = request().from_jwt(data, keyjar=self.keyjar)
        elif sformat == "urlencoded":
            if '?' in data:
                parts = urlparse(data)
                scheme, netloc, path, params, query, fragment = parts[:6]
            else:
                query = data
            request = request().from_urlencoded(query)
        else:
            raise PyoidcError("Unknown package format: '%s'" % sformat,
                              request)

        # get the verification keys
        if client_id:
            keys = self.keyjar.verify_keys(client_id)
        else:
            try:
                keys = self.keyjar.verify_keys(request["client_id"])
            except KeyError:
                keys = None

        logger.debug("verify keys: {}".format(keys))
        request.verify(key=keys, keyjar=self.keyjar)
        return request

    def parse_open_id_request(self, data, sformat="urlencoded", client_id=None):
        return self._parse_request(OpenIDRequest, data, sformat, client_id)

    def parse_user_info_request(self, data, sformat="urlencoded"):
        return self._parse_request(UserInfoRequest, data, sformat)

    def parse_refresh_session_request(self, url=None, query=None):
        if url:
            parts = urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        return RefreshSessionRequest().from_urlencoded(query)

    def parse_registration_request(self, data, sformat="urlencoded"):
        return self._parse_request(RegistrationRequest, data, sformat)

    def parse_end_session_request(self, query, sformat="urlencoded"):
        esr = self._parse_request(EndSessionRequest, query,
                                  sformat)
        # if there is a id_token in there it is as a string
        esr["id_token"] = deser_id_token(self, esr["id_token"])
        return esr

    @staticmethod
    def update_claims(session, where, about, old_claims=None):
        """

        :param session:
        :param where: Which request
        :param about: userinfo or id_token
        :param old_claims:
        :return: claims or None
        """

        if old_claims is None:
            old_claims = {}

        req = None
        if where == "oidreq":
            try:
                req = OpenIDRequest().deserialize(session[where], "json")
            except KeyError:
                pass
        else:  # where == "authzreq"
            try:
                req = AuthorizationRequest().deserialize(session[where], "json")
            except KeyError:
                pass

        if req:
            logger.debug("%s: %s" % (where, req.to_dict()))
            try:
                _claims = req["claims"][about]
                if _claims:
                    # update with old claims, do not overwrite
                    for key, val in old_claims.items():
                        if key not in _claims:
                            _claims[key] = val
                    return _claims
            except KeyError:
                pass

        return old_claims

    def id_token_claims(self, session):
        """
        Pick the IdToken claims from the request

        :param session: Session information
        :return: The IdToken claims
        """
        itc = {}
        itc = self.update_claims(session, "authzreq", "id_token", itc)
        itc = self.update_claims(session, "oidreq", "id_token", itc)
        return itc

    def make_id_token(self, session, loa="2", issuer="",
                      alg="RS256", code=None, access_token=None,
                      user_info=None, auth_time=0, exp=None, extra_claims=None):
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
        # defaults
        if exp is None:
            inawhile = {"days": 1}
        else:
            inawhile = exp
        # Handle the idtoken_claims
        extra = {}
        itc = self.id_token_claims(session)
        if itc:
            try:
                inawhile = {"seconds": itc["max_age"]}
            except KeyError:
                pass
            for key, val in itc.items():
                if key == "auth_time":
                    extra["auth_time"] = auth_time
                elif key == "acr":
                    # ["2","http://id.incommon.org/assurance/bronze"]
                    extra["acr"] = verify_acr_level(val, loa)
        else:
            if auth_time:
                extra["auth_time"] = auth_time
            if loa:
                extra["acr"] = loa

        if not user_info:
            _args = {}
        else:
            try:
                _args = user_info.to_dict()
            except AttributeError:
                _args = user_info

        # Make sure that there are no name clashes
        for key in ["iss", "sub", "aud", "exp", "acr", "nonce",
                    "auth_time"]:
            try:
                del _args[key]
            except KeyError:
                pass

        halg = "HS%s" % alg[-3:]

        if extra_claims is not None:
            _args.update(extra_claims)
        if code:
            _args["c_hash"] = jws.left_hash(code.encode("utf-8"), halg)
        if access_token:
            _args["at_hash"] = jws.left_hash(access_token.encode("utf-8"),
                                             halg)

        # Should better be done elsewhere
        if not issuer.endswith("/"):
            issuer += "/"

        idt = IdToken(iss=issuer, sub=session["sub"],
                      aud=session["client_id"],
                      exp=time_util.epoch_in_a_while(**inawhile), acr=loa,
                      iat=time_util.utc_time_sans_frac(),
                      **_args)

        for key, val in extra.items():
            idt[key] = val

        if "nonce" in session:
            idt["nonce"] = session["nonce"]

        return idt
