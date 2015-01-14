#!/usr/bin/env python
import time

__author__ = 'rohe0002'

import requests
import random
import string
import cookielib
from Cookie import SimpleCookie

from oic.utils.keyio import KeyJar
from oic.utils.time_util import utc_time_sans_frac
from oic.exception import UnSupported
import logging

logger = logging.getLogger(__name__)

DEF_SIGN_ALG = "HS256"

from oic.oauth2.message import *

Version = "2.0"

HTTP_ARGS = ["headers", "redirections", "connection_type"]

URL_ENCODED = 'application/x-www-form-urlencoded'
JSON_ENCODED = "application/json"
DEFAULT_POST_CONTENT_TYPE = URL_ENCODED

REQUEST2ENDPOINT = {
    "AuthorizationRequest": "authorization_endpoint",
    "AccessTokenRequest": "token_endpoint",
    # ROPCAccessTokenRequest: "authorization_endpoint",
    # CCAccessTokenRequest: "authorization_endpoint",
    "RefreshAccessTokenRequest": "token_endpoint",
    "TokenRevocationRequest": "token_endpoint"}

RESPONSE2ERROR = {
    "AuthorizationResponse": [AuthorizationErrorResponse, TokenErrorResponse],
    "AccessTokenResponse": [TokenErrorResponse]
}

ENDPOINTS = ["authorization_endpoint", "token_endpoint",
             "token_revocation_endpoint"]


class HTTP_ERROR(PyoidcError):
    pass


class MISSING_REQUIRED_ATTRIBUTE(PyoidcError):
    pass


class VerificationError(PyoidcError):
    pass


class ResponseError(PyoidcError):
    pass


class TimeFormatError(PyoidcError):
    pass


class CapabilitiesMisMatch(PyoidcError):
    pass


class MissingEndpoint(PyoidcError):
    pass


class TokenError(PyoidcError):
    pass


class GrantError(PyoidcError):
    pass


class ParseError(PyoidcError):
    pass


class OtherError(PyoidcError):
    pass


def rndstr(size=16):
    """
    Returns a string of random ascii characters or digits

    :param size: The length of the string
    :return: string
    """
    _basech = string.ascii_letters + string.digits
    return "".join([random.choice(_basech) for _ in range(size)])


# -----------------------------------------------------------------------------


class ExpiredToken(PyoidcError):
    pass


# -----------------------------------------------------------------------------


class Token(object):
    def __init__(self, resp=None):
        self.scope = []
        self.token_expiration_time = 0
        self.access_token = None
        self.refresh_token = None
        self.token_type = None
        self.replaced = False

        if resp:
            for prop, val in resp.items():
                setattr(self, prop, val)

            try:
                _expires_in = resp["expires_in"]
            except KeyError:
                return

            if _expires_in:
                _tet = utc_time_sans_frac() + int(_expires_in)
            else:
                _tet = 0
            self.token_expiration_time = int(_tet)

    def is_valid(self):
        if self.token_expiration_time:
            if utc_time_sans_frac() > self.token_expiration_time:
                return False

        return True

    def __str__(self):
        return "%s" % self.__dict__

    def keys(self):
        return self.__dict__.keys()

    def __eq__(self, other):
        skeys = self.keys()
        okeys = other.keys()
        if set(skeys) != set(okeys):
            return False

        for key in skeys:
            if getattr(self, key) != getattr(other, key):
                return False

        return True


class Grant(object):
    _authz_resp = AuthorizationResponse
    _acc_resp = AccessTokenResponse
    _token_class = Token

    def __init__(self, exp_in=600, resp=None, seed=""):
        self.grant_expiration_time = 0
        self.exp_in = exp_in
        self.seed = seed
        self.tokens = []
        self.id_token = None
        self.code = None
        if resp:
            self.add_code(resp)
            self.add_token(resp)

    @classmethod
    def from_code(cls, resp):
        instance = cls()
        instance.add_code(resp)
        return instance

    def add_code(self, resp):
        try:
            self.code = resp["code"]
            self.grant_expiration_time = utc_time_sans_frac() + self.exp_in
        except KeyError:
            pass

    def add_token(self, resp):
        """
        :param resp: An Authorization Response instance
        """

        if "access_token" in resp:
            tok = self._token_class(resp)
            self.tokens.append(tok)

    def is_valid(self):
        if utc_time_sans_frac() > self.grant_expiration_time:
            return False
        else:
            return True

    def __str__(self):
        return "%s" % self.__dict__

    def keys(self):
        return self.__dict__.keys()

    def update(self, resp):
        if "access_token" in resp or "id_token" in resp:
            tok = self._token_class(resp)
            if tok not in self.tokens:
                for otok in self.tokens:
                    otok.replaced = True
                self.tokens.append(tok)

        if "code" in resp:
            self.add_code(resp)

    def get_token(self, scope=""):
        token = None
        if scope:
            for token in self.tokens:
                if scope in token.scope and not token.replaced:
                    return token
        else:
            for token in self.tokens:
                if token.is_valid() and not token.replaced:
                    return token

        return token

    def get_id_token(self):
        if self.id_token:
            return self.id_token
        else:
            for tok in self.tokens:
                if tok.id_token:
                    if tok.id_token["exp"] >= time.time():
                        return tok.id_token
        return None

    def join(self, grant):
        if not self.exp_in:
            self.exp_in = grant.exp_in
        if not self.grant_expiration_time:
            self.grant_expiration_time = grant.grant_expiration_time
        if not self.seed:
            self.seed = grant.seed
        for token in grant.tokens:
            if token not in self.tokens:
                for otok in self.tokens:
                    if token.scope == otok.scope:
                        otok.replaced = True
                self.tokens.append(token)


# =============================================================================
# =============================================================================

ATTRS = {"version": None,
         "name": "",
         "value": None,
         "port": None,
         "port_specified": False,
         "domain": "",
         "domain_specified": False,
         "domain_initial_dot": False,
         "path": "",
         "path_specified": False,
         "secure": False,
         "expires": None,
         "discard": True,
         "comment": None,
         "comment_url": None,
         "rest": "",
         "rfc2109": True}

PAIRS = {
    "port": "port_specified",
    "domain": "domain_specified",
    "path": "path_specified"
}


class PBase(object):
    def __init__(self, ca_certs=None, verify_ssl=True):

        self.keyjar = KeyJar(verify_ssl=verify_ssl)

        self.request_args = {"allow_redirects": False}
        # self.cookies = {}
        self.cookiejar = cookielib.FileCookieJar()
        self.ca_certs = ca_certs
        if ca_certs:
            self.request_args["verify"] = verify_ssl
        else:
            self.request_args["verify"] = False

    def _cookies(self):
        cookie_dict = {}

        for _, a in list(self.cookiejar._cookies.items()):
            for _, b in list(a.items()):
                for cookie in list(b.values()):
                    # print cookie
                    cookie_dict[cookie.name] = cookie.value

        return cookie_dict

    def set_cookie(self, kaka):
        """PLaces a cookie (a cookielib.Cookie based on a set-cookie header
        line) in the cookie jar.
        Always chose the shortest expires time.
        """

        # default rfc2109=False
        # max-age, httponly
        for cookie_name, morsel in kaka.items():
            std_attr = ATTRS.copy()
            std_attr["name"] = cookie_name
            _tmp = morsel.coded_value
            if _tmp.startswith('"') and _tmp.endswith('"'):
                std_attr["value"] = _tmp[1:-1]
            else:
                std_attr["value"] = _tmp

            std_attr["version"] = 0
            attr = ""
            # copy attributes that have values
            try:
                for attr in morsel.keys():
                    if attr in ATTRS:
                        if morsel[attr]:
                            if attr == "expires":
                                std_attr[attr] = cookielib.http2time(morsel[attr])
                            else:
                                std_attr[attr] = morsel[attr]
                    elif attr == "max-age":
                        if morsel[attr]:
                            std_attr["expires"] = cookielib.http2time(morsel[attr])
            except TimeFormatError:
                # Ignore cookie
                logger.info(
                    "Time format error on %s parameter in received cookie" % (
                        attr,))
                continue

            for att, spec in PAIRS.items():
                if std_attr[att]:
                    std_attr[spec] = True

            if std_attr["domain"] and std_attr["domain"].startswith("."):
                std_attr["domain_initial_dot"] = True

            if morsel["max-age"] is 0:
                try:
                    self.cookiejar.clear(domain=std_attr["domain"],
                                         path=std_attr["path"],
                                         name=std_attr["name"])
                except ValueError:
                    pass
            else:
                # Fix for Microsoft cookie error
                if "version" in std_attr:
                    try:
                        std_attr["version"] = std_attr["version"].split(",")[0]
                    except (TypeError, AttributeError):
                        pass

                new_cookie = cookielib.Cookie(**std_attr)

                self.cookiejar.set_cookie(new_cookie)

                # return cookiejar

    def http_request(self, url, method="GET", **kwargs):
        _kwargs = copy.copy(self.request_args)
        if kwargs:
            _kwargs.update(kwargs)

        if self.cookiejar:
            _kwargs["cookies"] = self._cookies()
            logger.debug("SENT COOKIEs: %s" % (_kwargs["cookies"],))

        try:
            r = requests.request(method, url, **_kwargs)
        except Exception as err:
            logger.error(
                "http_request failed: %s, url: %s, htargs: %s, method: %s" % (
                    err, url, _kwargs, method))
            raise

        try:
            set_cookie = r.headers["set-cookie"]
            # Telekom fix
            # set_cookie = set_cookie.replace(
            # "=;Path=/;Expires=Thu, 01-Jan-1970 00:00:01 GMT;HttpOnly,", "")
            logger.debug("RECEIVED COOKIEs: %s" % set_cookie)
            self.set_cookie(SimpleCookie(set_cookie))
        except (AttributeError, KeyError), err:
            pass

        return r

    def send(self, url, method="GET", **kwargs):
        return self.http_request(url, method, **kwargs)

    def load_cookies_from_file(self, filename, ignore_discard=False,
                               ignore_expires=False):
        self.cookiejar.load(filename, ignore_discard, ignore_expires)

    def save_cookies_to_file(self, filename, ignore_discard=False,
                             ignore_expires=False):

        self.cookiejar.save(filename, ignore_discard, ignore_expires)


class Client(PBase):
    _endpoints = ENDPOINTS

    def __init__(self, client_id=None, ca_certs=None, client_authn_method=None,
                 keyjar=None, verify_ssl=True):
        """

        :param client_id: The client identifier
        :param ca_certs: Certificates used to verify HTTPS certificates
        :param client_authn_method: Methods that this client can use to
            authenticate itself. It's a dictionary with method names as
            keys and method classes as values.
        :param verify_ssl: Whether the SSL certificate should be verfied.
        :return: Client instance
        """

        PBase.__init__(self, ca_certs, verify_ssl=verify_ssl)

        self.client_id = client_id
        self.client_authn_method = client_authn_method
        self.keyjar = keyjar or KeyJar(verify_ssl=verify_ssl)
        self.verify_ssl = verify_ssl
        # self.secret_type = "basic "

        # self.state = None
        self.nonce = None

        self.grant = {}

        # own endpoint
        self.redirect_uris = [None]

        # service endpoints
        self.authorization_endpoint = None
        self.token_endpoint = None
        self.token_revocation_endpoint = None

        self.request2endpoint = REQUEST2ENDPOINT
        self.response2error = RESPONSE2ERROR
        self.grant_class = Grant
        self.token_class = Token

        self.provider_info = {}
        self._c_secret = None
        self.kid = {"sig": {}, "enc": {}}

    def get_client_secret(self):
        return self._c_secret

    def set_client_secret(self, val):
        if not val:
            self._c_secret = ""
        else:
            self._c_secret = val
            # client uses it for signing
            # Server might also use it for signing which means the
            # client uses it for verifying server signatures
            if self.keyjar is None:
                self.keyjar = KeyJar()
            self.keyjar.add_symmetric("", str(val), ["sig"])

    client_secret = property(get_client_secret, set_client_secret)

    def reset(self):
        # self.state = None
        self.nonce = None

        self.grant = {}

        self.authorization_endpoint = None
        self.token_endpoint = None
        self.redirect_uris = None

    def grant_from_state(self, state):
        for key, grant in self.grant.items():
            if key == state:
                return grant

        return None

    def _parse_args(self, request, **kwargs):
        ar_args = kwargs.copy()

        for prop in request.c_param.keys():
            if prop in ar_args:
                continue
            else:
                if prop == "redirect_uri":
                    _val = getattr(self, "redirect_uris", [None])[0]
                    if _val:
                        ar_args[prop] = _val
                else:
                    _val = getattr(self, prop, None)
                    if _val:
                        ar_args[prop] = _val

        return ar_args

    def _endpoint(self, endpoint, **kwargs):
        try:
            uri = kwargs[endpoint]
            if uri:
                del kwargs[endpoint]
        except KeyError:
            uri = ""

        if not uri:
            try:
                uri = getattr(self, endpoint)
            except Exception:
                raise MissingEndpoint("No '%s' specified" % endpoint)

        if not uri:
            raise MissingEndpoint("No '%s' specified" % endpoint)

        return uri

    def get_grant(self, state, **kwargs):
        # try:
        # _state = kwargs["state"]
        # if not _state:
        #         _state = self.state
        # except KeyError:
        #     _state = self.state

        try:
            return self.grant[state]
        except:
            raise GrantError("No grant found for state:'%s'" % state)

    def get_token(self, also_expired=False, **kwargs):
        try:
            return kwargs["token"]
        except KeyError:
            grant = self.get_grant(**kwargs)

            try:
                token = grant.get_token(kwargs["scope"])
            except KeyError:
                token = grant.get_token("")
                if not token:
                    try:
                        token = self.grant[kwargs["state"]].get_token("")
                    except KeyError:
                        raise TokenError("No token found for scope")

        if token is None:
            raise TokenError("No suitable token found")

        if also_expired:
            return token
        elif token.is_valid():
            return token
        else:
            raise TokenError("Token has expired")

    def construct_request(self, request, request_args=None, extra_args=None):
        if request_args is None:
            request_args = {}

        # logger.debug("request_args: %s" % request_args)
        kwargs = self._parse_args(request, **request_args)

        if extra_args:
            kwargs.update(extra_args)
            # logger.debug("kwargs: %s" % kwargs)
        # logger.debug("request: %s" % request)
        return request(**kwargs)

    def construct_Message(self, request=Message, request_args=None,
                          extra_args=None, **kwargs):

        return self.construct_request(request, request_args, extra_args)

    # noinspection PyUnusedLocal
    def construct_AuthorizationRequest(self, request=AuthorizationRequest,
                                       request_args=None, extra_args=None,
                                       **kwargs):

        if request_args is not None:
            try:  # change default
                new = request_args["redirect_uri"]
                if new:
                    self.redirect_uris = [new]
            except KeyError:
                pass
        else:
            request_args = {}

        if "client_id" not in request_args:
            request_args["client_id"] = self.client_id
        elif not request_args["client_id"]:
            request_args["client_id"] = self.client_id

        return self.construct_request(request, request_args, extra_args)

    # noinspection PyUnusedLocal
    def construct_AccessTokenRequest(self,
                                     request=AccessTokenRequest,
                                     request_args=None, extra_args=None,
                                     **kwargs):

        grant = self.get_grant(**kwargs)

        if not grant.is_valid():
            raise GrantExpired("Authorization Code to old %s > %s" % (
                utc_time_sans_frac(),
                grant.grant_expiration_time))

        if request_args is None:
            request_args = {}

        request_args["code"] = grant.code

        if "grant_type" not in request_args:
            request_args["grant_type"] = "authorization_code"

        if "client_id" not in request_args:
            request_args["client_id"] = self.client_id
        elif not request_args["client_id"]:
            request_args["client_id"] = self.client_id
        return self.construct_request(request, request_args, extra_args)

    def construct_RefreshAccessTokenRequest(self,
                                            request=RefreshAccessTokenRequest,
                                            request_args=None, extra_args=None,
                                            **kwargs):

        if request_args is None:
            request_args = {}

        token = self.get_token(also_expired=True, **kwargs)

        request_args["refresh_token"] = token.refresh_token

        try:
            request_args["scope"] = token.scope
        except AttributeError:
            pass

        return self.construct_request(request, request_args, extra_args)

    def construct_TokenRevocationRequest(self,
                                         request=TokenRevocationRequest,
                                         request_args=None, extra_args=None,
                                         **kwargs):

        if request_args is None:
            request_args = {}

        token = self.get_token(**kwargs)

        request_args["token"] = token.access_token
        return self.construct_request(request, request_args, extra_args)

    def construct_ResourceRequest(self, request=ResourceRequest,
                                  request_args=None, extra_args=None,
                                  **kwargs):

        if request_args is None:
            request_args = {}

        token = self.get_token(**kwargs)

        request_args["access_token"] = token.access_token
        return self.construct_request(request, request_args, extra_args)

    @staticmethod
    def get_or_post(uri, method, req, content_type=DEFAULT_POST_CONTENT_TYPE,
                    accept=None, **kwargs):
        if method == "GET":
            _qp = req.to_urlencoded()
            if _qp:
                path = uri + '?' + _qp
            else:
                path = uri
            body = None
        elif method == "POST":
            path = uri
            if content_type == URL_ENCODED:
                body = req.to_urlencoded()
            elif content_type == JSON_ENCODED:
                body = req.to_json()
            else:
                raise UnSupported(
                    "Unsupported content type: '%s'" % content_type)

            header_ext = {"Content-type": content_type}
            if accept:
                header_ext = {"Accept": accept}

            if "headers" in kwargs.keys():
                kwargs["headers"].update(header_ext)
            else:
                kwargs["headers"] = header_ext
        else:
            raise UnSupported("Unsupported HTTP method: '%s'" % method)

        return path, body, kwargs

    def uri_and_body(self, reqmsg, cis, method="POST", request_args=None,
                     **kwargs):

        if "endpoint" in kwargs and kwargs["endpoint"]:
            uri = kwargs["endpoint"]
        else:
            uri = self._endpoint(self.request2endpoint[reqmsg.__name__],
                                 **request_args)

        uri, body, kwargs = self.get_or_post(uri, method, cis, **kwargs)
        try:
            h_args = {"headers": kwargs["headers"]}
        except KeyError:
            h_args = {}

        return uri, body, h_args, cis

    def request_info(self, request, method="POST", request_args=None,
                     extra_args=None, **kwargs):

        if request_args is None:
            request_args = {}

        try:
            cls = getattr(self, "construct_%s" % request.__name__)
            cis = cls(request_args=request_args, extra_args=extra_args,
                      **kwargs)
        except AttributeError:
            cis = self.construct_request(request, request_args, extra_args)

        if "authn_method" in kwargs:
            h_arg = self.init_authentication_method(cis,
                                                    request_args=request_args,
                                                    **kwargs)
        else:
            h_arg = None

        if h_arg:
            if "headers" in kwargs.keys():
                kwargs["headers"].update(h_arg["headers"])
            else:
                kwargs["headers"] = h_arg["headers"]

        return self.uri_and_body(request, cis, method, request_args,
                                 **kwargs)

    def authorization_request_info(self, request_args=None, extra_args=None,
                                   **kwargs):
        return self.request_info(AuthorizationRequest, "GET",
                                 request_args, extra_args, **kwargs)

    def parse_response(self, response, info="", sformat="json", state="",
                       **kwargs):
        """
        Parse a response

        :param response: Response type
        :param info: The response, can be either in a JSON or an urlencoded
            format
        :param sformat: Which serialization that was used
        :param state: The state
        :param kwargs: Extra key word arguments
        :return: The parsed and to some extend verified response
        """

        _r2e = self.response2error

        if sformat == "urlencoded":
            if '?' in info or '#' in info:
                parts = urlparse.urlparse(info)
                scheme, netloc, path, params, query, fragment = parts[:6]
                # either query of fragment
                if query:
                    info = query
                else:
                    info = fragment

        err = None
        try:
            resp = response().deserialize(info, sformat, **kwargs)
            if "error" in resp and not isinstance(resp, ErrorResponse):
                resp = None
                try:
                    errmsgs = _r2e[response.__name__]
                except KeyError:
                    errmsgs = [ErrorResponse]

                try:
                    for errmsg in errmsgs:
                        try:
                            resp = errmsg().deserialize(info, sformat)
                            resp.verify()
                            break
                        except Exception, aerr:
                            resp = None
                            err = aerr
                except KeyError:
                    pass
            elif resp.only_extras():
                resp = None
            else:
                if "key" not in kwargs and "keyjar" not in kwargs:
                    kwargs["keyjar"] = self.keyjar
                verf = resp.verify(**kwargs)
                if not verf:
                    raise PyoidcError("Verification of the response failed")
                if resp.type() == "AuthorizationResponse" and \
                        "scope" not in resp:
                    try:
                        resp["scope"] = kwargs["scope"]
                    except KeyError:
                        pass
        except Exception, derr:
            resp = None
            err = derr

        if not resp:
            if err:
                raise err
            else:
                raise ResponseError("Missing or faulty response")

        if resp.type() in ["AuthorizationResponse", "AccessTokenResponse"]:
            try:
                _state = resp["state"]
            except (AttributeError, KeyError):
                _state = ""

            if not _state:
                _state = state

            try:
                self.grant[_state].update(resp)
            except KeyError:
                self.grant[_state] = self.grant_class(resp=resp)

        return resp

    #noinspection PyUnusedLocal
    def init_authentication_method(self, cis, authn_method, request_args=None,
                                   http_args=None, **kwargs):

        if http_args is None:
            http_args = {}
        if request_args is None:
            request_args = {}

        if authn_method:
            return self.client_authn_method[authn_method](self).construct(
                cis, request_args, http_args, **kwargs)
        else:
            return http_args

    @staticmethod
    def verify_header(reqresp, body_type):
        logger.debug("resp.headers: %s" % (reqresp.headers,))
        logger.debug("resp.txt: %s" % (reqresp.text,))

        # This might be a tad to strict
        if body_type == "":
            pass
        elif body_type == "json":
            try:
                assert "application/json" in reqresp.headers["content-type"]
            except AssertionError:
                try:
                    assert "application/jwt" in reqresp.headers["content-type"]
                    body_type = "jwt"
                except AssertionError:
                    raise AssertionError("Wrong content-type in header")
        elif body_type == "jwt":
            try:
                assert "application/jwt" in reqresp.headers["content-type"]
            except AssertionError:
                raise AssertionError("Wrong content-type in header")
        elif body_type == "urlencoded":
            try:
                assert DEFAULT_POST_CONTENT_TYPE in reqresp.headers[
                    "content-type"]
            except AssertionError:
                assert "text/plain" in reqresp.headers["content-type"]
        else:
            raise ValueError("Unknown return format: %s" % body_type)

        return body_type

    def parse_request_response(self, reqresp, response, body_type, state="",
                               **kwargs):

        if reqresp.status_code in [200, 201]:
            body_type = self.verify_header(reqresp, body_type)
        elif reqresp.status_code == 302:  # redirect
            pass
        elif reqresp.status_code == 500:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise ParseError("ERROR: Something went wrong: %s" % reqresp.text)
        elif reqresp.status_code in [400, 401]:
            #expecting an error response
            if issubclass(response, ErrorResponse):
                pass
        else:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise HTTP_ERROR("HTTP ERROR: %s [%s] on %s" % (
                reqresp.text, reqresp.status_code, reqresp.url))

        if body_type:
            if response:
                return self.parse_response(response, reqresp.text, body_type,
                                           state, **kwargs)
            else:
                raise OtherError("Didn't expect a response body")
        else:
            return reqresp

    def request_and_return(self, url, response=None, method="GET", body=None,
                           body_type="json", state="", http_args=None,
                           **kwargs):
        """
        :param url: The URL to which the request should be sent
        :param response: Response type
        :param method: Which HTTP method to use
        :param body: A message body if any
        :param body_type: The format of the body of the return message
        :param http_args: Arguments for the HTTP client
        :return: A cls or ErrorResponse instance or the HTTP response
            instance if no response body was expected.
        """

        if http_args is None:
            http_args = {}

        try:
            resp = self.http_request(url, method, data=body, **http_args)
        except Exception:
            raise

        if "keyjar" not in kwargs:
            kwargs["keyjar"] = self.keyjar

        return self.parse_request_response(resp, response, body_type, state,
                                           **kwargs)

    def do_authorization_request(self, request=AuthorizationRequest,
                                 state="", body_type="", method="GET",
                                 request_args=None, extra_args=None,
                                 http_args=None,
                                 response_cls=AuthorizationResponse,
                                 **kwargs):

        if state:
            request_args["state"] = state

        url, body, ht_args, csi = self.request_info(request, method,
                                                    request_args, extra_args,
                                                    **kwargs)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        resp = self.request_and_return(url, response_cls, method, body,
                                       body_type, state=state,
                                       http_args=http_args)

        if isinstance(resp, Message):
            if resp.type() in RESPONSE2ERROR["AuthorizationRequest"]:
                resp.state = csi.state

        return resp

    def do_access_token_request(self, request=AccessTokenRequest,
                                scope="", state="", body_type="json",
                                method="POST", request_args=None,
                                extra_args=None, http_args=None,
                                response_cls=AccessTokenResponse,
                                authn_method="", **kwargs):

        # method is default POST
        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state,
                                                    authn_method=authn_method,
                                                    **kwargs)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        logger.debug("<do_access_token> URL: %s, Body: %s" % (url, body))
        logger.debug("<do_access_token> response_cls: %s" % response_cls)

        return self.request_and_return(url, response_cls, method, body,
                                       body_type, state=state,
                                       http_args=http_args, **kwargs)

    def do_access_token_refresh(self, request=RefreshAccessTokenRequest,
                                state="", body_type="json", method="POST",
                                request_args=None, extra_args=None,
                                http_args=None,
                                response_cls=AccessTokenResponse,
                                authn_method="", **kwargs):

        token = self.get_token(also_expired=True, state=state, **kwargs)

        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    token=token,
                                                    authn_method=authn_method)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, response_cls, method, body,
                                       body_type, state=state,
                                       http_args=http_args)

    def do_revocate_token(self, request=TokenRevocationRequest,
                          scope="", state="", body_type="json", method="POST",
                          request_args=None, extra_args=None, http_args=None,
                          response_cls=None, authn_method=""):

        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state,
                                                    authn_method=authn_method)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, response_cls, method, body,
                                       body_type, state=state,
                                       http_args=http_args)

    def do_any(self, request, endpoint="", scope="", state="", body_type="json",
               method="POST", request_args=None, extra_args=None,
               http_args=None, response=None, authn_method=""):

        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state,
                                                    authn_method=authn_method,
                                                    endpoint=endpoint)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, response, method, body, body_type,
                                       state=state, http_args=http_args)

    def fetch_protected_resource(self, uri, method="GET", headers=None,
                                 state="", **kwargs):

        if "token" in kwargs and kwargs["token"]:
            token = kwargs["token"]
            request_args = {"access_token": token}
        else:
            try:
                token = self.get_token(state=state, **kwargs)
            except ExpiredToken:
                # The token is to old, refresh
                self.do_access_token_refresh()
                token = self.get_token(state=state, **kwargs)
            request_args = {"access_token": token.access_token}

        if headers is None:
            headers = {}

        if "authn_method" in kwargs:
            http_args = self.init_authentication_method(
                request_args=request_args, **kwargs)
        else:
            # If nothing defined this is the default
            http_args = self.client_authn_method[
                "bearer_header"](self).construct(request_args=request_args)

        headers.update(http_args["headers"])

        logger.debug("Fetch URI: %s" % uri)
        return self.http_request(uri, method, headers=headers)


class Server(PBase):
    def __init__(self, keys=None, ca_certs=None, verify_ssl=True):
        PBase.__init__(self, ca_certs, verify_ssl)

    @staticmethod
    def parse_url_request(request, url=None, query=None):
        if url:
            parts = urlparse.urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        req = request().deserialize(query, "urlencoded")
        req.verify()
        return req

    def parse_authorization_request(self, request=AuthorizationRequest,
                                    url=None, query=None):

        return self.parse_url_request(request, url, query)

    def parse_jwt_request(self, request=AuthorizationRequest, txt="",
                          keyjar="", verify=True):

        if not keyjar:
            keyjar = self.keyjar

        # areq = message().from_(txt, keys, verify)
        areq = request().deserialize(txt, "jwt", keyjar=keyjar,
                                     verify=verify)
        areq.verify()
        return areq

    def parse_body_request(self, request=AccessTokenRequest, body=None):
        # req = message(reqmsg).from_urlencoded(body)
        req = request().deserialize(body, "urlencoded")
        req.verify()
        return req

    def parse_token_request(self, request=AccessTokenRequest,
                            body=None):
        return self.parse_body_request(request, body)

    def parse_refresh_token_request(self, request=RefreshAccessTokenRequest,
                                    body=None):
        return self.parse_body_request(request, body)
