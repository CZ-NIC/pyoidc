#!/usr/bin/env python

import random
import string

from oic.oauth2.base import PBase
from oic.oauth2.exception import MissingEndpoint
from oic.oauth2.exception import GrantError
from oic.oauth2.exception import ResponseError
from oic.oauth2.exception import TokenError
from oic.oauth2.exception import ParseError
from oic.oauth2.exception import HttpError
from oic.oauth2.exception import OtherError
from oic.oauth2.grant import Token
from oic.oauth2.grant import Grant
from oic.oauth2.util import get_or_post
from oic.oauth2.util import verify_header
from oic.utils.keyio import KeyJar
from oic.utils.time_util import utc_time_sans_frac
from oic.oauth2.message import *

__author__ = 'rohe0002'

logger = logging.getLogger(__name__)

DEF_SIGN_ALG = "HS256"
SUCCESSFUL = [200, 201, 202, 203, 204, 205, 206]


Version = "2.0"

HTTP_ARGS = ["headers", "redirections", "connection_type"]

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


# =============================================================================

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
        :param verify_ssl: Whether the SSL certificate should be verified.
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
        self.authz_req = None

    def store_response(self, clinst, text):
        pass

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

    def uri_and_body(self, reqmsg, cis, method="POST", request_args=None,
                     **kwargs):

        if "endpoint" in kwargs and kwargs["endpoint"]:
            uri = kwargs["endpoint"]
        else:
            uri = self._endpoint(self.request2endpoint[reqmsg.__name__],
                                 **request_args)

        uri, body, kwargs = get_or_post(uri, method, cis, **kwargs)
        try:
            h_args = {"headers": kwargs["headers"]}
        except KeyError:
            h_args = {}

        return uri, body, h_args, cis

    def request_info(self, request, method="POST", request_args=None,
                     extra_args=None, lax=False, **kwargs):

        if request_args is None:
            request_args = {}

        try:
            cls = getattr(self, "construct_%s" % request.__name__)
            cis = cls(request_args=request_args, extra_args=extra_args,
                      **kwargs)
        except AttributeError:
            cis = self.construct_request(request, request_args, extra_args)

        cis.lax = lax

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

    def get_urlinfo(self, info):
        if '?' in info or '#' in info:
            parts = urlparse(info)
            scheme, netloc, path, params, query, fragment = parts[:6]
            # either query of fragment
            if query:
                info = query
            else:
                info = fragment
        return info

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
            info = self.get_urlinfo(info)

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
                    except Exception as aerr:
                        resp = None
                        err = aerr
            except KeyError:
                pass
        elif resp.only_extras():
            resp = None
        else:
            kwargs["client_id"] = self.client_id
            if "key" not in kwargs and "keyjar" not in kwargs:
                kwargs["keyjar"] = self.keyjar

            logger.debug("Verify response with {}".format(kwargs))
            verf = resp.verify(**kwargs)

            if not verf:
                raise PyoidcError("Verification of the response failed")
            if resp.type() == "AuthorizationResponse" and \
                    "scope" not in resp:
                try:
                    resp["scope"] = kwargs["scope"]
                except KeyError:
                    pass

        if not resp:
            raise ResponseError("Missing or faulty response")

        self.store_response(resp, info)

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

    # noinspection PyUnusedLocal
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

    def parse_request_response(self, reqresp, response, body_type, state="",
                               **kwargs):

        if reqresp.status_code in SUCCESSFUL:
            body_type = verify_header(reqresp, body_type)
        elif reqresp.status_code == 302:  # redirect
            pass
        elif reqresp.status_code == 500:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise ParseError("ERROR: Something went wrong: %s" % reqresp.text)
        elif reqresp.status_code in [400, 401]:
            # expecting an error response
            if issubclass(response, ErrorResponse):
                pass
        else:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise HttpError("HTTP ERROR: %s [%s] on %s" % (
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

        try:
            self.authz_req[request_args["state"]] = csi
        except TypeError:
            pass

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(ht_args)

        try:
            algs = kwargs["algs"]
        except:
            algs = {}

        resp = self.request_and_return(url, response_cls, method, body,
                                       body_type, state=state,
                                       http_args=http_args, algs=algs)

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
            http_args.update(ht_args)

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
            http_args.update(ht_args)

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
            http_args.update(ht_args)

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
            http_args.update(ht_args)

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
            parts = urlparse(url)
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
