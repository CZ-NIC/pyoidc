#!/usr/bin/env python
from future.backports.urllib.parse import urlparse

import logging

from jwkest import b64e

from oic import CC_METHOD
from oic import OIDCONF_PATTERN
from oic import unreserved
from oic.oauth2.base import PBase
from oic.oauth2.exception import GrantError
from oic.oauth2.exception import HttpError
from oic.oauth2.exception import MissingEndpoint
from oic.oauth2.exception import ParseError
from oic.oauth2.exception import ResponseError
from oic.oauth2.exception import TokenError
from oic.oauth2.exception import Unsupported
from oic.oauth2.grant import Grant
from oic.oauth2.grant import Token
from oic.oauth2.message import AccessTokenRequest
from oic.oauth2.message import ROPCAccessTokenRequest
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import ASConfigurationResponse
from oic.oauth2.message import AuthorizationErrorResponse
from oic.oauth2.message import AuthorizationRequest
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import ErrorResponse
from oic.oauth2.message import GrantExpired
from oic.oauth2.message import Message
from oic.oauth2.message import NoneResponse
from oic.oauth2.message import PyoidcError
from oic.oauth2.message import RefreshAccessTokenRequest
from oic.oauth2.message import ResourceRequest
from oic.oauth2.message import TokenErrorResponse
from oic.oauth2.message import sanitize
from oic.oauth2.util import get_or_post
from oic.oauth2.util import verify_header
from oic.utils.http_util import BadRequest
from oic.utils.http_util import Response
from oic.utils.http_util import SeeOther
from oic.utils.keyio import KeyJar
from oic.utils.time_util import utc_time_sans_frac

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


class ExpiredToken(PyoidcError):
    pass


# =============================================================================

def error_response(error, descr=None, status_code=400):
    logger.error("%s" % sanitize(error))
    response = ErrorResponse(error=error, error_description=descr)
    return Response(response.to_json(), content="application/json", status_code=status_code)


def none_response(**kwargs):
    _areq = kwargs["areq"]
    aresp = NoneResponse()
    if "state" in _areq:
        aresp["state"] = _areq["state"]

    return aresp


def authz_error(error, descr=None):
    response = AuthorizationErrorResponse(error=error)
    if descr:
        response["error_description"] = descr

    return Response(response.to_json(), content="application/json", status_code=400)


def redirect_authz_error(error, redirect_uri, descr=None, state="",
                         return_type=None):
    err = AuthorizationErrorResponse(error=error)
    if descr:
        err["error_description"] = descr
    if state:
        err["state"] = state
    if return_type is None or return_type == ["code"]:
        location = err.request(redirect_uri)
    else:
        location = err.request(redirect_uri, True)
    return SeeOther(location)


def exception_to_error_mesg(excep):
    if isinstance(excep, PyoidcError):
        if excep.content_type:
            if isinstance(excep.args, tuple):
                resp = BadRequest(excep.args[0], content=excep.content_type)
            else:
                resp = BadRequest(excep.args, content=excep.content_type)
        else:
            resp = BadRequest()
    else:
        err = ErrorResponse(error='service_error',
                            error_description='{}:{}'.format(
                                excep.__class__.__name__, excep.args))
        resp = BadRequest(err.to_json(), content='application/json')
    return resp


def compact(qsdict):
    res = {}
    for key, val in qsdict.items():
        if len(val) == 1:
            res[key] = val[0]
        else:
            res[key] = val
    return res

# =============================================================================


class Client(PBase):
    _endpoints = ENDPOINTS

    def __init__(self, client_id=None, client_authn_method=None,
                 keyjar=None, verify_ssl=True, config=None, client_cert=None):
        """

        :param client_id: The client identifier
        :param client_authn_method: Methods that this client can use to
            authenticate itself. It's a dictionary with method names as
            keys and method classes as values.
        :param keyjar: The keyjar for this client.
        :param verify_ssl: Whether the SSL certificate should be verified.
        :param client_cert: A client certificate to use.
        :return: Client instance
        """

        PBase.__init__(self, verify_ssl=verify_ssl, keyjar=keyjar,
                       client_cert=client_cert)

        self.client_id = client_id
        self.client_authn_method = client_authn_method

        self.nonce = None

        self.grant = {}
        self.state2nonce = {}
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

        # the OAuth issuer is the URL of the authorization server's
        # configuration information location
        self.config = config or {}
        try:
            self.issuer = self.config['issuer']
        except KeyError:
            self.issuer = ''
        self.allow = {}
        self.provider_info = {}

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
            self.keyjar.add_symmetric("", str(val))

    client_secret = property(get_client_secret, set_client_secret)

    def reset(self):
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
        except KeyError:
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

    def clean_tokens(self):
        """Clean replaced and invalid tokens."""
        for state in self.grant:
            grant = self.get_grant(state)
            for token in grant.tokens:
                if token.replaced or not token.is_valid():
                    grant.delete_token(token)

    def construct_request(self, request, request_args=None, extra_args=None):
        if request_args is None:
            request_args = {}

        # logger.debug("request_args: %s" % sanitize(request_args))
        kwargs = self._parse_args(request, **request_args)

        if extra_args:
            kwargs.update(extra_args)
            # logger.debug("kwargs: %s" % sanitize(kwargs))
        # logger.debug("request: %s" % sanitize(request))
        return request(**kwargs)

    def construct_Message(self, request=Message, request_args=None,
                          extra_args=None, **kwargs):

        return self.construct_request(request, request_args, extra_args)

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

    def construct_AccessTokenRequest(self,
                                     request=AccessTokenRequest,
                                     request_args=None, extra_args=None,
                                     **kwargs):

        if request_args is None:
            request_args = {}
        if request is not ROPCAccessTokenRequest:
            grant = self.get_grant(**kwargs)

            if not grant.is_valid():
                raise GrantExpired("Authorization Code to old %s > %s" % (
                    utc_time_sans_frac(),
                    grant.grant_expiration_time))

            request_args["code"] = grant.code

        try:
            request_args['state'] = kwargs['state']
        except KeyError:
            pass

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

    # def construct_TokenRevocationRequest(self,
    #                                      request=TokenRevocationRequest,
    #                                      request_args=None, extra_args=None,
    #                                      **kwargs):
    #
    #     if request_args is None:
    #         request_args = {}
    #
    #     token = self.get_token(**kwargs)
    #
    #     request_args["token"] = token.access_token
    #     return self.construct_request(request, request_args, extra_args)

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

        if self.events:
            self.events.store('Protocol request', cis)

        if 'nonce' in cis and 'state' in cis:
            self.state2nonce[cis['state']] = cis['nonce']

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

        # if self.events:
        #    self.events.store('Response', info)
        resp = response().deserialize(info, sformat, **kwargs)
        msg = 'Initial response parsing => "{}"'
        logger.debug(msg.format(sanitize(resp.to_dict())))
        if self.events:
            self.events.store('Response', resp.to_dict())

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
                    except Exception:
                        resp = None
            except KeyError:
                pass
        elif resp.only_extras():
            resp = None
        else:
            kwargs["client_id"] = self.client_id
            try:
                kwargs['iss'] = self.provider_info['issuer']
            except (KeyError, AttributeError):
                if self.issuer:
                    kwargs['iss'] = self.issuer

            if "key" not in kwargs and "keyjar" not in kwargs:
                kwargs["keyjar"] = self.keyjar

            logger.debug("Verify response with {}".format(sanitize(kwargs)))
            verf = resp.verify(**kwargs)

            if not verf:
                logger.error('Verification of the response failed')
                raise PyoidcError("Verification of the response failed")
            if resp.type() == "AuthorizationResponse" and "scope" not in resp:
                try:
                    resp["scope"] = kwargs["scope"]
                except KeyError:
                    pass

        if not resp:
            logger.error('Missing or faulty response')
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
        elif reqresp.status_code in [302, 303]:  # redirect
            return reqresp
        elif reqresp.status_code == 500:
            logger.error("(%d) %s" % (reqresp.status_code,
                                      sanitize(reqresp.text)))
            raise ParseError("ERROR: Something went wrong: %s" % reqresp.text)
        elif reqresp.status_code in [400, 401]:
            # expecting an error response
            if issubclass(response, ErrorResponse):
                pass
        else:
            logger.error("(%d) %s" % (reqresp.status_code,
                                      sanitize(reqresp.text)))
            raise HttpError("HTTP ERROR: %s [%s] on %s" % (
                reqresp.text, reqresp.status_code, reqresp.url))

        if response:
            if body_type == 'txt':
                # no meaning trying to parse unstructured text
                return reqresp.text
            return self.parse_response(response, reqresp.text, body_type,
                                       state, **kwargs)

        # could be an error response
        if reqresp.status_code in [200, 400, 401]:
            if body_type == 'txt':
                body_type = 'urlencoded'
            try:
                err = ErrorResponse().deserialize(reqresp.message,
                                                  method=body_type)
                try:
                    err.verify()
                except PyoidcError:
                    pass
                else:
                    return err
            except Exception:
                pass

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
            try:
                request_args["state"] = state
            except TypeError:
                request_args = {"state": state}

        kwargs['authn_endpoint'] = 'authorization'
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
        except KeyError:
            algs = {}

        resp = self.request_and_return(url, response_cls, method, body,
                                       body_type, state=state,
                                       http_args=http_args, algs=algs)

        if isinstance(resp, Message):
            if resp.type() in RESPONSE2ERROR["AuthorizationResponse"]:
                resp.state = csi.state

        return resp

    def do_access_token_request(self, request=AccessTokenRequest,
                                scope="", state="", body_type="json",
                                method="POST", request_args=None,
                                extra_args=None, http_args=None,
                                response_cls=AccessTokenResponse,
                                authn_method="", **kwargs):

        kwargs['authn_endpoint'] = 'token'
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

        if self.events is not None:
            self.events.store('request_url', url)
            self.events.store('request_http_args', http_args)
            self.events.store('Request', body)

        logger.debug("<do_access_token> URL: %s, Body: %s" % (url,
                                                              sanitize(body)))
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
        kwargs['authn_endpoint'] = 'refresh'
        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    token=token,
                                                    authn_method=authn_method)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(ht_args)

        response = self.request_and_return(url, response_cls, method, body,
                                           body_type, state=state,
                                           http_args=http_args)
        if token.replaced:
            grant = self.get_grant(state)
            grant.delete_token(token)
        return response

    # def do_revocate_token(self, request=TokenRevocationRequest,
    #                       scope="", state="", body_type="json", method="POST",
    #                       request_args=None, extra_args=None, http_args=None,
    #                       response_cls=None, authn_method=""):
    #
    #     url, body, ht_args, csi = self.request_info(request, method=method,
    #                                                 request_args=request_args,
    #                                                 extra_args=extra_args,
    #                                                 scope=scope, state=state,
    #                                                 authn_method=authn_method)
    #
    #     if http_args is None:
    #         http_args = ht_args
    #     else:
    #         http_args.update(ht_args)
    #
    #     return self.request_and_return(url, response_cls, method, body,
    #                                    body_type, state=state,
    #                                    http_args=http_args)

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
                self.do_access_token_refresh(state=state)
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

    def add_code_challenge(self):
        """
        PKCE RFC 7636 support

        :return:
        """
        try:
            cv_len = self.config['code_challenge']['length']
        except KeyError:
            cv_len = 64  # Use default

        code_verifier = unreserved(cv_len)
        _cv = code_verifier.encode()

        try:
            _method = self.config['code_challenge']['method']
        except KeyError:
            _method = 'S256'

        try:
            _h = CC_METHOD[_method](_cv).hexdigest()
            code_challenge = b64e(_h.encode()).decode()
        except KeyError:
            raise Unsupported(
                'PKCE Transformation method:{}'.format(_method))

        # TODO store code_verifier

        return {"code_challenge": code_challenge,
                "code_challenge_method": _method}, code_verifier

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

            if not self.allow.get("issuer_mismatch", False) and _issuer != _pcr_issuer:
                raise PyoidcError("provider info issuer mismatch '%s' != '%s'" % (_issuer, _pcr_issuer))

            self.provider_info = pcr
        else:
            _pcr_issuer = issuer

        self.issuer = _pcr_issuer

        if endpoints:
            for key, val in pcr.items():
                if key.endswith("_endpoint"):
                    setattr(self, key, val)

        if keys:
            if self.keyjar is None:
                self.keyjar = KeyJar()

            self.keyjar.load_keys(pcr, _pcr_issuer)

    def provider_config(self, issuer, keys=True, endpoints=True,
                        response_cls=ASConfigurationResponse,
                        serv_pattern=OIDCONF_PATTERN):
        if issuer.endswith("/"):
            _issuer = issuer[:-1]
        else:
            _issuer = issuer

        url = serv_pattern % _issuer

        pcr = None
        r = self.http_request(url)
        if r.status_code == 200:
            pcr = response_cls().from_json(r.text)
        elif r.status_code == 302:
            while r.status_code == 302:
                r = self.http_request(r.headers["location"])
                if r.status_code == 200:
                    pcr = response_cls().from_json(r.text)
                    break

        if pcr is None:
            raise PyoidcError("Trying '%s', status %s" % (url, r.status_code))

        self.handle_provider_config(pcr, issuer, keys, endpoints)

        return pcr


class Server(PBase):
    def __init__(self, keyjar=None, verify_ssl=True, client_cert=None):
        PBase.__init__(self, verify_ssl=verify_ssl, keyjar=keyjar,
                       client_cert=client_cert)

    @staticmethod
    def parse_url_request(request, url=None, query=None):
        if url:
            parts = urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        if isinstance(query, dict):
            req = request(**query)
        else:
            req = request().deserialize(query, "urlencoded")
        req.verify()
        return req

    def parse_authorization_request(self, request=AuthorizationRequest,
                                    url=None, query=None):

        return self.parse_url_request(request, url, query)

    def parse_jwt_request(self, request=AuthorizationRequest, txt="",
                          keyjar="", verify=True, **kwargs):

        if not keyjar:
            keyjar = self.keyjar

        # areq = message().from_(txt, keys, verify)
        areq = request().deserialize(txt, "jwt", keyjar=keyjar,
                                     verify=verify, **kwargs)
        if verify:
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
