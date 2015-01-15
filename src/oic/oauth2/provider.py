#!/usr/bin/env python
import traceback
import sys
import urllib
import urlparse
from oic.utils.sdb import AccessCodeUsed, AuthnEvent


__author__ = 'rohe0002'

import base64
import logging
import os

from oic.exception import MissingParameter
from oic.exception import URIError
from oic.exception import RedirectURIError
from oic.exception import ParameterError
from oic.exception import FailedAuthentication
from oic.exception import UnknownClient

from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import ErrorResponse
from oic.oauth2.message import AuthorizationErrorResponse
from oic.oauth2.message import AuthorizationRequest
from oic.oauth2.message import add_non_standard
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import NoneResponse
from oic.oauth2.message import by_schema
from oic.oauth2.message import MissingRequiredAttribute
from oic.oauth2.message import TokenErrorResponse
from oic.oauth2.message import AccessTokenRequest

from oic.utils.http_util import BadRequest
from oic.utils.http_util import CookieDealer
from oic.utils.http_util import make_cookie
from oic.utils.http_util import Redirect
from oic.utils.http_util import Response

from oic.utils.authn.user import NoSuchAuthentication
from oic.utils.authn.user import ToOld
from oic.utils.authn.user import TamperAllert

from oic.oauth2 import rndstr
from oic.oauth2 import Server

logger = logging.getLogger(__name__)
LOG_INFO = logger.info
LOG_DEBUG = logger.debug


class Endpoint(object):
    etype = ""

    def __init__(self, func):
        self.func = func

    @property
    def name(self):
        return "%s_endpoint" % self.etype

    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)


class AuthorizationEndpoint(Endpoint):
    etype = "authorization"


class TokenEndpoint(Endpoint):
    etype = "token"


def code_response(**kwargs):
    _areq = kwargs["areq"]
    _scode = kwargs["scode"]
    aresp = AuthorizationResponse()
    if "state" in _areq:
        aresp["state"] = _areq["state"]
    aresp["code"] = _scode
    add_non_standard(_areq, aresp)
    return aresp


def token_response(**kwargs):
    _areq = kwargs["areq"]
    _scode = kwargs["scode"]
    _sdb = kwargs["sdb"]
    _dic = _sdb.upgrade_to_token(_scode, issue_refresh=False)

    aresp = AccessTokenResponse(**by_schema(AccessTokenResponse, **_dic))
    if "state" in _areq:
        aresp["state"] = _areq["state"]

    return aresp


# noinspection PyUnusedLocal
def none_response(**kwargs):
    _areq = kwargs["areq"]
    aresp = NoneResponse()
    if "state" in _areq:
        aresp["state"] = _areq["state"]

    return aresp


def location_url(response_type, redirect_uri, query):
    if response_type in [["code"], ["token"], ["none"]]:
        return "%s?%s" % (redirect_uri, query)
    else:
        return "%s#%s" % (redirect_uri, query)


class Provider(object):
    endp = [AuthorizationEndpoint, TokenEndpoint]

    def __init__(self, name, sdb, cdb, authn_broker, authz, client_authn,
                 symkey="", urlmap=None, iv=0, default_scope="",
                 ca_bundle=None, verify_ssl=True, default_acr=""):
        self.name = name
        self.sdb = sdb
        self.cdb = cdb
        self.server = Server(ca_certs=ca_bundle, verify_ssl=verify_ssl)

        self.authn_broker = authn_broker
        if authn_broker is None:
            # default cookie function
            self.cookie_func = CookieDealer(srv=self).create_cookie
        else:
            self.cookie_func = self.authn_broker[0][0].create_cookie
            for item in self.authn_broker:
                item.srv = self

        self.authz = authz
        self.client_authn = client_authn
        self.symkey = symkey
        self.seed = rndstr()
        self.iv = iv or os.urandom(16)
        self.cookie_name = "pyoidc"
        self.default_scope = default_scope
        self.sso_ttl = 0
        self.default_acr = default_acr

        if urlmap is None:
            self.urlmap = {}
        else:
            self.urlmap = urlmap

        self.response_type_map = {
            "code": code_response,
            "token": token_response,
            "none": none_response,
        }

    def endpoints(self):
        for endp in self.endp:
            yield endp(None).name

    def subset(self, li1, li2):
        """
        Verify that all items in li1 appears in li2

        :param li1: List 1
        :param li2: List 2
        :return: True if all items in li1 appears in li2
        """
        for item in li1:
            try:
                assert item in li2
            except AssertionError:
                return False
        return True

    def get_client_id(self, req, authn):
        """
        Verify the client and return the client id

        :param req: The request
        :param authn: Authentication information from the HTTP header
        :return:
        """

        logger.debug("REQ: %s" % req.to_dict())
        if authn:
            if authn.startswith("Basic "):
                logger.debug("Basic auth")
                (_id, _secret) = base64.b64decode(authn[6:]).split(":")
                if _id not in self.cdb:
                    logger.debug("Unknown client_id")
                    raise FailedAuthentication("Unknown client_id")
                else:
                    try:
                        assert _secret == self.cdb[_id]["client_secret"]
                    except AssertionError:
                        logger.debug("Incorrect secret")
                        raise FailedAuthentication("Incorrect secret")
            else:
                try:
                    assert authn[:6].lower() == "bearer"
                    logger.debug("Bearer auth")
                    _token = authn[7:]
                except AssertionError:
                    raise FailedAuthentication("AuthZ type I don't know")

                try:
                    _id = self.cdb[_token]
                except KeyError:
                    logger.debug("Unknown access token")
                    raise FailedAuthentication("Unknown access token")
        else:
            try:
                _id = req["client_id"]
                if _id not in self.cdb:
                    logger.debug("Unknown client_id")
                    raise FailedAuthentication("Unknown client_id")
            except KeyError:
                raise FailedAuthentication("Missing client_id")

        return _id

    def authn_reply(self, areq, aresp, bsid, **kwargs):
        """

        :param areq: Authorization Request
        :param aresp: Authorization Response
        :param bsid: Session id
        :param kwargs: Additional keyword args
        :return:
        """
        if "redirect_uri" in areq:
            # TODO verify that the uri is reasonable
            redirect_uri = areq["redirect_uri"]
        else:
            redirect_uri = self.urlmap[areq["client_id"]]

        location = location_url(areq["response_type"], redirect_uri,
                                aresp.to_urlencoded())

        LOG_DEBUG("Redirected to: '%s' (%s)" % (location, type(location)))

        # set cookie containing session ID

        cookie = make_cookie(self.cookie_name, bsid, self.seed)

        return Redirect(str(location), headers=[cookie])

    def authn_response(self, areq, **kwargs):
        """

        :param areq: Authorization request
        :param kwargs: Extra keyword arguments
        :return:
        """
        scode = kwargs["code"]
        areq["response_type"].sort()
        _rtype = " ".join(areq["response_type"])
        return self.response_type_map[_rtype](areq=areq, scode=scode,
                                              sdb=self.sdb)

    @staticmethod
    def input(query="", post=None):
        # Support GET and POST
        if query:
            return query
        elif post:
            return post
        else:
            raise MissingParameter("No input")

    @staticmethod
    def _error_response(error, descr=None):
        logger.error("%s" % error)
        response = ErrorResponse(error=error, error_description=descr)
        return Response(response.to_json(), content="application/json",
                        status="400 Bad Request")

    @staticmethod
    def _error(error, descr=None):
        response = ErrorResponse(error=error, error_description=descr)
        return Response(response.to_json(), content="application/json",
                        status="400 Bad Request")

    @staticmethod
    def _authz_error(error, descr=None):

        response = AuthorizationErrorResponse(error=error)
        if descr:
            response["error_description"] = descr

        return Response(response.to_json(), content="application/json",
                        status="400 Bad Request")

    @staticmethod
    def _redirect_authz_error(error, redirect_uri, descr=None, state="",
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
        return Redirect(location)

    def _verify_redirect_uri(self, areq):
        """
        MUST NOT contain a fragment
        MAY contain query component

        :return: An error response if the redirect URI is faulty otherwise
            None
        """
        try:
            _redirect_uri = urlparse.unquote(areq["redirect_uri"])

            part = urlparse.urlparse(_redirect_uri)
            if part.fragment:
                raise URIError("Contains fragment")

            (_base, _query) = urllib.splitquery(_redirect_uri)
            if _query:
                _query = urlparse.parse_qs(_query)

            match = False
            for regbase, rquery in self.cdb[areq["client_id"]]["redirect_uris"]:
                if _base == regbase or _redirect_uri.startswith(regbase):
                    # every registered query component must exist in the
                    # redirect_uri
                    if rquery:
                        for key, vals in rquery.items():
                            assert key in _query
                            for val in vals:
                                assert val in _query[key]
                    match = True
                    break
            if not match:
                raise RedirectURIError("Doesn't match any registered uris")
            # ignore query components that are not registered
            return None
        except Exception, err:
            logger.error("Faulty redirect_uri: %s" % areq["redirect_uri"])
            try:
                _cinfo = self.cdb[areq["client_id"]]
            except KeyError:
                logger.info("Unknown client: %s" % areq["client_id"])
                raise UnknownClient(areq["client_id"])
            else:
                logger.info("Registered redirect_uris: %s" % _cinfo)
                raise RedirectURIError("Faulty redirect_uri: %s" % err)

    def get_redirect_uri(self, areq):
        """ verify that the redirect URI is reasonable

        :param areq: The Authorization request
        :return: Tuple of (redirect_uri, Response instance)
            Response instance is not None of matching redirect_uri failed
        """
        if 'redirect_uri' in areq:
            self._verify_redirect_uri(areq)
            uri = areq["redirect_uri"]
        else:
            raise ParameterError(
                "Missing redirect_uri and more than one or none registered")

        return uri

    def pick_auth(self, areq, comparision_type=""):
        """

        :param areq: AuthorizationRequest instance
        :param comparision_type: How to pick the authentication method
        :return: An authentication method and its authn class ref
        """
        if comparision_type == "any":
            return self.authn_broker[0]

        try:
            if len(self.authn_broker) == 1:
                return self.authn_broker[0]
            else:
                try:
                    _values = areq["acr_values"]
                except KeyError:
                    _values = self.default_acr

                if isinstance(_values, basestring):
                    _values = [_values]

                if not comparision_type:
                    comparision_type = "exact"

                for _acr in _values:
                    res = self.authn_broker.pick(_acr, comparision_type)
                    if res:
                        # Return the best guess by pick.
                        return res[0]
        except KeyError:
            pass

        # return the best I have
        return None, None

    def authorization_endpoint(self, request="", cookie="", authn="", **kwargs):
        """ The AuthorizationRequest endpoint

        :param request: The client request
        """

        logger.debug("Request: '%s'" % request)
        # Same serialization used for GET and POST
        try:
            areq = self.server.parse_authorization_request(query=request)
        except MissingRequiredAttribute, err:
            logger.debug("%s" % err)
            return self._error("invalid_request", "%s" % err)
        except KeyError:
            areq = AuthorizationRequest().deserialize(request, "urlencoded")
            # verify the redirect_uri
            try:
                self.get_redirect_uri(areq)
            except (RedirectURIError, ParameterError), err:
                return self._error("invalid_request", "%s" % err)
        except Exception, err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            logger.debug("Bad request: %s (%s)" % (err, err.__class__.__name__))
            return BadRequest("%s" % err)

        if not areq:
            logger.debug("No AuthzRequest")
            return self._error("invalid_request", "No parsable AuthzRequest")

        logger.debug("AuthzRequest: %s" % (areq.to_dict(),))
        try:
            redirect_uri = self.get_redirect_uri(areq)
        except (RedirectURIError, ParameterError), err:
            return self._error("invalid_request", "%s" % err)
        except UnknownClient, err:
            return self._error("unauthorized_client", "%s" % err)

        try:
            # verify that the request message is correct
            areq.verify()
        except (MissingRequiredAttribute, ValueError), err:
            return self._redirect_authz_error("invalid_request", redirect_uri,
                                              "%s" % err)

        # Check if the person is already authenticated
        a_args = {}
        if cookie:
            logger.debug("Cookie: %s" % cookie)
            a_args["cookie"] = cookie
        if authn:
            try:
                a_args["authorization"] = authn
            except KeyError:
                pass

        # Pick authentication method
        _authn, acr = self.pick_auth(areq=areq)

        if authn is None:
            return self._redirect_authz_error("invalid_request", redirect_uri)

        try:
            identity = _authn.authenticated_as(**a_args)
        except (NoSuchAuthentication, ToOld, TamperAllert):
            identity = None

        authn_args = {"query": request}

        cinfo = self.cdb[areq["client_id"]]
        for attr in ["policy_uri", "logo_uri", "tos_uri"]:
            try:
                authn_args[attr] = cinfo[attr]
            except KeyError:
                pass

        # To authenticate or Not
        if identity is None:  # No!
            if "prompt" in areq and "none" in areq["prompt"]:
                # Need to authenticate but not allowed
                return self._redirect_authz_error("login_required",
                                                  redirect_uri)
            else:
                # Do authentication
                return _authn(**authn_args)
        else:
            user = identity["uid"]
            aevent = AuthnEvent(user, authn_info=acr)

        # If I get this far the person is already authenticated
        logger.debug("- authenticated -")
        logger.debug("AREQ keys: %s" % areq.keys())

        try:
            oidc_req = areq["request"]
        except KeyError:
            oidc_req = None

        skey = self.sdb.create_authz_session(aevent, areq, oidreq=oidc_req)

        # Now about the authorization step.
        try:
            permissions = self.authz.permissions(cookie)
            if not permissions:
                return self.authz(user, skey)
        except (ToOld, TamperAllert):
            return self.authz(user, areq, skey)

        return self.authz_part2(user, areq, skey, permissions, _authn)

    def authz_part2(self, user, areq, skey, permission=None, authn=None,
                    **kwargs):
        """
        After the authentication this is where you should end up

        :param user:
        :param areq: The Authorization Request
        :param skey: Session key
        :param permission: A permission specification
        :param authn: The Authentication Method used
        :param kwargs: possible other parameters
        :return: A redirect to the redirect_uri of the client
        """
        _log_debug = logger.debug
        _log_debug("- in authenticated() -")

        self.sdb.update(skey, "auz", permission)

        _log_debug("response type: %s" % areq["response_type"])

        # create the response
        aresp = AuthorizationResponse()
        try:
            aresp["state"] = areq["state"]
        except KeyError:
            pass

        if "response_type" in areq and \
                        len(areq["response_type"]) == 1 and \
                        "none" in areq["response_type"]:
            pass
        else:
            # if self.sdb.is_revoked(sinfo):
            #    return self._error(error="access_denied",
            #                       descr="Token is revoked")

            try:
                aresp["scope"] = areq["scope"]
            except KeyError:
                pass

            _log_debug("_dic: %s" % self.sdb[skey])

            rtype = set(areq["response_type"][:])
            if "code" in areq["response_type"]:
                #if issue_new_code:
                #    scode = self.sdb.duplicate(_sinfo)
                #    _sinfo = self.sdb[scode]

                _code = aresp["code"] = self.sdb.get_token(skey)
                rtype.remove("code")
            else:
                _code = self.sdb[skey]["code"]
                self.sdb.update(skey, "code", None)

            if "token" in rtype:
                self.sdb.upgrade_to_token(skey, issue_refresh=False,
                                          access_grant=_code)
                atr = AccessTokenResponse(**aresp.to_dict())
                aresp = atr
                _cont = self.sdb[skey]
                _log_debug("_dic: %s" % _cont)
                for key, val in _cont.items():
                    if key in aresp.parameters() and val is not None:
                        aresp[key] = val

                rtype.remove("token")

            if len(rtype):
                return BadRequest("Unknown response type")

        try:
            redirect_uri = self.get_redirect_uri(areq)
        except (RedirectURIError, ParameterError), err:
            return BadRequest("%s" % err)

        # self.sdb.store_session(skey)

        # so everything went well should set a SSO cookie
        headers = [authn.create_cookie(user, typ="sso", ttl=self.sso_ttl)]
        location = aresp.request(redirect_uri)
        logger.debug("Redirected to: '%s' (%s)" % (location, type(location)))
        return Redirect(str(location), headers=headers)

    def token_scope_check(self, areq, info):
        """ Not implemented here """
        # if not self.subset(areq["scope"], _info["scope"]):
        # LOG_INFO("Asked for scope which is not subset of previous defined")
        #     err = TokenErrorResponse(error="invalid_scope")
        #     return Response(err.to_json(), content="application/json")
        return None

    def token_endpoint(self, authn="", **kwargs):
        """
        This is where clients come to get their access tokens
        """

        _sdb = self.sdb

        LOG_DEBUG("- token -")
        body = kwargs["request"]
        LOG_DEBUG("body: %s" % body)

        areq = AccessTokenRequest().deserialize(body, "urlencoded")

        try:
            client = self.client_authn(self, areq, authn)
        except FailedAuthentication, err:
            err = TokenErrorResponse(error="unauthorized_client",
                                     error_description="%s" % err)
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        LOG_DEBUG("AccessTokenRequest: %s" % areq)

        try:
            assert areq["grant_type"] == "authorization_code"
        except AssertionError:
            err = TokenErrorResponse(error="invalid_request",
                                     error_description="Wrong grant type")
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        # assert that the code is valid
        _info = _sdb[areq["code"]]

        resp = self.token_scope_check(areq, _info)
        if resp:
            return resp

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _info:
            assert areq["redirect_uri"] == _info["redirect_uri"]

        try:
            _tinfo = _sdb.upgrade_to_token(areq["code"])
        except AccessCodeUsed:
            err = TokenErrorResponse(error="invalid_grant",
                                     error_description="Access grant used")
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        LOG_DEBUG("_tinfo: %s" % _tinfo)

        atr = AccessTokenResponse(**by_schema(AccessTokenResponse, **_tinfo))

        LOG_DEBUG("AccessTokenResponse: %s" % atr)

        return Response(atr.to_json(), content="application/json")

    def verify_endpoint(self, request="", cookie=None, **kwargs):
        _req = urlparse.parse_qs(request)
        try:
            areq = urlparse.parse_qs(_req["query"][0])
        except KeyError:
            return BadRequest()

        authn, acr = self.pick_auth(areq=areq)
        kwargs["cookie"] = cookie
        return authn.verify(_req, **kwargs)
