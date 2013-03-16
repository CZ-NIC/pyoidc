#!/usr/bin/env python
import logging
from oic.oic.exception import MissingParameter
from oic.oauth2.exception import FailedAuthentication, MissingSession

__author__ = 'rohe0002'

import base64

from urlparse import parse_qs

from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import add_non_standard
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import NoneResponse
from oic.oauth2.message import AuthorizationRequest
from oic.oauth2.message import by_schema
from oic.oauth2.message import MissingRequiredAttribute
from oic.oauth2.message import TokenErrorResponse
from oic.oauth2.message import AccessTokenRequest

from oic.utils.http_util import Unauthorized
from oic.utils.http_util import BadRequest
from oic.utils.http_util import Redirect
from oic.utils.http_util import ServiceError
from oic.utils.http_util import Response

from oic.oauth2 import rndstr
from oic.oauth2 import Server as SrvMethod

logger = logging.getLogger(__name__)
LOG_INFO = logger.info
LOG_DEBUG = logger.debug


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
    _dic = _sdb.update_to_token(_scode, issue_refresh=False)

    aresp = AccessTokenResponse(**_dic)
    if "state" in _areq:
        aresp["state"] = _areq["state"]

    return aresp


#noinspection PyUnusedLocal
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
    def __init__(self, name, sdb, cdb, function, urlmap=None):
        self.name = name
        self.sdb = sdb
        self.cdb = cdb
        self.srvmethod = SrvMethod()
        self.function = function
        self.seed = rndstr()

        if urlmap is None:
            self.urlmap = {}
        else:
            self.urlmap = urlmap

        self.response_type_map = {
            "code": code_response,
            "token": token_response,
            "none": none_response,
        }

    #noinspection PyUnusedLocal
    def authn_intro(self, post="", **kwargs):
        """
        After the authentication this is where you should end up
        """

        _sdb = self.sdb

        # parse the form
        dic = parse_qs(post)

        try:
            (verified, user) = self.function["verify_user"](dic)
            if not verified:
                raise FailedAuthentication("Wrong password")
        except KeyError, err:
            logger.error("KeyError on authentication: %s" % err)
            raise FailedAuthentication("Authentication failed")
        except FailedAuthentication, err:
            raise

        try:
            # Use the session identifier to find the session information
            sid = base64.b64decode(dic["sid"][0])
            session = _sdb[sid]
        except KeyError:
            raise MissingSession("Unknown session identifier")

        _sdb.update(sid, "sub", dic["login"][0])

        LOG_DEBUG("session[\"authzreq\"] = %s" % session["authzreq"])
        #_log_info( "type: %s" % type(session["authzreq"]))

        # pick up the original request
        areq = AuthorizationRequest().deserialize(session["authzreq"], "json")

        LOG_DEBUG("areq: %s" % areq)

        # Do the authorization
        try:
            permission = self.function["authorize"](user, session)
            _sdb.update(sid, "permission", permission)
        except Exception:
            raise

        LOG_INFO("response type: %s" % areq["response_type"])

        return areq, session

    def authn_reply(self, areq, aresp, **kwargs):

        if "redirect_uri" in areq:
            # TODO verify that the uri is reasonable
            redirect_uri = areq["redirect_uri"]
        else:
            redirect_uri = self.urlmap[areq["client_id"]]

        location = location_url(areq["response_type"], redirect_uri,
                                aresp.to_urlencoded())

        LOG_DEBUG("Redirected to: '%s' (%s)" % (location, type(location)))

        return Redirect(str(location))

    def authn_response(self, areq, **kwargs):
        scode = kwargs["code"]
        areq["response_type"].sort()
        _rtype = " ".join(areq["response_type"])
        return self.response_type_map[_rtype](areq=areq, scode=scode,
                                              sdb=self.sdb)

    def authenticated(self, post=None, **kwargs):

        LOG_DEBUG("- authenticated -")

        try:
            areq, session = self.authn_intro(post, **kwargs)
        except FailedAuthentication:
            return Unauthorized("Authentication failed")
        except MissingSession, err:
            return ServiceError("%s" % err)

        try:
            aresp = self.authn_response(areq,
                                        **by_schema(AuthorizationResponse,
                                                    **session))
        except KeyError, err:  # Don't know what to do raise an exception
            return BadRequest("Unknown response type (%s)" % err)

        add_non_standard(aresp, areq)

        return self.authn_reply(areq, aresp)

    def input(self, query="", post=None):
        # Support GET and POST
        if query:
            return query
        elif post:
            return post
        else:
            raise MissingParameter("No input")

    def authorization_endpoint(self, query="", **kwargs):
        """ The AuthorizationRequest endpoint

        :param query: The query part of the request URL
        """
        _sdb = self.sdb

        LOG_DEBUG("- authorization -")
        LOG_DEBUG("Query: '%s'" % query)

        try:
            areq = self.srvmethod.parse_authorization_request(query=query)
        except MissingRequiredAttribute, err:
            return BadRequest("%s" % err)
        except Exception, err:
            return BadRequest("%s" % err)

#        if "redirect_uri" in areq:
#            _redirect = areq["redirect_uri"]
#        else:
#            # A list, so pick one (==the first)
#            _redirect = self.urlmap[areq["client_id"]][0]

        sid = _sdb.create_authz_session("", areq)
        bsid = base64.b64encode(sid)

        grant = _sdb[sid]["code"]
        LOG_DEBUG("code: '%s'" % grant)

        return self.function["authenticate"](bsid)

    def token_endpoint(self, **kwargs):
        """
        This is where clients come to get their access tokens
        """

        _sdb = self.sdb

        LOG_DEBUG("- token -")
        body = kwargs["post"]
        LOG_DEBUG("body: %s" % body)

        areq = AccessTokenRequest().deserialize(body, "urlencoded")

        # Client is from basic auth or ...
        try:
            client = areq["client_id"]
        except KeyError:
            err = TokenErrorResponse(error="unathorized_client")
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        try:
            client = self.function["verify_client"](client, self.cdb)
        except (KeyError, AttributeError):
            err = TokenErrorResponse(error="unathorized_client",
                                     error_description="client_id:%s" % client)
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        LOG_DEBUG("AccessTokenRequest: %s" % areq)

        assert areq["grant_type"] == "authorization_code"

        # assert that the code is valid
        _info = _sdb[areq["code"]]

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _info:
            assert areq["redirect_uri"] == _info["redirect_uri"]

        _tinfo = _sdb.update_to_token(areq["code"])

        LOG_DEBUG("_tinfo: %s" % _tinfo)
            
        atr = AccessTokenResponse(**by_schema(AccessTokenResponse, **_tinfo))

        LOG_DEBUG("AccessTokenResponse: %s" % atr)

        return Response(atr.to_json(), content="application/json")

# =============================================================================


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
