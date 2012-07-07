#!/usr/bin/env python
import logging

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

class AuthnFailure(Exception):
    pass

def get_post(environ):
    # the environment variable CONTENT_LENGTH may be empty or missing
    try:
      request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    except ValueError:
      request_body_size = 0

    # When the method is POST the query string will be sent
    # in the HTTP request body which is passed by the WSGI server
    # in the file like wsgi.input environment variable.
    return environ['wsgi.input'].read(request_body_size)

#noinspection PyUnusedLocal
#def do_authorization(user):
#    return ""

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
    if response_type in [["code"],["token"],["none"]]:
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
    def authn_intro(self, environ, start_response):
        """
        After the authentication this is where you should end up
        """

        _sdb = self.sdb

        # parse the form
        dic = parse_qs(get_post(environ))

        try:
            (verified, user) = self.function["verify user"](dic)
            if not verified:
                return Unauthorized("Wrong password")
        except KeyError, err:
            return Unauthorized("Authentication failed")
        except AuthnFailure, err:
            return Unauthorized("Authentication failure: %s" % (err,))

        try:
            # Use the session identifier to find the session information
            sid = base64.b64decode(dic["sid"][0])
            session = _sdb[sid]
        except KeyError:
            return BadRequest("Unknown session identifier")

        _sdb.update(sid, "user_id", dic["login"][0])

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

    def authn_reply(self, areq, aresp, environ, start_response):

        if "redirect_uri" in areq:
            # TODO verify that the uri is reasonable
            redirect_uri = areq["redirect_uri"]
        else:
            redirect_uri = self.urlmap[areq["client_id"]]

        location = location_url(areq["response_type"], redirect_uri,
                                aresp.to_urlencoded())

        LOG_DEBUG("Redirected to: '%s' (%s)" % (location, type(location)))

        redirect = Redirect(str(location))
        return redirect(environ, start_response)

    def authn_response(self, areq, **kwargs):
        scode = kwargs["code"]
        areq["response_type"].sort()
        _rtype = " ".join(areq["response_type"])
        return self.response_type_map[_rtype](areq=areq, scode=scode,
                                              sdb=self.sdb)

    def authenticated(self, environ, start_response):

        LOG_DEBUG("- authenticated -")

        try:
            result = self.authn_intro(environ, start_response)
        except Exception, err:
            resp = ServiceError("%s" % err)
            return resp(environ, start_response)

        if isinstance(result, Response):
            return result(environ, start_response)
        else:
            areq, session = result


        try:
            aresp = self.authn_response(areq,
                                        **by_schema(AuthorizationResponse,
                                                    **session))
        except KeyError, err: # Don't know what to do raise an exception
            resp = BadRequest("Unknown response type (%s)" % err)
            return resp(environ, start_response)

        add_non_standard(aresp, areq)

        return self.authn_reply(areq, aresp, environ, start_response)
    
    def authorization_endpoint(self, environ, start_response, **kwargs):
        # The AuthorizationRequest endpoint

        _sdb = self.sdb

        LOG_DEBUG("- authorization -")

        if environ.get("REQUEST_METHOD") == "GET":
            query = environ.get("QUERY_STRING")
        elif environ.get("REQUEST_METHOD") == "POST":
            query = get_post(environ)
        else:
            resp = BadRequest("Unsupported method")
            return resp(environ, start_response)
            
        LOG_DEBUG("Query: '%s'" % query)

        try:
            areq = self.srvmethod.parse_authorization_request(query=query)
        except MissingRequiredAttribute, err:
            resp = BadRequest("%s" % err)
            return resp(environ, start_response)
        except Exception,err:
            resp = BadRequest("%s" % err)
            return resp(environ, start_response)

#        if "redirect_uri" in areq:
#            _redirect = areq["redirect_uri"]
#        else:
#            # A list, so pick one (==the first)
#            _redirect = self.urlmap[areq["client_id"]][0]

        sid = _sdb.create_authz_session("", areq)
        bsid = base64.b64encode(sid)

        grant = _sdb[sid]["code"]
        LOG_DEBUG("code: '%s'" % grant)

        return self.function["authenticate"](environ, start_response, bsid)

    def token_endpoint(self, environ, start_response):
        """
        This is where clients come to get their access tokens
        """

        _sdb = self.sdb

        LOG_DEBUG("- token -")
        body = get_post(environ)
        LOG_DEBUG("body: %s" % body)

        areq = AccessTokenRequest().deserialize(body, "urlencoded")

        # Client is from basic auth or ...
        client = environ["REMOTE_USER"]
        if not self.function["verify client"](environ, client, self.cdb):
            err = TokenErrorResponse(error="unathorized_client")
            resp = Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")
            return resp(environ, start_response)

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

        resp = Response(atr.to_json(), content="application/json")
        return resp(environ, start_response)

