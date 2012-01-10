#!/usr/bin/env python

__author__ = 'rohe0002'

import base64

try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs

from oic.utils.http_util import *

from oic.oauth2 import rndstr

from oic.oauth2 import Server as SrvMethod

from oic.oauth2 import MissingRequiredAttribute
from oic.oauth2 import AuthorizationResponse
from oic.oauth2 import AuthorizationRequest
from oic.oauth2 import AccessTokenResponse
from oic.oauth2 import AccessTokenRequest
from oic.oauth2 import TokenErrorResponse
from oic.oauth2 import NoneResponse
from oic import oauth2

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

#noinspection PyUnusedLocal
def code_response(**kwargs):
    _areq = kwargs["areq"]
    _scode = kwargs["scode"]
    aresp = AuthorizationResponse()
    if _areq.state:
        aresp.state = _areq.state
    aresp.code = _scode
    return aresp

def token_response(**kwargs):
    _areq = kwargs["areq"]
    _scode = kwargs["scode"]
    _sdb = kwargs["sdb"]
    _dic = _sdb.update_to_token(_scode, issue_refresh=False)

    aresp = oauth2.factory(AccessTokenResponse, **_dic)
    if _areq.scope:
        aresp.scope = _areq.scope
    aresp.c_extension = _areq.c_extension
    return aresp

#noinspection PyUnusedLocal
def none_response(**kwargs):
    _areq = kwargs["areq"]
    aresp = NoneResponse()
    if _areq.state:
        aresp.state = _areq.state
    return aresp

def location_url(response_type, redirect_uri, query):
    if response_type in [["code"],["token"],["none"]]:
        return "%s?%s" % (redirect_uri, query)
    else:
        return "%s#%s" % (redirect_uri, query)

class Server(object):
    authorization_request = AuthorizationRequest
    
    def __init__(self, name, sdb, cdb, function, urlmap=None, debug=0):
        self.name = name
        self.sdb = sdb
        self.cdb = cdb

        self.srvmethod = SrvMethod()

        self.function = function

        self.debug = debug
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
    def authn_intro(self, environ, start_response, logger):
        """
        After the authentication this is where you should end up
        """

        _log_info = logger.info
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

        if self.debug:
            _log_info("session[\"authzreq\"] = %s" % session["authzreq"])
        #_log_info( "type: %s" % type(session["authzreq"]))

        # pick up the original request
        areq = self.authorization_request.set_json(session["authzreq"],
                                                   extended=True)

        if self.debug:
            _log_info("areq: %s" % areq)

        # Do the authorization
        try:
            permission = self.function["authorize"](user, session)
            _sdb.update(sid, "permission", permission)
        except Exception:
            raise

        _log_info("response type: %s" % areq.response_type)

        return areq, session

    def authn_reply(self, areq, aresp, environ, start_response, logger):
        _log_info = logger.info

        if areq.redirect_uri:
            # TODO verify that the uri is reasonable
            redirect_uri = areq.redirect_uri
        else:
            redirect_uri = self.urlmap[areq.client_id]

        location = location_url(areq.response_type, redirect_uri,
                                aresp.get_urlencoded())

        if self.debug:
            _log_info("Redirected to: '%s' (%s)" % (location, type(location)))

        redirect = Redirect(str(location))
        return redirect(environ, start_response)

    def authn_response(self, areq, session):
        scode = session["code"]
        areq.response_type.sort()
        _rtype = " ".join(areq.response_type)
        return self.response_type_map[_rtype](areq=areq, scode=scode,
                                              sdb=self.sdb)

    def authenticated(self, environ, start_response, logger, _):
        _log_info = logger.info

        if self.debug:
            _log_info("- authenticated -")

        try:
            result = self.authn_intro(environ, start_response, logger)
        except Exception, err:
            resp = ServiceError("%s" % err)
            return resp(environ, start_response)

        if isinstance(result, Response):
            return result(environ, start_response)
        else:
            areq, session = result


        try:
            aresp = self.authn_response(areq, session)
        except KeyError: # Don't know what to do raise an exception
            resp = BadRequest("Unknown response type")
            return resp(environ, start_response)

        aresp.c_extension = areq.c_extension

        return self.authn_reply(areq, aresp, environ, start_response, logger)
    
    #noinspection PyUnusedLocal
    def authorization_endpoint(self, environ, start_response, logger, _):
        # The AuthorizationRequest endpoint

        _log_info = logger.info
        _sdb = self.sdb

        if self.debug:
            _log_info("- authorization -")

        if environ.get("REQUEST_METHOD") == "GET":
            query = environ.get("QUERY_STRING")
        elif environ.get("REQUEST_METHOD") == "POST":
            query = get_post(environ)
        else:
            resp = BadRequest("Unsupported method")
            return resp(environ, start_response)
            
        if self.debug:
            _log_info("Query: '%s'" % query)

        try:
            areq = self.srvmethod.parse_authorization_request(query=query,
                                                              extended=True)
        except MissingRequiredAttribute, err:
            resp = BadRequest("%s" % err)
            return resp(environ, start_response)
        except Exception,err:
            resp = BadRequest("%s" % err)
            return resp(environ, start_response)

        if areq.redirect_uri:
            _redirect = areq.redirect_uri
        else:
            # A list, so pick one (==the first)
            _redirect = self.urlmap[areq.client_id][0]

        sid = _sdb.create_authz_session("", areq)
        bsid = base64.b64encode(sid)

        grant = _sdb[sid]["code"]
        if self.debug:
            _log_info("code: '%s'" % grant)

        return self.function["authenticate"](environ, start_response, bsid)

    #noinspection PyUnusedLocal
    def token_endpoint(self, environ, start_response, logger, handle):
        """
        This is where clients come to get their access tokens
        """

        _log_info = logger.info
        _sdb = self.sdb

        if self.debug:
            _log_info("- token -")
        body = get_post(environ)
        if self.debug:
            _log_info("body: %s" % body)

        areq = AccessTokenRequest.set_urlencoded(body, extended=True)

        # Client is from basic auth or ...
        client = environ["REMOTE_USER"]
        if not self.function["verify client"](environ, client, self.cdb):
            err = TokenErrorResponse(error="unathorized_client")
            resp = Response(err.get_json(), content="application/json",
                            status="401 Unauthorized")
            return resp(environ, start_response)

        if self.debug:
            _log_info("AccessTokenRequest: %s" % areq)

        assert areq.grant_type == "authorization_code"

        # assert that the code is valid
        _info = _sdb[areq.code]

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _info:
            assert areq.redirect_uri == _info["redirect_uri"]

        _tinfo = _sdb.update_to_token(areq.code)

        if self.debug:
            _log_info("_tinfo: %s" % _tinfo)
            
        atr = oauth2.factory(AccessTokenResponse, **_tinfo)

        if self.debug:
            _log_info("AccessTokenResponse: %s" % atr)

        resp = Response(atr.get_json(), content="application/json")
        return resp(environ, start_response)

