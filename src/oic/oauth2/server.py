#!/usr/bin/env python

__author__ = 'rohe0002'

import random
import string
import base64

try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs

from oic.utils.http_util import *
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

def rndstr(size=16):
    return "".join([random.choice(string.ascii_letters) for _ in range(size)])

class Server(oauth2.Server):

    def __init__(self, name, sdb, cdb, function, urlmap=None, debug=0):
        self.name = name
        self.sdb = sdb
        self.cdb = cdb
        
        self.function = function

        self.debug = debug
        self.seed = rndstr()
        if urlmap is None:
            self.urlmap = {}
        else:
            self.urlmap = urlmap

    #noinspection PyUnusedLocal
    def authenticated(self, environ, start_response, logger, _):
        """
        After the authentication this is where you should end up
        """

        _log_info = logger.info
        _sdb = self.sdb

        if self.debug:
            _log_info("- authenticated -")

        # parse the form
        dic = parse_qs(get_post(environ))

        try:
            (verified, user) = self.function["verify user"](dic)
            if not verified:
                resp = Unauthorized("Wrong password")
                return resp(environ, start_response)
        except KeyError, err:
            resp = Unauthorized("Missing key: %s" % (err,))
            return resp(environ, start_response)
        except AuthnFailure, err:
            resp = Unauthorized("Authentication failure: %s" % (err,))
            return resp(environ, start_response)

        try:
            # Use the session identifier to find the session information
            sid = base64.b64decode(dic["sid"][0])
            session = _sdb[sid]
        except KeyError:
            resp = BadRequest("Unknown session identifier")
            return resp(environ, start_response)

        _sdb.update(sid, "userid", dic["login"][0])

        if self.debug:
            _log_info("session[\"authzreq\"] = %s" % session["authzreq"])
        #_log_info( "type: %s" % type(session["authzreq"]))

        # pick up the original request
        areq = AuthorizationRequest.set_json(session["authzreq"], extended=True)

        if self.debug:
            _log_info("areq: %s" % areq)

        # Do the authorization
        try:
            permission = self.function["authorize"](user, session)
            _sdb.update(sid, "permission", permission)
        except Exception:
            raise

        _log_info("response type: %s" % areq.response_type)

        scode = session["code"]
        # create the response
        if "code" in areq.response_type:
            aresp = AuthorizationResponse()
            if areq.state:
                aresp.state = areq.state

            if self.debug:
                _log_info("_dic: %s" % _sdb[scode])
            aresp.code = scode
            aresp.c_extension = areq.c_extension
        elif "token" in areq.response_type:
            _dic = _sdb.update_to_token(scode, issue_refresh=False)
            if self.debug:
                _log_info("_dic: %s" % _dic)
            aresp = oauth2.factory(AccessTokenResponse, **_dic)

            if areq.state:
                aresp.state = areq.state
            if areq.scope:
                aresp.scope = areq.scope
            aresp.c_extension = areq.c_extension

        elif "none" in areq.response_type:
            # return only state

            aresp = NoneResponse()
            if areq.state:
                aresp.state = areq.state
        else: # Don't know what to do raise an exception
            resp = BadRequest("Unknown response type")
            return resp(environ, start_response)

        if areq.redirect_uri:
            # TODO verify that the uri is reasonable
            redirect_uri = areq.redirect_uri
        else:
            redirect_uri = self.urlmap[areq.client_id]

        location = "%s?%s" % (redirect_uri, aresp.get_urlencoded())

        if self.debug:
            _log_info("Redirected to: '%s' (%s)" % (location, type(location)))

        redirect = Redirect(str(location))
        return redirect(environ, start_response)

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
            areq = self.parse_authorization_request(query=query,
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

        if not self.function["verify client"](environ, areq, self.cdb):
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

