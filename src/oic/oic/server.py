#!/usr/bin/env python

__author__ = 'rohe0002'

import random
import httplib2
import base64

try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs

from oic.oauth2.server import Server as AServer

from oic.utils.http_util import *
from oic.utils import time_util

from oic.oauth2 import MissingRequiredAttribute
from oic.oauth2 import rndstr

from oic.oic import Server as SrvMethod

from oic.oic import AuthorizationResponse
from oic.oic import AuthorizationRequest
from oic.oic import AccessTokenResponse
from oic.oic import AccessTokenRequest
from oic.oic import TokenErrorResponse
from oic.oic import OpenIDRequest
from oic.oic import IdToken
from oic.oic import RegistrationRequest
from oic.oic import RegistrationResponse

from oic import oauth2

class MissingAttribute(Exception):
    pass

class UnsupportedMethod(Exception):
    pass

#noinspection PyUnusedLocal
def devnull(txt):
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
def do_authorization(user):
    return ""

def get_or_post(environ):
    _method = environ.get("REQUEST_METHOD")
    
    if _method == "GET":
        data = environ.get("QUERY_STRING")
    elif _method == "POST":
        data = get_post(environ)
    else:
        raise UnsupportedMethod(_method)

    return data

def secret(seed, id):
    csum = hmac.new(seed, digestmod=hashlib.sha224)
    csum.update("%s" % time.time())
    csum.update("%f" % random.random())
    csum.update(id)
    return csum.hexdigest()

#noinspection PyUnusedLocal
def code_response(**kwargs):
    _areq = kwargs["areq"]
    _scode = kwargs["scode"]
    aresp = AuthorizationResponse()
    if _areq.state:
        aresp.state = _areq.state
    if _areq.nonce:
        aresp.nonce = _areq.nonce
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
    return aresp

def add_token_info(aresp, sdict):
    for prop in AccessTokenResponse.c_attributes.keys():
        try:
            if sdict[prop]:
                setattr(aresp, prop, sdict[prop])
        except KeyError:
            pass

def code_token_response(**kwargs):
    _areq = kwargs["areq"]
    _scode = kwargs["scode"]
    _sdb = kwargs["sdb"]
    aresp = AuthorizationResponse()
    if _areq.state:
        aresp.state = _areq.state
    if _areq.nonce:
        aresp.nonce = _areq.nonce
    if _areq.scope:
        aresp.scope = _areq.scope

    aresp.code = _scode

    _dic = _sdb.update_to_token(_scode, issue_refresh=False)
    add_token_info(aresp, _dic)

    return aresp

def location_url(response_type, redirect_uri, query):
    if response_type in [["code"],["token"],["none"]]:
        return "%s?%s" % (redirect_uri, query)
    else:
        return "%s#%s" % (redirect_uri, query)

class Server(AServer):
    authorization_request = AuthorizationRequest

    def __init__(self, name, sdb, cdb, function, jwt_key, userdb, urlmap=None,
                 debug=0, cache=None, timeout=None, proxy_info=None,
                 follow_redirects=True, ca_certs="", jwt_keys=None):

        AServer.__init__(self, name, sdb, cdb, function, urlmap, debug)

        self.srvmethod = SrvMethod(jwt_keys)

        self.jwt_key = jwt_key
        self.userdb = userdb

        self.function = function

        self.response_type_map.update({
            "code": code_response,
            "token": token_response,
        })

        if not ca_certs:
            self.http = httplib2.Http(cache, timeout, proxy_info,
                                      disable_ssl_certificate_validation=True)
        else:
            self.http = httplib2.Http(cache, timeout, proxy_info,
                                      ca_certs=ca_certs)

        self.http.follow_redirects = follow_redirects

    def _id_token(self, session, loa=2):
        idt = IdToken(iss=self.name,
                       user_id=session["user_id"],
                       aud = session["client_id"],
                       exp = time_util.in_a_while(days=1),
                       iso29115=loa,
                       )
        if "nonce" in session:
            idt.nonce = session["nonce"]

        return idt.get_jwt(key=self.jwt_key)

    #noinspection PyUnusedLocal

    def authn_response(self, areq, session):
        areq.response_type.sort()
        _rtype = " ".join(areq.response_type)

        scode = session["code"]

        args = {"areq":areq, "scode":scode, "sdb":self.sdb}
        if "id_token" in areq.response_type:
            args["id_token"] = self._id_token(session)

        return self.response_type_map[_rtype](**args)

    #noinspection PyUnusedLocal
    def authorization_endpoint(self, environ, start_response, logger, _):
        # The AuthorizationRequest endpoint

        _log_info = logger.info
        _sdb = self.sdb

        if self.debug:
            _log_info("- authorization -")

        # Support GET and POST
        try:
            query = get_or_post(environ)
        except UnsupportedMethod:
            resp = BadRequest("Unsupported method")
            return resp(environ, start_response)

        if self.debug:
            _log_info("Query: '%s'" % query)

        # Same serialization used for GET and POST
        try:
            areq = self.srvmethod.parse_authorization_request(query=query, 
                                                              extended=True)
        except MissingRequiredAttribute, err:
            resp = BadRequest("%s" % err)
            return resp(environ, start_response)
        except Exception,err:
            resp = BadRequest("%s" % err)
            return resp(environ, start_response)

        # This is where to send the use afterwards
        if areq.redirect_uri:
            _redirect = areq.redirect_uri
        else:
            # A list, so pick one (==the first)
            _redirect = self.urlmap[areq.client_id][0]

        # Is there an request decode it
        openid_req = None
        if "request" in areq or "request_uri" in areq:
            try:
                # Should actually do a get on the URL
                #jwt_key = self.cdb[areq.client_id]["jwk_url"]
                jwt_key = self.cdb[areq.client_id]["jwk_key"]
            except KeyError: # TODO
                jwt_key = ()
        
            if areq.request:
                openid_req = OpenIDRequest.set_jwt(areq.request, jwt_key)
            elif areq.request_uri:
                # Do a HTTP get
                _req = self.http.request(areq.request_uri)
                if not _req:
                    resp = BadRequest("Couldn't get at the OpenID request")
                    return resp(environ, start_response)
                openid_req = OpenIDRequest.set_jwt(_req, jwt_key)

        # Store session info
        sid = _sdb.create_authz_session("", areq, oidreq=openid_req)
        bsid = base64.b64encode(sid)
        _log_info("SID:%s" % bsid)

        # start the authentication process
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

        if self.debug:
            _log_info("environ: %s" % environ)

        if not self.function["verify client"](environ, areq, self.cdb):
            _log_info("could not verify client")
            err = TokenErrorResponse(error="unathorized_client")
            resp = Unauthorized(err.get_json(), content="application/json")
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

        if self.debug:
            _log_info("All checks OK")

        try:
            _tinfo = _sdb.update_to_token(areq.code)
        except Exception,err:
            _log_info("Error: %s" % err)
            raise

        if self.debug:
            _log_info("_tinfo: %s" % _tinfo)

        atr = oauth2.factory(AccessTokenResponse, **_tinfo)

        if self.debug:
            _log_info("AccessTokenResponse: %s" % atr)

        resp = Response(atr.to_json(), content="application/json")
        return resp(environ, start_response)

    #noinspection PyUnusedLocal
    def userinfo_endpoint(self, environ, start_response, logger):

        # POST or GET
        try:
            query = get_or_post(environ)
        except UnsupportedMethod:
            resp = BadRequest("Unsupported method")
            return resp(environ, start_response)

        uireq = self.srvmethod.parse_user_info_request(data=query)
        logger.info("user_info_request: %s" % uireq)

        # should be an access token
        typ, key, _ = self.sdb.get_type_and_key(uireq.access_token)
        logger.info("access_token type: '%s', key: '%s'" % (typ, key))
        
        assert typ == "T"
        session = self.sdb[uireq.access_token]
        _req = session["oidreq"]

        oidreq = OpenIDRequest.from_json(_req)

        #logger.info("oidreq: %s[%s]" % (oidreq, type(oidreq)))
        info = self.function["user info"](self.userdb,
                                          session["user_id"],
                                          session["client_id"],
                                          oidreq.user_info)

        logger.info("info: %s" % (info,))
        resp = Response(info.get_json(), content="application/json")
        return resp(environ, start_response)

    #noinspection PyUnusedLocal
    def check_session_endpoint(self, environ, start_response, logger):

        try:
            info = get_or_post(environ)
        except UnsupportedMethod:
            resp = BadRequest("Unsupported method")
            return resp(environ, start_response)

        idt = self.srvmethod.parse_check_session_request(query=info)

        resp = Response(idt.get_json(), content="application/json")
        return resp(environ, start_response)

    #noinspection PyUnusedLocal
    def registration_endpoint(self, environ, start_response, logger):

        try:
            query = get_or_post(environ)
        except UnsupportedMethod:
            resp = BadRequest("Unsupported method")
            return resp(environ, start_response)

        request = RegistrationRequest.from_urlencoded(query)

        if request.type == "client_associate":
            # create new id och secret
            client_id = rndstr(12)
            while client_id in self.cdb:
                client_id = rndstr(12)

            client_secret = secret(self.seed, client_id)
            self.cdb[client_id] = {
                "client_secret":client_secret
            }
            _cinfo = self.cdb[client_id]

            for key,val in request.dictionary().items():
                _cinfo[key] = val

            if "jwk_url" not in _cinfo:
                _cinfo["jwk_url"] = None
                
        elif request.type == "client_update":
            # verify that these are an id,secret pair I know about
            try:
                _cinfo = self.cdb[request.client_id]
            except KeyError:
                logger.info("Unknown client id")
                resp = BadRequest()
                return resp(environ, start_response)

            if _cinfo["client_secret"] != request.client_secret:
                logger.info("Wrong secret")
                resp = BadRequest()
                return resp(environ, start_response)

            # update secret
            client_secret = secret(self.seed, request.client_id)
            _cinfo["client_secret"] = client_secret
            client_id = request.client_id
        else:
            resp = BadRequest("Unknown request type: %s" % request.type)
            return resp(environ, start_response)

        # set expiration time
        _cinfo["registration_expires"] = time_util.time_sans_frac()+3600
        response = RegistrationResponse(client_id, client_secret,
                                        expires_in=3600)

        resp = Response(response.to_json(), content="application/json",
                        headers=[("Cache-Control", "no-store")])
        return resp(environ, start_response)

# -----------------------------------------------------------------------------

#class UserInfo():
#    """The generic user info interface. It's a read only interface"""
#    def __init__(self, rules, db):
#        """
#        :param rules: The servers view on what a what a specific client
#            should receive
#        :param db: UserInformation interface
#        """
#        self.rules = rules
#        self.db = db
#
#    def pick(self, userid, client_id, claims=None, locale=""):
#        """
#        One implementation
#
#        :param userid: The User ID
#        :param client_id: The ID of the client
#        :param claims: The claims the client has defined
#        :param locale: Which locale the client wants
#        :return: A dictionary
#        """
#        try:
#            info = self.db[userid]
#        except KeyError:
#            return None
#
#        # attribute names are of the form name '#' locale
#
#        # first my own rules on what to return
#        try:
#            attrs = self.rules[client_id]
#
#            for key, val in info.items():
#                if key in attrs:
#                    continue
#
#                try:
#                    prop, ploc = key.split("#")
#                    if prop in attrs:
#                        continue
#                except ValueError:
#                    pass
#
#                del info[key]
#
#        except KeyError:
#            pass
#
#        # Don't send back more than is needed
#        if claims:
#            if isinstance(claims, Claims):
#                cdic = claims.dictionary(extended=True)
#            else:
#                cdic = claims
#            attrs = cdic.keys()
#
#            for key, val in info.items():
#                if key in attrs:
#                    continue
#
#                try:
#                    prop, ploc = key.split("#")
#                    if locale:
#                        if ploc != locale:
#                            del info[key]
#                        continue
#                    elif prop in attrs:
#                        continue
#                except ValueError:
#                    del info[key]
#
#
#            for attr in [key for key, val in cdic.items() if not val]:
#                if attr not in info.keys():
#                    raise MissingAttribute(attr)
#        return info
#
#
#class JSON_UserInfo(UserInfo):
#    def __init__(self, rules, json_file):
#        UserInfo.__init__(self,
#                          json.loads(open(rules).read()),
#                          json.loads(open(json_file).read()))
