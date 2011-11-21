#!/usr/bin/env python

__author__ = 'rohe0002'

import random
import string
import httplib2
import base64
import json

try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs

from oic import oic

from oic.utils.http_util import *
from oic.utils import time_util

from oic.oauth2 import MissingRequiredAttribute
from oic.oic import CLAIMS
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

class AuthnFailure(Exception):
    pass

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

def rndstr(size=16):
    return "".join([random.choice(string.ascii_letters) for _ in range(size)])

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

class Server(oic.Server):
    def __init__(self, name, sdb, cdb, function, jwt_key, userdb, urlmap=None,
                 debug=0,
                 cache=None, timeout=None,
                 proxy_info=None, follow_redirects=True,
                 disable_ssl_certificate_validation=False):
        self.name = name
        self.sdb = sdb
        self.cdb = cdb
        self.jwt_key = jwt_key
        self.userdb = userdb

        self.function = function

        self.debug = debug
        self.seed = rndstr()
        if urlmap is None:
            self.urlmap = {}
        else:
            self.urlmap = urlmap

        self.http = httplib2.Http(cache, timeout, proxy_info,
            disable_ssl_certificate_validation=disable_ssl_certificate_validation)
        self.http.follow_redirects = follow_redirects

    def _id_token(self, session, loa=2):
        idt = IdToken(iss=self.name,
                       user_id=session.user_id,
                       aud = session.client_id,
                       exp = time_util.in_a_while(days=1),
                       iso29115=loa,
                       )
        if session.nonce:
            idt.none = session.nonce

        return idt.get_jwt(key=self.jwt_key)

    #noinspection PyUnusedLocal
    def add_token_info(self, aresp, sdict):
        for prop in AccessTokenResponse.c_attributes.keys():
            try:
                if sdict[prop]:
                    setattr(aresp, prop, sdict[prop])
            except KeyError:
                pass
    
    #noinspection PyUnusedLocal
    def authenticated(self, environ, start_response, logger, _):
        """
        After the authentication this is where you should end up
        """

        _log_info = logger.info
        _sdb = self.sdb

        # parse the form
        dic = parse_qs(get_post(environ))

        try:
            user = dic["login"][0]
            verified = self.function["verify user"](user, dic["password"][0])
            if not verified:
                resp = Unauthorized("Wrong password")
                return resp(environ, start_response)
        except AuthnFailure, err:
            resp = Unauthorized("%s" % (err,))
            return resp(environ, start_response)

        if self.debug:
            _log_info("- authenticated -")

        try:
            # Use the session identifier to find the session information
            sid = base64.b64decode(dic["sid"][0])
            session = _sdb[sid]
        except KeyError:
            resp = BadRequest("")
            return resp(environ, start_response)

        # store the user id among the session info
        _sdb.update(sid, "user_id", dic["login"][0])

#        if self.debug:
#            _log_info("session[\"authzreq\"] = %s" % session["authzreq"])
        #_log_info( "type: %s" % type(session["authzreq"]))

        # pick up the original request
        areq = AuthorizationRequest.set_json(session["authzreq"],
                                             extended=True)

        if self.debug:
            _log_info("areq: %s" % areq)
            _log_info("session: %s" % (session,))

        # Do the authorization
        try:
            scope, permission = self.function["authorize"](user, session)
            _sdb.update(sid, "permission", permission)
            _sdb.update(sid, "scope", scope)
        except Exception:
            raise

        _log_info("response type: %s" % areq.response_type)


        # create the response
        # not either/or code and token but rather any of these combination
        # code,
        # token,
        # 'code token',
        # 'code id_token',
        # 'code token id_token'
        # 'token id_token',

        # so collect the parts
        aresp = AuthorizationResponse()
        if areq.state:
            aresp.state = areq.state
        if areq.scope:
            aresp.scope = areq.scope
        if areq.nonce:
            aresp.nonce = areq.nonce

        aresp.c_extension = areq.c_extension

        code_and_or_token = 0
        token_or_id_token = 0
        scode = session["code"]
        if "code" in areq.response_type:
            code_and_or_token += 1
            aresp.code = scode
        if "token" in areq.response_type:
            code_and_or_token += 1
            token_or_id_token = 1
            _dic = _sdb.update_to_token(scode, issue_refresh=False)
            self.add_token_info(aresp, _dic)

        if "id_token" in areq.response_type:
            if len(areq.response_type) == 1 or not code_and_or_token:
                # MUST be combined with code or token
                resp = BadRequest("unsupported response type combination")
                return resp(environ, start_response)
            token_or_id_token += 1
            aresp.id_token = self._id_token(session)
        else:
            id_token = None


        if "none" in areq.response_type:
            # return only state
            if len(areq.response_type) != 1:
                # not to be combined with anything else
                resp = BadRequest("unsupported response type combination")
                return resp(environ, start_response)


        if areq.redirect_uri:
            # TODO verify that the uri is reasonable
            redirect_uri = areq.redirect_uri
        else:
            redirect_uri = self.urlmap[areq.client_id]

        if self.debug:
            _log_info("response_type: %s" % (areq.response_type,))
            _log_info("token_or_id_token: %d" % token_or_id_token)
            _log_info("code_and_or_token: %d" % code_and_or_token)

        if token_or_id_token:
            location = "%s#%s" % (redirect_uri, aresp.get_urlencoded())
        else:
            location = "%s?%s" % (redirect_uri, aresp.get_urlencoded())

        if self.debug:
            _log_info("Redirected to: '%s'" % (location,))

        redirect = Redirect(str(location))
        return redirect(environ, start_response)

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
            areq = self.parse_authorization_request(query=query,
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
        if not self.cdb[areq.client_id]["jwk_url"]:
            jwt_key = ""
        else: # TODO
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
        else:
            openid_req = None

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
            resp = Unauthorized(err.get_json(), content="application/json",
                                headers=[("WWW-Authenticate",
                                          'Basic realm="WallyWorld"')])
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
    def user_info_endpoint(self, environ, start_response, logger):

        # POST or GET
        try:
            query = get_or_post(environ)
        except UnsupportedMethod:
            resp = BadRequest("Unsupported method")
            return resp(environ, start_response)

        uireq = self.parse_user_info_request(query=query)
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
        resp = Response(json.dumps(info), content="application/json")
        return resp(environ, start_response)

    #noinspection PyUnusedLocal
    def check_id_endpoint(self, environ, start_response, logger):

        try:
            query = get_or_post(environ)
        except UnsupportedMethod:
            resp = BadRequest("Unsupported method")
            return resp(environ, start_response)

        resp = Response()
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

class UserInfo():
    """The generic user info interface. It's a read only interface"""
    def __init__(self, rules, db):
        """
        :param rules: The servers view on what a what a specific client
            should receive
        :param db: UserInformation interface
        """
        self.rules = rules
        self.db = db

    def pick(self, userid, client_id, claims=None, locale=""):
        """
        One implementation
        
        :param userid: The User ID
        :param client_id: The ID of the client
        :param claims: The claims the client has defined
        :param locale: Which locale the client wants
        :return: A dictionary
        """
        try:
            info = self.db[userid]
        except KeyError:
            return None

        # attribute names are of the form name '#' locale

        # first my own rules on what to return
        try:
            attrs = self.rules[client_id]

            for key, val in info.items():
                if key in attrs:
                    continue

                try:
                    prop, ploc = key.split("#")
                    if prop in attrs:
                        continue
                except ValueError:
                    pass

                del info[key]

        except KeyError:
            pass

        # Don't send back more than is needed
        if claims:
            if isinstance(claims, CLAIMS):
                cdic = claims.dictionary(extended=True)
            else:
                cdic = claims
            attrs = cdic.keys()

            for key, val in info.items():
                if key in attrs:
                    continue

                try:
                    prop, ploc = key.split("#")
                    if locale:
                        if ploc != locale:
                            del info[key]
                        continue
                    elif prop in attrs:
                        continue
                except ValueError:
                    del info[key]


            for attr in [key for key, val in cdic.items() if not val]:
                if attr not in info.keys():
                    raise MissingAttribute(attr)
        return info


class JSON_UserInfo(UserInfo):
    def __init__(self, rules, json_file):
        UserInfo.__init__(self,
                          json.loads(open(rules).read()),
                          json.loads(open(json_file).read()))
