#!/usr/bin/env python

__author__ = 'rohe0002'

import time
import os.path
import urlparse
import httplib2

from hashlib import md5

from oic.utils import http_util
#from oic.utils.time_util import time_sans_frac

from oic.oic import Client
from oic.oic import ENDPOINTS
from oic.oic.message import AuthorizationRequest
from oic.oic.message import IDTokenClaim
from oic.oic.message import UserInfoClaim
from oic.oic.message import Claims
from oic.oic.message import OpenIDRequest
from oic.oic.message import AuthorizationResponse
from oic.oic.message import AccessTokenResponse
#from oic.oic.message import ProviderConfigurationResponse
from oic.oic.message import RegistrationRequest
from oic.oic.message import RegistrationResponse
from oic.oic.message import IssuerRequest
from oic.oic.message import IssuerResponse

from oic.oauth2.message import ErrorResponse
from oic.oauth2 import Grant
from oic.oauth2 import DEF_SIGN_ALG
from oic.oauth2 import rndstr

from oic.oauth2.consumer import TokenError
from oic.oauth2.consumer import AuthzError
from oic.oauth2.consumer import UnknownState

SWD_PATTERN = "http://%s/.well-known/simple-web-discovery"
ISSUER_URL = "http://openid.net/specs/connect/1.0/issuer"

def stateID(url, seed):
    """The hash of the time + server path + a seed makes an unique
    SID for each session.

    :param url: The base URL for this site
    :return: The hex version of the digest
    """
    ident = md5()
    ident.update(repr(time.time()))
    ident.update(url)
    ident.update(seed)
    return ident.hexdigest()

def factory(kaka, sdb, config):
    """
    Return the right Consumer instance dependent on what's in the cookie

    :param kaka: The cookie
    :param sdb: The session database
    :param config: The common Consumer configuration
    :return: Consumer instance or None
    """
    part = http_util.cookie_parts(config["name"], kaka)
    if part is None:
        return None

    cons = Consumer(sdb, config=config)
    cons.restore(part[0])
    http_util.parse_cookie(config["name"], cons.seed, kaka)
    return cons

def construct_openid_request(arq, keys, algorithm=DEF_SIGN_ALG, iss=None,
                             aud=None):
    """
    Construct the specification of what I want returned.
    The request will be signed
    """

    # Should be configurable !!
    claim = Claims(name=None, nickname={"optional": True},
                 email=None, verified=None,
                 picture={"optional": True})

    uic = UserInfoClaim([claim], format="signed", locale="us-en")

    id_token = IDTokenClaim(max_age=86400)
    ava = {}
    for attr in ["response_type", "scope", "prompt"]:
        _tmp = arq[attr]
        if _tmp:
            ava[attr] = " ".join(_tmp)
        else:
            ava[attr] = _tmp

    oir = OpenIDRequest(ava["response_type"], arq.client_id, arq.redirect_uri,
                        ava["scope"], arq.state, user_info=uic,
                        prompt=ava["prompt"], id_token=id_token, iss=iss,
                        aud=aud)

    return oir.get_jwt(key=keys, algorithm=algorithm)

def clean_response(aresp):
    """
    Creates a new instance with only the standard attributes

    :param aresp: The original AccessTokenResponse
    :return: An AccessTokenResponse instance
    """
    atr = AccessTokenResponse()
    for prop in AccessTokenResponse.c_attributes.keys():
        setattr(atr, prop, getattr(aresp, prop))

    return atr



IGNORE = ["request2endpoint", "response2error", "grant_class", "token_class",
          "http"]


class Consumer(Client):
    """ An OpenID Connect consumer implementation

    """
    #noinspection PyUnusedLocal
    def __init__(self, session_db, config, client_config=None,
                 server_info=None, debug=False):
        """ Initializes a Consumer instance.

        :param session_db: Where info are kept about sessions
        :param config: Configuration of the consumer
        :param client_config: Client configuration
        :param server_info: Information about the server
        """
        if client_config is None:
            client_config = {}

        Client.__init__(self, **client_config)

        self.config = config
        if config:
            try:
                self.debug = config["debug"]
            except KeyError:
                self.debug = 0

        if server_info:
            for endpoint in ENDPOINTS:
                try:
                    setattr(self, endpoint, server_info[endpoint])
                except KeyError:
                    setattr(self, endpoint, "")


        self.sdb = session_db
        self.debug = debug
        self.seed = ""
        self.nonce = ""
        self.request_filename=""
        self.user_info = None
        self.registration_expires_in = 0
        self.secret_type = "Bearer"

    def update(self, sid):
        """ Updates the instance variables from something stored in the
        session database. Will not overwrite something that's already there.
        Except for the grant dictionary !!

        :param sid: Session identifier
        """
        for key, val in self.sdb[sid].items():
            _val = getattr(self, key)
            if not _val and val:
                setattr(self, key, val)
            elif key == "grant" and val:
                val.update(_val)
                setattr(self, key, val)

    def restore(self, sid):
        """ Restores the instance variables from something stored in the
        session database.

        :param sid: Session identifier
        """
        for key, val in self.sdb[sid].items():
            setattr(self, key, val)

    def dictionary(self):
        return dict([(k,v) for k, v in self.__dict__.items() if k not in
                                                               IGNORE])

    def _backup(self, sid):
        """ Stores instance variable values in the session store under a
        session identifier.

        :param sid: Session identifier
        """
        self.sdb[sid] = self.dictionary()

    #noinspection PyUnusedLocal,PyArgumentEqualDefault
    def begin(self, environ, start_response, logger, scope="", response_type=""):
        """ Begin the OAuth2 flow

        :param environ: The WSGI environment
        :param start_response: The function to start the response process
        :param logger: A logger instance
        :return: A URL to which the user should be redirected
        """
        _log_info = logger.info

        if self.debug:
            _log_info("- begin -")

        _path = http_util.geturl(environ, False, False)
        self.redirect_uris = [_path + self.config["authz_page"]]

        # Put myself in the dictionary of sessions, keyed on session-id
        if not self.seed:
            self.seed = rndstr()

        if not scope:
            scope = self.config["scope"]
        if not response_type:
            response_type = self.config["response_type"]

        sid = stateID(_path, self.seed)
        self.state = sid
        self.grant[sid] = Grant(seed=self.seed)

        self._backup(sid)
        self.sdb["seed:%s" % self.seed] = sid

        # Store the request and the redirect uri used
        self._request = http_util.geturl(environ)
        self.nonce = rndstr(12)

        args = {
            "client_id": self.client_id,
            "state":sid,
            "response_type":response_type,
            "scope": scope,
            "nonce": self.nonce
        }
        
        areq = self.construct_AuthorizationRequest(AuthorizationRequest,
                                                   request_args=args)

        if "request_method" in self.config:
            _keys = self.keystore.get_sign_key()
            id_request = construct_openid_request(areq, _keys)
            if self.config["request_method"] == "parameter":
                areq.request = id_request
            elif self.config["request_method"] == "simple":
                pass
            else: # has to be 'file' at least that's my assumption.
                # write to file in the tmp directory remember the name
                _filedir = self.config["temp_dir"]
                _webpath = self.config["temp_path"]
                _name = rndstr(10)
                filename = os.path.join(_filedir, _name)
                while os.path.exists(filename):
                    _name = rndstr(10)
                    filename = os.path.join(_filedir, _name)
                fid = open(filename, mode="w")
                fid.write(id_request)
                fid.close()
                _webname = "%s%s%s" % (_path,_webpath,_name)
                areq.request_uri = _webname
                self.request_uri = _webname
                self._backup(sid)

        location = "%s?%s" % (self.authorization_endpoint,
                              areq.get_urlencoded())

        if self.debug:
            _log_info("Redirecting to: %s" % location)

        return location

    #noinspection PyUnusedLocal
    def parse_authz(self, environ, start_response, logger):
        """
        This is where we get redirect back to after authorization at the
        authorization server has happened.

        :param environ: The WSGI environment
        :param start_response: The function to start the response process
        :param logger: A logger instance
        :return: A AccessTokenResponse instance
        """

        _log_info = logger.info
        if self.debug:
            _log_info("- authorization -")
            _log_info("environ: %s" % environ)

        if environ.get("REQUEST_METHOD") == "GET":
            _query = environ.get("QUERY_STRING")
#        elif environ.get("REQUEST_METHOD") == "POST":
#            _query = http_util.get_post(environ)
        else:
            resp = http_util.BadRequest("Unsupported method")
            return resp(environ, start_response)

        _log_info("response: %s" % _query)
        
        _path = http_util.geturl(environ, False, False)

        if "code" in self.config["response_type"]:
            # Might be an error response
            _log_info("Expect Authorization Response")
            aresp = self.parse_response(AuthorizationResponse, info=_query,
                                        format="urlencoded")
            if isinstance(aresp, ErrorResponse):
                _log_info("ErrorResponse: %s" % aresp)
                raise AuthzError(aresp.error)

            _log_info("Aresp: %s" % aresp)

            try:
                self.update(aresp.state)
            except KeyError:
                raise UnknownState(aresp.state)

            self.redirect_uris = [self.sdb[aresp.state]["redirect_uris"]]

            # May have token and id_token information too
            if aresp.access_token:
                atr = clean_response(aresp)
                self.access_token = atr
                # update the grant object
                self.get_grant(state=aresp.state).add_token(atr)
            else:
                atr = None

            self._backup(aresp.state)

            idt = None
            return aresp, atr, idt
        else: # implicit flow
            _log_info("Expect Access Token Response")
            atr = self.parse_response(AccessTokenResponse, info=_query,
                                      format="urlencoded", extended=True)
            if isinstance(atr, ErrorResponse):
                raise TokenError(atr.error)

            idt = None
            return None, atr, idt

    def complete(self, logger):
        """
        Do the access token request, the last step in a code flow.
        If Implicit flow was used then this method is never used.
        """
        args = {"redirect_uri": self.redirect_uris[0]}
        if "password" in self.config and self.config["password"]:
            logger.info("basic auth")
            http_args = {"password":self.config["password"]}
        elif self.client_secret:
            logger.info("request_body auth")
            http_args = {}
            args.update({"client_secret":self.client_secret,
                         "client_id": self.client_id,
                         "secret_type": self.secret_type})
        else:
            raise Exception("Nothing to authenticate with")

        resp = self.do_access_token_request(state=self.state,
                                            request_args=args,
                                            http_args=http_args)

        logger.info("Access Token Response: %s" % resp)

        if isinstance(resp, ErrorResponse):
            raise TokenError(resp.error)

        #self._backup(self.sdb["seed:%s" % _cli.seed])
        self._backup(self.state)

        return resp

    def refresh_token(self):
        pass
    
    #noinspection PyUnusedLocal
    def userinfo(self, logger):
        self.log = logger
        uinfo = self.do_user_info_request(state=self.state)

        if isinstance(uinfo, ErrorResponse):
            raise TokenError(uinfo.error)

        self.user_info = uinfo
        self._backup(self.state)

        return uinfo

    def refresh_session(self):
        pass

    def check_session(self):
        pass

    def end_session(self):
        pass

    def discovery_query(self, uri, principal):
        try:
            (response, content) = self.http.request(uri)
        except httplib2.ServerNotFoundError:
            if uri.startswith("http://"): # switch to https
                location = "https://%s" % uri[7:]
                return self.discovery_query(location, principal)
            else:
                raise

        if response.status == 200:
            result = IssuerResponse.from_json(content)
            if result.SWD_service_redirect:
                _loc = result.SWD_service_redirect.location
                _uri = IssuerRequest(ISSUER_URL, principal).request(_loc)
                return self.discovery_query(_uri, principal)
            else:
                return result
        else:
            raise Exception(response.status)

    def get_domain(self, principal, idtype="mail"):
        if idtype == "mail":
            (local, domain) = principal.split("@")
        elif idtype == "url":
            domain, user = urlparse.urlparse(principal)[1:2]
        else:
            domain = ""

        return domain
    
    def discover(self, principal, idtype="mail"):
        _loc = SWD_PATTERN % self.get_domain(principal, idtype)
        uri = IssuerRequest(ISSUER_URL, principal).request(_loc)

        result = self.discovery_query(uri, principal)
        return result.locations[0]

    def register(self, server, type="client_associate", **kwargs):
        req = RegistrationRequest(type=type)

        if type == "client_update":
            req.client_id = self.client_id
            req.client_secret = self.client_secret

        for prop in RegistrationRequest.c_attributes.keys():
            if prop in ["type", "client_id", "client_secret"]:
                continue

            try:
                val = getattr(self, prop)
                if val:
                    setattr(req, prop, val)
            except Exception:
                val = None

            if not val:
                if prop in kwargs:
                    setattr(req, prop, kwargs[prop])

        headers = {"content-type": "application/x-www-form-urlencoded"}
        (response, content) = self.http.request(server, "POST",
                                                req.to_urlencoded(),
                                                headers=headers)

        if response.status == 200:
            resp = RegistrationResponse.from_json(content)
            self.client_secret = resp.client_secret
            self.client_id = resp.client_id
            self.registration_expires = resp.expires_at
        else:
            err = ErrorResponse.from_json(content)
            raise Exception("Registration failed: %s" % err.get_json())

        return resp