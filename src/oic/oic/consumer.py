#!/usr/bin/env python

__author__ = 'rohe0002'

import random
import string
import time
import os.path

from hashlib import md5

from oic.utils import http_util
from oic.oic import AuthorizationRequest
from oic.oic import AccessTokenResponse
from oic.oic import Client
from oic.oauth2 import ErrorResponse
from oic.oauth2.consumer import TokenError
from oic.oauth2.consumer import AuthzError
#from oic.oauth2.consumer import UnknownState

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

def rndstr(size=16):
    """
    Returns a string of random ascii characters or digits

    :param size: The length of the string
    :return: string
    """
    _basech = string.ascii_letters + string.digits
    return "".join([random.choice(_basech) for _ in range(size)])

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

class Consumer(Client):
    """ An OpenID Connect consumer implementation

    """
    #noinspection PyUnusedLocal
    def __init__(self, session_db, config, client_config=None,
                 server_info=None):
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
            self.debug = config["debug"]

        if server_info:
            self.authorization_endpoint = server_info["authorization_endpoint"]
            self.token_endpoint = server_info["token_endpoint"]
            self.user_info_endpoint = server_info["user_info_endpoint"]

        self.sdb = session_db
        self.function = self.config["function"]
        self.seed = ""
        self.nonce = ""
        self.request_filename=""
        self.user_info = None

    def update(self, sid):
        """ Updates the instance variables from something stored in the
        session database. Will not overwrite something that's already there.

        :param sid: Session identifier
        """
        for key, val in self.sdb[sid].items():
            if self.key:
                pass
            else:
                setattr(self, key, val)

    def restore(self, sid):
        """ Restores the instance variables from something stored in the
        session database.

        :param sid: Session identifier
        """
        for key, val in self.sdb[sid].items():
            setattr(self, key, val)

    def dictionary(self):
        return {
            "client_id": self.client_id,
            "state": self.state,
            "authorization_code": self.authorization_code,
            "grant_expiration_time": self.grant_expiration_time,
            "scope": self.scope,
            "access_token": self.access_token,
            "token_expiration_time": self.token_expiration_time,
            "redirect_uri": self.redirect_uri,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "token_revocation_endpoint": self.token_revocation_endpoint,
            "user_info_endpoint": self.user_info_endpoint,
            "seed": self.seed,
            "debug": self.debug,
            "nonce": self.nonce,
            "request_filename": self.request_filename,
            "user_info": self.user_info,
            "id_token": self.id_token
        }

    def _backup(self, sid):
        """ Stores instance variable values in the session store under a
        session identifier.

        :param sid: Session identifier
        """
        self.sdb[sid] = self.dictionary()

    def extract_access_token_response(self, aresp):
        atr = AccessTokenResponse()
        for prop in AccessTokenResponse.c_attributes.keys():
            setattr(atr, prop, getattr(aresp, prop))
        return atr
    
    #noinspection PyUnusedLocal,PyArgumentEqualDefault
    def begin(self, environ, start_response, logger):
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
        self.redirect_uri = _path + self.config["authz_page"]

        # Put myself in the dictionary of sessions, keyed on session-id
        if not self.seed:
            self.seed = rndstr()

        sid = stateID(_path, self.seed)
        self._backup(sid)
        self.sdb["seed:%s" % self.seed] = sid

        # Store the request and the redirect uri used
        self._request = http_util.geturl(environ)
        self.nonce = rndstr(12)

        areq = self.get_authorization_request(AuthorizationRequest,
                            state=sid,
                            client_id=self.client_id,
                            redirect_uri=self.redirect_uri,
                            response_type=self.config["response_type"],
                            scope=self.config["scope"],
                            nonce=self.nonce)

        id_request = self.function["openid_request"](areq, self.config["key"])
        if self.config["request_method"] == "parameter":
            areq.request = id_request
        elif self.config["request_method"] == "simple":
            pass
        else: # has to be 'file' at least that's my assumption.
            # write to file in the tmp directory remember the name
            filename = os.path.join(self.config["temp_dir"], rndstr(10))
            while os.path.exists(filename):
                filename = os.path.join(self.config["temp_dir"], rndstr(10))
            fid = open(filename)
            fid.write(id_request)
            fid.close()
            self.request_filename = "/"+filename
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
            _log_info("- %s flow -" % self.config["flow_type"])
            _log_info("environ: %s" % environ)

        if environ.get("REQUEST_METHOD") == "GET":
            _query = environ.get("QUERY_STRING")
        elif environ.get("REQUEST_METHOD") == "POST":
            _query = http_util.get_post(environ)
        else:
            resp = http_util.BadRequest("Unsupported method")
            return resp(environ, start_response)

        _log_info("response: %s" % _query)
        
        _path = http_util.geturl(environ, False, False)

        if "code" in self.config["response_type"]:
            # Might be an error response
            aresp = self.parse_authorization_response(query=_query)
            if isinstance(aresp, ErrorResponse):
                raise AuthzError(aresp.error)

            _log_info("before: %s" % (self.dictionary(),))

#            try:
#                self.update(self.state)
#            except KeyError:
#                raise UnknownState(self.state)
#
#            _log_info("after: %s" % (self.dictionary(),))

            self._backup(self.state)
            
            # May have token and id_token information too
            if aresp.access_token:
                atr = self.extract_access_token_response(aresp)
                self.access_token = atr
            else:
                atr = None

            idt = None
            return aresp, atr, idt
        else:
            atr = self.parse_access_token_response(info=_query,
                                                   format="urlencoded",
                                                   extended=True)
            if isinstance(atr, ErrorResponse):
                raise TokenError(atr.error)

            idt = None
            return None, atr, idt

    def complete(self, logger):
        """
        Do the access token request, the last step in a code flow.
        If Implicit flow was used then this method is never used.
        """
        if self.config["password"]:
            logger.info("basic auth")
            atr = self.do_access_token_request(code=self.authorization_code,
                                    grant_type="authorization_code",
                                    client_password=self.config["password"])
        elif self.config["client_secret"]:
            logger.info("request_body auth")
            atr = self.do_access_token_request(code=self.authorization_code,
                                    grant_type="authorization_code",
                                    auth_method="request_body",
                                    client_secret=self.config["client_secret"])
        else:
            raise Exception("Nothing to authenticate with")

        if isinstance(atr, ErrorResponse):
            raise TokenError(atr.error)

        #self._backup(self.sdb["seed:%s" % _cli.seed])
        self._backup(self.state)

        return atr

    def refresh_token(self):
        pass
    
    #noinspection PyUnusedLocal
    def userinfo(self, logger):
        self.log = logger
        uinfo = self.do_user_info_request()

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
    