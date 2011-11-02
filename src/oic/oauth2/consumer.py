#!/usr/bin/env python

__author__ = 'rohe0002'

import random
import string
import time

from hashlib import md5

from oic.utils import http_util
from oic.oauth2 import AuthorizationRequest
from oic.oauth2 import Client
from oic.oauth2 import ErrorResponse

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
    Returns a string of random characters

    :param size: The length of the string
    :return: string
    """
    return "".join([random.choice(string.ascii_letters) for _ in range(size)])

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

class UnknownState(Exception):
    pass

class TokenError(Exception):
    pass

class AuthzError(Exception):
    pass

class Consumer(Client):
    """ An OAuth2 consumer implementation

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

        self.sdb = session_db
        self.seed = ""

    def restore(self, sid):
        """ Restores the instance variables from something stored in the
        session database.

        :param sid: Session identifier
        """
        for key, val in self.sdb[sid].items():
            setattr(self, key, val)

    def _backup(self, sid):
        """ Stores instance variable values in the session store under a
        session identifier.

        :param sid: Session identifier
        """
        self.sdb[sid] = {
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
            "seed": self.seed,
            "debug": self.debug,
        }

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

        areq = self.get_authorization_request(AuthorizationRequest,
                            state=sid,
                            response_type=self.config["response_type"],
                            scope=self.config["scope"])

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

        _query = environ.get("QUERY_STRING")
        _path = http_util.geturl(environ, False, False)

        if self.config["flow_type"] == "code":
            # Might be an error response
            aresp = self.parse_authorization_response(query=_query)
            if isinstance(aresp, ErrorResponse):
                raise AuthzError(aresp.error)

            try:
                self.restore(aresp.state)
            except KeyError:
                raise UnknownState(aresp.state)
            
            self.set_from_authorization_response(aresp)
            self._backup(aresp.state)
            return aresp
        else:
            atr = self.parse_access_token_response(info=_query,
                                                   format="urlencoded",
                                                   extended=True)
            if isinstance(atr, ErrorResponse):
                raise TokenError(atr.error)

            return atr

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


