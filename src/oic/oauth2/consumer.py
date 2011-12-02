#!/usr/bin/env python

__author__ = 'rohe0002'

import random
import string
import time

from hashlib import md5

from oic.utils import http_util
from oic.oauth2 import AuthorizationRequest
from oic.oauth2 import AuthorizationResponse
from oic.oauth2 import AccessTokenResponse
from oic.oauth2 import Client
from oic.oauth2 import ErrorResponse
from oic.oauth2 import Grant

ENDPOINTS = ["authorization_endpoint", "token_endpoint", "user_info_endpoint",
    "check_id_endpoint", "registration_endpoint", "token_revokation_endpoint"]

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

def factory(kaka, sdb, client_id, **kwargs):
    """
    Return the right Consumer instance dependent on what's in the cookie

    :param kaka: The cookie
    :param sdb: The session database
    :param kwargs: The Consumer configuration arguments
    :return: Consumer instance or None
    """
    part = http_util.cookie_parts(client_id, kaka)
    if part is None:
        return None
    
    cons = Consumer(sdb, **kwargs)
    cons.restore(part[0])
    http_util.parse_cookie(client_id, cons.seed, kaka)
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
    def __init__(self, session_db, client_config=None,
                 server_info=None, authz_page="", response_type="",
                 scope="", flow_type="", debug=False, password=None):
        """ Initializes a Consumer instance.

        :param session_db: Where info are kept about sessions acts like a
            dictionary
        :param client_config: Client configuration
        :param server_info: Information about the server
        :param authz_page:
        :param response_type:
        :param scope:
        :param flow_type:
        :param debug:
        """
        if client_config is None:
            client_config = {}
            
        Client.__init__(self, **client_config)

        self.authz_page = authz_page
        self.response_type = response_type
        self.scope = scope
        self.flow_type = flow_type
        self.debug = debug
        self.password = password

        if server_info:
            for endpoint in ENDPOINTS:
                try:
                    setattr(self, endpoint, server_info[endpoint])
                except KeyError:
                    setattr(self, endpoint, None)
        else:
            for endpoint in ENDPOINTS:
                setattr(self, endpoint, None)

        self.sdb = session_db
        self.seed = rndstr()

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
                _tmp = {}
                for state, info in _val.items():
                    try:
                        info.join(val[state])
                    except KeyError:
                        pass

                    _tmp[state] = info
                setattr(self, key, _tmp)

        return self

    def restore(self, sid):
        """ Restores the instance variables from something stored in the
        session database.

        :param sid: Session identifier
        """
        for key, val in self.sdb[sid].items():
            setattr(self, key, val)

    def _backup(self, sid):
        """ Stores dynamic instance variable values in the session store
        under a session identifier.

        :param sid: Session identifier
        """

        res = {
            "state": self.state,
            "grant": self.grant,
            "seed": self.seed,
        }

        for endpoint in ENDPOINTS:
            res[endpoint] = getattr(self, endpoint, None)

        self.sdb[sid] = res

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

        # Store the request and the redirect uri used
        _path = http_util.geturl(environ, False, False)
        self.redirect_uri = "%s%s" % (_path, self.authz_page)
        self._request = http_util.geturl(environ)

        # Put myself in the dictionary of sessions, keyed on session-id
        if not self.seed:
            self.seed = rndstr()

        sid = stateID(_path, self.seed)
        self.state = sid
        self.grant[sid] = Grant(seed=self.seed)
        self._backup(sid)
        self.sdb["seed:%s" % self.seed] = sid

        location = self.request_info(AuthorizationRequest, method="GET",
                                       scope=self.scope,
                                       request_args={"state": sid})[0]


        if self.debug:
            _log_info("Redirecting to: %s" % (location,))

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
            _log_info("- %s flow -" % self.flow_type)

        _query = environ.get("QUERY_STRING")
        if self.debug:
            _log_info("QUERY: %s" % _query)
        _path = http_util.geturl(environ, False, False)

        if "code" in self.response_type:
            # Might be an error response
            try:
                aresp = self.parse_response(AuthorizationResponse,
                                            info=_query, format="urlencoded")
            except Exception, err:
                logger.error("%s" % err)
                raise
            
            if isinstance(aresp, ErrorResponse):
                raise AuthzError(aresp.error)

            try:
                self.update(aresp.state)
            except KeyError:
                raise UnknownState(aresp.state)
            
            self._backup(aresp.state)
            return aresp
        else: # implicit flow
            atr = self.parse_response(AccessTokenResponse, info=_query,
                                      format="urlencoded", extended=True)
            if isinstance(atr, ErrorResponse):
                raise TokenError(atr.error)

            try:
                self.update(atr.state)
            except KeyError:
                raise UnknownState(atr.state)

            self.seed = self.grant[self.state].seed
            
            return atr

    def complete(self, logger):
        """
        Do the access token request, the last step in a code flow.
        If Implicit flow was used then this method is never used.
        """

        if self.password:
            logger.info("basic auth")
            atr = self.do_access_token_request(state=self.state,
                                    http_args={"password":self.password})
        elif self.client_secret:
            logger.info("request_body auth")
            atr = self.do_access_token_request(state=self.state,
                                    request_args={
                                        "client_secret": self.client_secret})
        else:
            raise Exception("Nothing to authenticate with")
        
        if isinstance(atr, ErrorResponse):
            # Losing information here, not good!
            raise TokenError(atr.error)

        #self._backup(self.sdb["seed:%s" % _cli.seed])
        self._backup(self.state)
        
        return atr
