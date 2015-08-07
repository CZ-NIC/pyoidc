#!/usr/bin/env python
import time
import logging
from hashlib import md5

from oic.exception import PyoidcError
from oic.oauth2.message import AuthorizationRequest, AuthorizationResponse, \
    Message, AccessTokenResponse, AccessTokenRequest
from oic.utils import http_util
from oic.oauth2 import Client
from oic.oauth2 import Grant
from oic.oauth2 import rndstr

__author__ = 'rohe0002'

ENDPOINTS = ["authorization_endpoint", "token_endpoint", "userinfo_endpoint",
             "check_id_endpoint", "registration_endpoint",
             "token_revokation_endpoint"]

logger = logging.getLogger(__name__)
LOG_INFO = logger.info
LOG_DEBUG = logger.debug


def stateID(url, seed):
    """The hash of the time + server path + a seed makes an unique
    SID for each session.

    :param url: The base URL for this site
    :return: The hex version of the digest
    """
    ident = md5()
    ident.update(repr(time.time()).encode())
    ident.update(url.encode())
    ident.update(seed)
    return ident.hexdigest()


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


class UnknownState(PyoidcError):
    pass


class TokenError(PyoidcError):
    pass


class AuthzError(PyoidcError):
    pass


class ConfigurationError(PyoidcError):
    pass


class MissingAuthenticationInfo(PyoidcError):
    pass


class Consumer(Client):
    """ An OAuth2 consumer implementation

    """
    # noinspection PyUnusedLocal
    def __init__(self, session_db, client_config=None,
                 server_info=None, authz_page="", response_type="",
                 scope="", flow_type="", password=None):
        """ Initializes a Consumer instance.

        :param session_db: Where info are kept about sessions acts like a
            dictionary
        :param client_config: Client configuration
        :param server_info: Information about the server
        :param authz_page:
        :param response_type:
        :param scope:
        :param flow_type:
        """
        if client_config is None:
            client_config = {}

        Client.__init__(self, **client_config)

        self.authz_page = authz_page
        self.response_type = response_type
        self.scope = scope
        self.flow_type = flow_type
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
        self.seed = rndstr().encode("utf-8")
        self._request = None

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
            "grant": self.grant,
            "seed": self.seed,
            "redirect_uris": self.redirect_uris,
        }

        for endpoint in ENDPOINTS:
            res[endpoint] = getattr(self, endpoint, None)

        self.sdb[sid] = res

    # noinspection PyUnusedLocal,PyArgumentEqualDefault
    def begin(self, baseurl, request, response_type="", **kwargs):
        """ Begin the OAuth2 flow

        :param baseurl: The RPs base
        :param request: The Authorization query
        :param response_type: The response type the AS should use.
            Default 'code'.
        :return: A URL to which the user should be redirected
        """

        LOG_DEBUG("- begin -")

        # Store the request and the redirect uri used
        self.redirect_uris = ["%s%s" % (baseurl, self.authz_page)]
        self._request = request

        # Put myself in the dictionary of sessions, keyed on session-id
        if not self.seed:
            self.seed = rndstr()

        sid = stateID(request, self.seed)
        self.grant[sid] = Grant(seed=self.seed)
        self._backup(sid)
        self.sdb["seed:%s" % self.seed] = sid

        if not response_type:
            if self.response_type:
                response_type = self.response_type
            else:
                self.response_type = response_type = "code"

        location = self.request_info(
            AuthorizationRequest, method="GET", scope=self.scope,
            request_args={"state": sid, "response_type": response_type})[0]

        LOG_DEBUG("Redirecting to: %s" % (location,))

        return sid, location

    # noinspection PyUnusedLocal
    def handle_authorization_response(self, query="", **kwargs):
        """
        This is where we get redirect back to after authorization at the
        authorization server has happened.

        :param query: The query part of the request
        :return: A AccessTokenResponse instance
        """

        LOG_DEBUG("- authorization - %s flow -" % self.flow_type)
        LOG_DEBUG("QUERY: %s" % query)

        if "code" in self.response_type:
            # Might be an error response
            try:
                aresp = self.parse_response(AuthorizationResponse,
                                            info=query, sformat="urlencoded")
            except Exception as err:
                logger.error("%s" % err)
                raise

            if isinstance(aresp, Message):
                if aresp.type().endswith("ErrorResponse"):
                    raise AuthzError(aresp["error"])

            try:
                self.update(aresp["state"])
            except KeyError:
                raise UnknownState(aresp["state"])

            self._backup(aresp["state"])

            return aresp
        else:  # implicit flow
            atr = self.parse_response(AccessTokenResponse,
                                      info=query, sformat="urlencoded",
                                      extended=True)

            if isinstance(atr, Message):
                if atr.type().endswith("ErrorResponse"):
                    raise TokenError(atr["error"])

            try:
                self.update(atr["state"])
            except KeyError:
                raise UnknownState(atr["state"])

            self.seed = self.grant[atr["state"]].seed

            return atr

    def complete(self, query, state, **kwargs):
        """
        :param query: The query part of the request URL
        :param state:
        """

        resp = self.handle_authorization_response(query, **kwargs)

        if resp.type() == "AuthorizationResponse":
            # Go get the access token
            resp = self.do_access_token_request(state=state)

        return resp

    def client_auth_info(self):
        """

        """
        if self.password:
            http_args = {"client_password": self.password}
            request_args = {}
            extra_args = {}
        elif self.client_secret:
            http_args = {}
            request_args = {"client_secret": self.client_secret,
                            "client_id": self.client_id}
            extra_args = {"auth_method": "bearer_body"}
        else:
            raise MissingAuthenticationInfo("Nothing to authenticate with")

        return request_args, http_args, extra_args

    # noinspection PyUnusedLocal
    def get_access_token_request(self, state, **kwargs):

        request_args, http_args, extra_args = self.client_auth_info()

        url, body, ht_args, csi = self.request_info(AccessTokenRequest,
                                                    request_args=request_args,
                                                    state=state,
                                                    **extra_args)

        if not http_args:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return url, body, http_args
