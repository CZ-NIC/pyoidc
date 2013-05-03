#!/usr/bin/env python
__author__ = 'rohe0002'

import base64
import logging
import os

from oic.oauth2.exception import MissingParameter
from oic.oauth2.exception import FailedAuthentication

from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import add_non_standard
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import NoneResponse
from oic.oauth2.message import by_schema
from oic.oauth2.message import MissingRequiredAttribute
from oic.oauth2.message import TokenErrorResponse
from oic.oauth2.message import AccessTokenRequest

from oic.utils.http_util import BadRequest
from oic.utils.http_util import make_cookie
from oic.utils.http_util import Redirect
from oic.utils.http_util import Response

from oic.oauth2 import rndstr
from oic.oauth2 import Server as SrvMethod

logger = logging.getLogger(__name__)
LOG_INFO = logger.info
LOG_DEBUG = logger.debug


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

    aresp = AccessTokenResponse(**by_schema(AccessTokenResponse, **_dic))
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
    if response_type in [["code"], ["token"], ["none"]]:
        return "%s?%s" % (redirect_uri, query)
    else:
        return "%s#%s" % (redirect_uri, query)


class Provider(object):
    def __init__(self, name, sdb, cdb, authn, authz, client_authn,
                 symkey="", urlmap=None, iv=0):
        self.name = name
        self.sdb = sdb
        self.cdb = cdb
        self.srvmethod = SrvMethod()
        self.authn = authn
        if authn:
            self.authn.srv = self
        self.authz = authz
        self.client_authn = client_authn
        self.symkey = symkey
        self.seed = rndstr()
        self.iv = iv or os.urandom(16)
        self.cookie_name = "pyoidc"

        if urlmap is None:
            self.urlmap = {}
        else:
            self.urlmap = urlmap

        self.response_type_map = {
            "code": code_response,
            "token": token_response,
            "none": none_response,
        }

    def get_client_id(self, req, authn):
        """
        Verify the client and return the client id

        :param req: The request
        :param authn: Authentication information from the HTTP header
        :return:
        """

        logger.debug("REQ: %s" % req.to_dict())
        if authn:
            if authn.startswith("Basic "):
                logger.debug("Basic auth")
                (_id, _secret) = base64.b64decode(authn[6:]).split(":")
                if _id not in self.cdb:
                    logger.debug("Unknown client_id")
                    raise FailedAuthentication("Unknown client_id")
                else:
                    try:
                        assert _secret == self.cdb[_id]["client_secret"]
                    except AssertionError:
                        logger.debug("Incorrect secret")
                        raise FailedAuthentication("Incorrect secret")
            else:
                try:
                    assert authn[:6].lower() == "bearer"
                    logger.debug("Bearer auth")
                    _token = authn[7:]
                except AssertionError:
                    raise FailedAuthentication("AuthZ type I don't know")

                try:
                    _id = self.cdb[_token]
                except KeyError:
                    logger.debug("Unknown access token")
                    raise FailedAuthentication("Unknown access token")
        else:
            try:
                _id = req["client_id"]
                if _id not in self.cdb:
                    logger.debug("Unknown client_id")
                    raise FailedAuthentication("Unknown client_id")
            except KeyError:
                raise FailedAuthentication("Missing client_id")

        return _id

    def authn_reply(self, areq, aresp, bsid, **kwargs):

        if "redirect_uri" in areq:
            # TODO verify that the uri is reasonable
            redirect_uri = areq["redirect_uri"]
        else:
            redirect_uri = self.urlmap[areq["client_id"]]

        location = location_url(areq["response_type"], redirect_uri,
                                aresp.to_urlencoded())

        LOG_DEBUG("Redirected to: '%s' (%s)" % (location, type(location)))

        # set cookie containing session ID

        cookie = make_cookie(self.cookie_name, bsid, self.seed)

        return Redirect(str(location), headers=[cookie])

    def authn_response(self, areq, **kwargs):
        """

        :param areq: Authorization request
        :param kwargs: Extra keyword arguments
        :return:
        """
        scode = kwargs["code"]
        areq["response_type"].sort()
        _rtype = " ".join(areq["response_type"])
        return self.response_type_map[_rtype](areq=areq, scode=scode,
                                              sdb=self.sdb)

    def input(self, query="", post=None):
        # Support GET and POST
        if query:
            return query
        elif post:
            return post
        else:
            raise MissingParameter("No input")

    def authorization_endpoint(self, query="", **kwargs):
        """ The AuthorizationRequest endpoint

        :param query: The query part of the request URL
        """
        _sdb = self.sdb

        LOG_DEBUG("- authorization -")
        LOG_DEBUG("Query: '%s'" % query)

        identity = self.authn.authenticated_as()
        if identity is None:  # No!
            return self.authn(query=query)
        else:
            # I get back a dictionary
            user = identity["uid"]

        LOG_DEBUG("- authenticated -")

        try:
            areq = self.srvmethod.parse_authorization_request(query=query)
        except MissingRequiredAttribute, err:
            return BadRequest("%s" % err)
        except Exception, err:
            return BadRequest("%s" % err)

        sid = _sdb.create_authz_session(user, areq)
        bsid = base64.b64encode(sid)
        session = _sdb[sid]

        # Do the authorization
        try:
            permission = self.authz(session["sub"], session)
            _sdb.update(sid, "permission", permission)
        except Exception:
            raise

        grant = session["code"]
        LOG_DEBUG("code: '%s'" % grant)

        try:
            aresp = self.authn_response(areq,
                                        **by_schema(AuthorizationResponse,
                                                    **session))
        except KeyError, err:  # Don't know what to do raise an exception
            return BadRequest("Unknown response type (%s)" % err)

        add_non_standard(aresp, areq)

        return self.authn_reply(areq, aresp, bsid)

    def token_endpoint(self, auth_header="", **kwargs):
        """
        This is where clients come to get their access tokens
        """

        _sdb = self.sdb

        LOG_DEBUG("- token -")
        body = kwargs["post"]
        LOG_DEBUG("body: %s" % body)

        areq = AccessTokenRequest().deserialize(body, "urlencoded")


        try:
            client = self.client_authn(self, areq, auth_header)
        except FailedAuthentication, err:
            err = TokenErrorResponse(error="unathorized_client",
                                     error_description="%s" % err)
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

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

        return Response(atr.to_json(), content="application/json")

# =============================================================================


class Endpoint(object):
    etype = ""

    def __init__(self, func):
        self.func = func

    @property
    def name(self):
        return "%s_endpoint" % self.etype

    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)


class AuthorizationEndpoint(Endpoint):
    etype = "authorization"


class TokenEndpoint(Endpoint):
    etype = "token"
