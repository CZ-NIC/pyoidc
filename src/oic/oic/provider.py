#!/usr/bin/env python
import json
import traceback
import urllib
import sys
from oic.utils.keyio import KeyChain, key_export

from requests import ConnectionError

from oic.oauth2.message import ErrorResponse, by_schema
from oic.oic.message import AuthorizationRequest
from oic.oic.message import IdToken
from oic.oic.message import OpenIDSchema
from oic.oic.message import RegistrationResponseCU
from oic.oic.message import RegistrationResponseCARS
from oic.oic.message import AuthorizationResponse
from oic.oic.message import AuthorizationErrorResponse
from oic.oic.message import OpenIDRequest
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AuthnToken
from oic.oic.message import AccessTokenRequest
from oic.oic.message import TokenErrorResponse
from oic.oic.message import SCOPE2CLAIMS
from oic.oic.message import RegistrationRequest
from oic.oic.message import ClientRegistrationErrorResponse
from oic.oic.message import UserInfoClaim
from oic.oic.message import DiscoveryRequest
from oic.oic.message import ProviderConfigurationResponse
from oic.oic.message import DiscoveryResponse

from jwkest import jws, jwe
from jwkest.jws import alg2keytype

__author__ = 'rohe0002'

import random
import base64
import urlparse
import hmac
import time
import hashlib
import logging

from urlparse import parse_qs

from oic.oauth2.provider import Provider as AProvider

from oic.utils.http_util import Response
from oic.utils.http_util import Redirect
from oic.utils.http_util import BadRequest
from oic.utils.http_util import geturl
from oic.utils.http_util import Unauthorized
from oic.utils import time_util

from oic.oauth2 import MissingRequiredAttribute
from oic.oauth2 import rndstr
from oic.oauth2.provider import AuthnFailure


from oic.oic import Server
from oic.oic import JWT_BEARER
#from oic.oic.base import Server
#from oic.oic.base import JWT_BEARER

from oic.oic.exception import *

logger = logging.getLogger(__name__)

SWD_ISSUER = "http://openid.net/specs/connect/1.0/issuer"
STR = 5*"_"

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

#def update_info(aresp, sdict):
#    for prop in aresp._schema["param"].keys():
#        try:
#            aresp[prop] = sdict[prop]
#        except KeyError:
#            pass

def code_token_response(**kwargs):
    _areq = kwargs["areq"]
    _scode = kwargs["scode"]
    _sdb = kwargs["sdb"]

    aresp = AuthorizationResponse()

    for key in ["state", "nonce", "scope"]:
        try:
            aresp[key] = _areq[key]
        except KeyError:
            pass

    aresp["code"] = _scode

    _dic = _sdb.update_to_token(_scode, issue_refresh=False)
    for prop in AccessTokenResponse.c_param.keys():
        try:
            aresp[prop] = _dic[prop]
        except KeyError:
            pass

    return aresp

def location_url(response_type, redirect_uri, query):
    if response_type in [["code"],["token"],["none"]]:
        return "%s?%s" % (redirect_uri, query)
    else:
        return "%s#%s" % (redirect_uri, query)

def construct_uri(item):
    (base_url, query) = item
    if query:
        return "%s?%s" % (base_url, urllib.urlencode(query))
    else:
        return base_url

import socket

class Provider(AProvider):
    def __init__(self, name, sdb, cdb, function, userdb, urlmap=None,
                 ca_certs="", keyjar=None, hostname=""):

        AProvider.__init__(self, name, sdb, cdb, function, urlmap)

        self.server = Server(ca_certs=ca_certs)
        if keyjar:
            self.server.keyjar = keyjar

        self.keyjar = self.server.keyjar
        self.userdb = userdb

        self.function = function
        self.endpoints = []
        self.baseurl = ""
        self.cert = []
        self.cert_encryption = []

        self.cookie_func = None
        self.cookie_name = "pyoidc"
        self.seed = ""
        self.cookie_ttl = 0
        self.test_mode = False
        self.jwk = []

        self.authn_as = None
        self.preferred_id_type = "public"
        self.hostname = hostname or socket.gethostname

    def id_token_as_signed_jwt(self, session, loa="2", alg="RS256", code=None,
                               access_token=None, user_info=None):

        logger.debug("Signing alg: %s" % alg)
        _idt = self.server.make_id_token(session, loa, self.name, alg, code,
                                         access_token, user_info)

        logger.debug("id_token: %s" % _idt.to_dict())
        ckey = self.keyjar.get_signing_key(alg2keytype(alg),
                               session["client_id"])
        _signed_jwt = _idt.to_jwt(key=ckey, algorithm=alg)

        return _signed_jwt

    def _error_response(self, error, descr=None):
        response = ErrorResponse(error=error, error_description=descr)
        return Response(response.to_json(), content="application/json",
                        status="400 Bad Request")

    def _error(self, environ, start_response, error, descr=None):
        response = ErrorResponse(error=error, error_description=descr)
        resp = Response(response.to_json(), content="application/json",
                        status="400 Bad Request")
        if start_response:
            return resp(environ, start_response)
        else:
            return resp

    def _authz_error(self, environ, start_response, error, descr=None):

        response = AuthorizationErrorResponse(error=error)
        if descr:
            response["error_description"]=descr

        resp = Response(response.to_json(), content="application/json",
                        status="400 Bad Request")
        return resp(environ, start_response)

    def _redirect_authz_error(self, error, redirect_uri, descr=None):
        err = ErrorResponse(error=error)
        if descr:
            err["error_description"] = descr
        location = err.request(redirect_uri)
        return Redirect(location)

    def _verify_redirect_uri(self, areq):
        """
        MUST NOT contain a fragment
        MAY contain query component
        """
        try:
            _redirect_uri = urlparse.unquote(areq["redirect_uri"])

            part = urlparse.urlparse(_redirect_uri)
            if part.fragment:
                raise ValueError

            (_base, _query) = urllib.splitquery(_redirect_uri)
            if _query:
                _query = urlparse.parse_qs(_query)

            match = False
            for regbase, rquery in self.cdb[areq["client_id"]]["redirect_uris"]:
                if _base == regbase or _redirect_uri.startswith(regbase):
                    # every registered query component must exist in the
                    # redirect_uri
                    if rquery:
                        for key, vals in rquery.items():
                            assert key in _query
                            for val in vals:
                                assert val in _query[key]
                    match = True
                    break
            if not match:
                raise AssertionError
            # ignore query components that are not registered
            return None
        except Exception:
            logger.error("Faulty redirect_uri: %s" % areq["redirect_uri"])
            logger.info("Registered redirect_uris: %s" % (
                                self.cdb[areq["client_id"]]["redirect_uris"],))
            response = AuthorizationErrorResponse(error="invalid_request",
                               error_description="Faulty redirect_uri")

            return Response(response.to_json(), content="application/json",
                            status="400 Bad Request")

    def _parse_openid_request(self, request, redirect_uri):
        try:
            return OpenIDRequest().from_jwt(request, keyjar=self.keyjar)
        except Exception, err:
            logger.error("Faulty request: %s" % request)
            logger.error("Exception: %s" % (err.__class__.__name__,))
            openid_req = OpenIDRequest().from_jwt(request, verify=False)
            logger.error("Request: %s" % openid_req.to_dict())
            return self._redirect_authz_error("invalid_openid_request_object",
                                              redirect_uri)

    def _parse_id_token(self, id_token, redirect_uri):
        try:
            return IdToken().from_jwt(id_token, keyjar=self.keyjar)
        except Exception, err:
            logger.error("Faulty id_token: %s" % id_token)
            logger.error("Exception: %s" % (err.__class__.__name__,))
            id_token = IdToken().from_jwt(id_token, verify=False)
            logger.error("IdToken: %s" % id_token.to_dict())
            return self._redirect_authz_error("invalid_id_token_object",
                                              redirect_uri)

    def get_redirect_uri(self, areq):
        """ verify that the redirect URI is reasonable
        :param areq: The Authorization request
        :return: Tuple of (redirect_uri, Response instance)
            Response instance is not None of matching redirect_uri failed
        """
        if 'redirect_uri' in areq:
            reply = self._verify_redirect_uri(areq)
            if reply:
                return (None, reply)
            uri = areq["redirect_uri"]
        else: # pick the one registered
            ruris = self.cdb[areq["client_id"]]["redirect_uris"]
            if len(ruris) == 1:
                uri = construct_uri(ruris[0])
            else:
                err = "Missing redirect_uri and more than one registered"
                logger.debug("Bad request: %s" % err)
                resp = BadRequest("%s" % err)
                return None, resp

        return uri, None

    def get_sector_id(self, redirect_uri, client_info):
        """
        Pick the sector id given a number of factors
        :param redirect_uri: The redirect_uri used
        :param client_info: Information provided by the client in the
          client registration
        :return: A sector_id or None
        """

        _redirect_uri = urlparse.unquote(redirect_uri)

        part = urlparse.urlparse(_redirect_uri)
        if part.fragment:
            raise ValueError

        (_base, _query) = urllib.splitquery(_redirect_uri)

        sid = ""
        try:
            if _base in client_info["si_redirects"]:
                sid = client_info["sector_id"]
        except KeyError:
            try:
                uit = client_info["user_id_type"]
                if uit == "pairwise":
                    sid = _base
            except KeyError:
                pass

        return sid

    def input(self, environ, **kwargs):
        # Support GET and POST
        try:
            query = kwargs["query"]
        except KeyError:
            try:
                query = get_or_post(environ)
            except UnsupportedMethod:
                return BadRequest("Unsupported method")

        return query

    def authorization_endpoint(self, environ, start_response, **kwargs):
        # The AuthorizationRequest endpoint

        try:
            _log_debug = kwargs["logger"].debug
            _log_info = kwargs["logger"].info
        except KeyError:
            _log_debug = logger.debug
            _log_info = logger.info
        _sdb = self.sdb
        _srv = self.server

        _log_debug("- authorization -")

        query = self.input(environ, **kwargs)
        if isinstance(query, Response):
            return query(environ, start_response)

        _log_debug("authorization_request: %s" % query)

        # Same serialization used for GET and POST
        try:
            areq = _srv.parse_authorization_request(query=query)
        except (MissingRequiredAttribute, KeyError):
            areq = AuthorizationRequest().deserialize(query, "urlencoded")
            # verify the redirect_uri
            (uri, reply) = self.get_redirect_uri(areq)
            if reply:
                return reply(environ, start_response)
            resp = self._redirect_authz_error("invalid_request",
                                              uri, "Missing required attribute")
            return resp(environ, start_response)
        except Exception, err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            _log_debug("Bad request: %s (%s)" % (err, err.__class__.__name__))
            resp = BadRequest("%s" % err)
            return resp(environ, start_response)

#        try:
#            areq.verify()
#        except Exception, err:
#            _log_debug("Bad request: %s" % err)
#            resp = BadRequest("%s" % err)
#            return resp(environ, start_response)

        (redirect_uri, reply) = self.get_redirect_uri(areq)
        if reply:
            return reply(environ, start_response)

        try:
            client_info = self.cdb[areq["client_id"]]
        except KeyError:
            _log_info("Unknown client: %s" % areq["client_id"])
            raise UnknownClient(areq["client_id"])

        if "request_uri" in areq:
            # Do a HTTP get
            try:
                _req = _srv.http_request(areq["request_uri"])
            except ConnectionError:
                return self._authz_error(environ, start_response,
                                         "invalid_request_uri")

            if not _req:
                return self._authz_error(environ, start_response,
                                         "invalid_request_uri")

            resp = self._parse_openid_request(_req.text, redirect_uri)
            if isinstance(resp, Response):
                return resp(environ, start_response)
            else:
                areq["request"] = resp

        try:
            openid_req = areq["request"]
        except KeyError:
            openid_req = None

        if openid_req:
            try:
                user = openid_req["id_token"]["claims"]["user_id"]["value"]
            except KeyError:
                user = ""
        elif "id_token" in areq:
            user = areq["id_token"]["user_id"]
        else:
            user = ""

        if user:
            try:
                sid = _sdb.get_sid_from_userid(user)
            except Exception:
                logger.error("Unknown user id '%s'" % user)
                logger.debug("uid2sid: %s" % _sdb.uid2sid)
                sid = ""

            if sid:
                return self.authenticated(environ,
                                          start_response,
                                          active_auth=sid,
                                          areq=areq, user=user)

        if "prompt" in areq:
            _log_debug("Prompt: '%s'" % areq["prompt"])

            if "none" in areq["prompt"]:
                resp = self._redirect_authz_error("login_required",
                                                  redirect_uri)
                return resp(environ, start_response)
            elif "login" in areq["prompt"]:
                # force re-authentication, remove link to SSO history
                try:
                    del kwargs["handle"]
                except KeyError:
                    pass

        _log_debug("AREQ keys: %s" % areq.keys())

        sid = _sdb.create_authz_session(user, areq, oidreq=openid_req)

        _log_debug("session: %s" % _sdb[sid])

        bsid = base64.b64encode(sid)

        cookie = None

        if self.authn_as:
            user_id = self.authn_as
            _log_debug("Implicit authenticated as %s" % user_id)
            _sdb.update(sid, "local_user_id", user_id)
            (redirect_uri, reply) = self.get_redirect_uri(areq)
            client_info = self.cdb[areq["client_id"]]
            sector_id = self.get_sector_id(redirect_uri, client_info)

            try:
                preferred_id_type = client_info["preferred_id_type"]
            except KeyError:
                preferred_id_type = self.preferred_id_type

            self.sdb.do_userid(sid, user_id, sector_id, preferred_id_type)
            _log_debug("session: %s" % _sdb[sid])
            _log_debug("uid2sid: %s" % _sdb.uid2sid)
            return self.authenticated(environ, start_response, active_auth=sid,
                                      areq=areq, user=user_id)

        if openid_req:
            _log_info("Request: %s" % openid_req.to_dict())
            try:
                _max_age = openid_req["id_token"]["max_age"]
            except KeyError:
                _max_age = -1

            if _max_age >= 0:
                if "handle" in kwargs:
                    try:
                        (key, timestamp) = kwargs["handle"]
                        _log_info("key: %s" % key)
                        if key.startswith(STR) and key.endswith(STR):
                            pass
                        else:
                            _now = time.mktime(time.gmtime())
                            if (_now - int(timestamp)) <= _max_age:
                                _log_info("- SSO -")
                                _scode = base64.b64decode(key)
                                _log_debug("OLD session: %s" % _sdb[_scode])
                                user = self.sdb[_scode]["user_id"]
                                _sdb.update(sid, "user_id", user)
                                return self.authenticated(environ,
                                                          start_response,
                                                          active_auth=_scode,
                                                          areq=areq, user=user)
                            else:
                                _log_info("Authentication to old: %d>%d" % (
                                            _now - int(timestamp), _max_age))
                    except ValueError:
                        pass
        else:
            if "handle" in kwargs and kwargs["handle"]:
                (key, timestamp) = kwargs["handle"]
                if key.startswith(STR) and key.endswith(STR):
                    cookie = self.cookie_func(self.cookie_name, key,
                                              self.seed, self.cookie_ttl)
                else:
                    try:
                        _log_info("- SSO -")
                        _scode = base64.b64decode(key)
                        user = self.sdb[_scode]["user_id"]
                        _sdb.update(sid, "user_id", user)
                        # This happens if a valid cookie is presented
                        return self.authenticated(environ, start_response,
                                                  active_auth=_scode,
                                                  areq=areq, user=user)
                    except ValueError:
                        pass

        # DEFAULT: start the authentication process
        kwa = {"cookie": cookie}
        for item in ["policy_url", "logo_url"]:
            try:
                kwa[item] = client_info[item]
            except KeyError:
                pass

        _log_info("KWA: %s" % kwa)
        return self.function["authenticate"](environ, start_response, bsid,
                                             **kwa)

    def verify_client(self, environ, areq):
        try:
            _token = self._bearer_auth(environ)
            if _token in self.cdb:
                return True
        except AuthnFailure:
            pass

        if areq["client_id"] not in self.cdb:
            return False

        if "client_secret" in areq: # client_secret_post
            identity = areq["client_id"]
            if self.cdb[identity]["client_secret"] == areq["client_secret"]:
                return True
        elif "client_assertion" in areq: # client_secret_jwt or public_key_jwt
            if areq["client_assertion_type"] != JWT_BEARER:
                return False

            bjwt = AuthnToken().from_jwt(areq["client_assertion"],
                                         keyjar=self.keyjar)

            try:
                # There might not be a client_id in the request
                #assert bjwt["iss"] == areq["client_id"] # Issuer == the client

                assert str(bjwt["iss"]) in self.cdb # It's a client I know
                assert str(bjwt["aud"]) == geturl(environ, query=False)
                return True
            except AssertionError:
                pass

        return False

    def userinfo_in_id_token_claims(self, session):
        itc = self.server.id_token_claims(session)
        if not itc:
            return None

        try:
            claims = itc["claims"]
        except KeyError:
            return None

        _claims = {}
        # schema dependent
        for key in OpenIDSchema().parameters():
            if key in claims:
                _claims[key] = claims[key]

        if _claims:
            return self._collect_user_info(session, {"claims": _claims})
        else:
            return None

    def encrypt(self, payload, client_info, cid, type="id_token"):
        """
        Handles the encryption of a payload

        :param payload: The information to be encrypted
        :param client_info: Client information
        :param cid: Client id
        :return: The encrypted information as a JWT
        """

        alg = client_info["%s_encrypted_response_alg" % type]
        try:
            enc = client_info["%s_encrypted_response_enc" % type]
        except KeyError:
            enc = "A128CBC"
        try:
            int = client_info["%s_encrypted_response_int" % type]
        except KeyError:
            int = "HS256"

        keys = self.keyjar.get_encrypt_key(owner=cid)
        #logger.debug("keys for %s: %s" % (cid, self.keyjar.keys_by_owner(cid)))
        logger.debug("alg=%s, enc=%s, int=%s" % (alg, enc, int))
        logger.debug("Encryption keys for %s: %s" % (cid, keys))

        # use the clients public key for encryption
        return jwe.encrypt(payload, keys, alg, enc, context="public", int=int)

    def sign_encrypt_id_token(self, sinfo, client_info, areq, code=None,
                              access_token=None, user_info=None):
        """
        Signed and or encrypt a IDToken

        :param sinfo: Session information
        :param client_info: Client information
        :param areq: The request
        :param code: Access grant
        :param access_token: Access Token
        :param user_info: User information
        :return: IDToken instance
        """

        try:
            alg = client_info["id_token_signed_response_alg"]
        except KeyError:
            alg = "RS256"

        id_token = self.id_token_as_signed_jwt(sinfo, alg=alg,
                                               code=code,
                                               access_token=access_token,
                                               user_info=user_info)

        # Then encrypt
        if "id_token_encrypted_response_alg" in client_info:
            id_token = self.encrypt(id_token, client_info, areq["client_id"],
                                    "id_token")

        return id_token

    #noinspection PyUnusedLocal
    def token_endpoint(self, environ, start_response, **kwargs):
        """
        This is where clients come to get their access tokens
        """

        try:
            _log_debug = kwargs["logger"].debug
            _log_info = kwargs["logger"].info
        except KeyError:
            _log_debug = logger.debug
            _log_info = logger.info
        _sdb = self.sdb

        _log_debug("- token -")

        body = self.input(environ, **kwargs)
        if isinstance(body, Response):
            return body(environ, start_response)

        _log_info("token_request: %s" % body)

        areq = AccessTokenRequest().deserialize(body, "urlencoded")

        try:
            resp = self.verify_client(environ, areq)
        except Exception, err:
            _log_info("Failed to verify client due to: %s" % err)
            resp = False

        if not resp:
            _log_info("could not verify client")
            err = TokenErrorResponse(error="unathorized_client")
            resp = Unauthorized(err.to_json(), content="application/json")
            return resp(environ, start_response)

        _log_debug("AccessTokenRequest: %s" % areq)
        client_info = self.cdb[areq["client_id"]]

        assert areq["grant_type"] == "authorization_code"

        _access_code = areq["code"]
        # assert that the code is valid
        if self.sdb.is_revoked(_access_code):
            return self._error(environ, start_response,
                               error="access_denied", descr="Token is revoked")

        _info = _sdb[_access_code]

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _info:
            assert areq["redirect_uri"] == _info["redirect_uri"]

        _log_debug("All checks OK")

        try:
            _tinfo = _sdb.update_to_token(_access_code)
        except Exception,err:
            _log_info("Error: %s" % err)
            # Should revoke the token issued to this access code
            _sdb.revoke_all_tokens(_access_code)
            return self._error(environ, start_response,
                               error="access_denied", descr= "%s" % err)

        if "openid" in _info["scope"]:
            userinfo = self.userinfo_in_id_token_claims(_info)
            _idtoken = self.sign_encrypt_id_token(_info, client_info, areq,
                                                  user_info=userinfo)
            _sdb.update_by_token(_access_code, "id_token", _idtoken)

        _log_debug("_tinfo: %s" % _tinfo)

        atr = AccessTokenResponse(**by_schema(AccessTokenResponse, **_tinfo))

        _log_debug("access_token_response: %s" % atr.to_dict())

        resp = Response(atr.to_json(), content="application/json")
        return resp(environ, start_response)

    def _bearer_auth(self, environ):
        #'HTTP_AUTHORIZATION': 'Bearer pC7efiVgbI8UASlolltdh76DrTZ2BQJQXFhVvwWlKekFvWCcdMTmNCI/BCSCxQiG'
        try:
            authn = environ["HTTP_AUTHORIZATION"]
            try:
                assert authn[:6].lower() == "bearer"
                _token = authn[7:]
            except AssertionError:
                raise AuthnFailure("AuthZ type I don't know")
        except KeyError:
            raise AuthnFailure

        return _token

    def _collect_user_info(self, session, userinfo_claims=None):
        """
        Collect information about a user.
        This can happen in two cases, either when constructing a IdToken or
        when returning user info through the UserInfo endpoint

        :param session: Session information
        :param userinfo_claims: user info claims
        :return: User info
        """
        if userinfo_claims is None:
            uic = {}
            for scope in session["scope"]:
                try:
                    claims = dict([(name, None) for name in SCOPE2CLAIMS[scope]])
                    uic.update(claims)
                except KeyError:
                    pass

            if "oidreq" in session:
                oidreq = OpenIDRequest().deserialize(session["oidreq"], "json")
                logger.debug("OIDREQ: %s" % oidreq.to_dict())
                if "userinfo" in oidreq:
                    userinfo_claims = oidreq["userinfo"]
                    _claim = oidreq["userinfo"]["claims"]
                    for key, val in uic.items():
                        if key not in _claim:
                            _claim[key] = val
                elif uic:
                    userinfo_claims = UserInfoClaim(claims=uic)
                else:
                    userinfo_claims = None
            elif uic:
                userinfo_claims = UserInfoClaim(claims=uic)
            else:
                userinfo_claims = None

            logger.debug("userinfo_claim: %s" % userinfo_claims.to_dict())

        logger.debug("userdb: %s" % self.userdb.keys())
        logger.debug("Session info: %s" % session)
        info = self.function["userinfo"](self, self.userdb,
                                         session["local_user_id"],
                                         session["client_id"],
                                         userinfo_claims)

        info["user_id"] = session["user_id"]
        logger.debug("user_info_response: %s" % (info,))

        return info

    #noinspection PyUnusedLocal
    def userinfo_endpoint(self, environ, start_response, **kwargs):

        try:
            _log_debug = kwargs["logger"].debug
            _log_info = kwargs["logger"].info
        except KeyError:
            _log_debug = logger.debug
            _log_info = logger.info

        query = self.input(environ, **kwargs)
        if isinstance(query, Response):
            return query(environ, start_response)

        _log_debug("environ: %s" % environ)
        _sdb = self.sdb

        if not query or "access_token" not in query:
            _token = self._bearer_auth(environ)
            logger.debug("Bearer token: %s" % _token)
        else:
            uireq = self.server.parse_user_info_request(data=query)
            _log_debug("user_info_request: %s" % uireq)
            _token = uireq["access_token"]

        # should be an access token
        typ, key = _sdb.token.type_and_key(_token)
        _log_debug("access_token type: '%s'" % (typ,))

        try:
            assert typ == "T"
        except AssertionError:
            raise AuthnFailure("Wrong type of token")

        #_log_info("keys: %s" % self.sdb.keys())
        if _sdb.is_revoked(key):
            return self._error(environ, start_response, error="access_denied",
                               descr="Token is revoked")
        session = _sdb[key]

        # Scope can translate to userinfo_claims

        info = self._collect_user_info(session)

        # Should I return a JSON or a JWT ?
        _cinfo = self.cdb[session["client_id"]]
        if "userinfo_signed_response_alg" in _cinfo:
            algo = _cinfo["userinfo_signed_response_alg"]
            key = self.keyjar.get_signing_key(alg2keytype(algo),
                                  owner=session["client_id"])
            jinfo = info.to_jwt(key, algo)
            content_type="application/jwt"
            if "userinfo_encrypted_response_alg" in _cinfo:
                jinfo = self.encrypt(jinfo, _cinfo, session["client_id"],
                                     "userinfo")
        elif "userinfo_encrypted_response_alg" in _cinfo:
            jinfo = self.encrypt(info.to_json(), _cinfo, session["client_id"],
                                 "userinfo")
            content_type="application/jwt"
        else:
            jinfo = info.to_json()
            content_type="application/json"

        resp = Response(jinfo, content=content_type)
        return resp(environ, start_response)

    #noinspection PyUnusedLocal
    def check_session_endpoint(self, environ, start_response, **kwargs):
        try:
            _log_debug = kwargs["logger"].debug
            _log_info = kwargs["logger"].info
        except KeyError:
            _log_debug = logger.debug
            _log_info = logger.info

        info = self.input(environ, **kwargs)
        if isinstance(info, Response):
            return info(environ, start_response)

        if not info:
            info = "id_token=%s" % self._bearer_auth(environ)

        if self.test_mode:
            _log_info("check_session_request: %s" % info)
        idt = self.server.parse_check_session_request(query=info)
        if self.test_mode:
            _log_info("check_session_response: %s" % idt.to_dict())

        resp = Response(idt.to_json(), content="application/json")
        return resp(environ, start_response)

    def _verify_url(self, url, urlset):
        part = urlparse.urlparse(url)

        for reg, qp in urlset:
            _part = urlparse.urlparse(reg)
            if part.scheme == _part.scheme and part.netloc == _part.netloc:
                    return True

        return False

    def do_client_registration(self, request, client_id, ignore=None):
        if ignore is None:
            ignore = []

        _cinfo = self.cdb[client_id].copy()

        for key,val in request.items():
            if key not in ignore:
                _cinfo[key] = val

        if "redirect_uris" in request:
            ruri = []
            for uri in request["redirect_uris"]:
                if urlparse.urlparse(uri).fragment:
                    err = ClientRegistrationErrorResponse(
                        error="invalid_configuration_parameter",
                        error_description="redirect_uri contains fragment")
                    return Response(err.to_json(),
                                    content="application/json",
                                    status="400 Bad Request")
                base, query = urllib.splitquery(uri)
                if query:
                    ruri.append((base, urlparse.parse_qs(query)))
                else:
                    ruri.append((base, query))
            _cinfo["redirect_uris"] = ruri

        if "sector_identifier_url" in request:
            si_url = request["sector_identifier_url"]
            try:
                res = self.server.http_request(si_url)
            except ConnectionError:
                return self._error_response("invalid_configuration_parameter",
                                    descr="Couldn't open sector_identifier_url")

            if not res:
                return self._error_response(
                                   "invalid_configuration_parameter",
                                   descr="Couldn't open sector_identifier_url")
            try:
                si_redirects = json.loads(res.text)
            except Exception:
                return self._error_response(
                                   "invalid_configuration_parameter",
                                   descr="Error deserializing sector_identifier_url content")

            if "redirect_uris" in request:
                for uri in request["redirect_uris"]:
                    try:
                        assert uri in si_redirects
                    except AssertionError:
                        return self._error_response(
                            "invalid_configuration_parameter",
                            descr="redirect_uri missing from sector_identifiers")

            _cinfo["si_redirects"] = si_redirects
            _cinfo["sector_id"] = si_url
        elif "redirect_uris" in request:
            if len(request["redirect_uris"]) > 1:
                # check that the hostnames are the same
                host = ""
                for url in request["redirect_uris"]:
                    part = urlparse.urlparse(url)
                    _host = part.netloc.split(":")[0]
                    if not host:
                        host = _host
                    else:
                        try:
                            assert host == _host
                        except AssertionError:
                            return self._error_response(
                                "invalid_configuration_parameter",
                                descr="'sector_identifier_url' must be registered")

        for item in ["policy_url", "logo_url"]:
            if item in request:
                if self._verify_url(request[item], _cinfo["redirect_uris"]):
                    _cinfo[item] = request[item]
                else:
                    return self._error_response(
                                        "invalid_configuration_parameter",
                                       descr="%s pointed to illegal URL" % item)

        try:
            self.keyjar.provider_keys(request, client_id)
            try:
                logger.debug("keys for %s: %s" % (client_id,
                                                  self.keyjar[client_id]))
            except KeyError:
                pass
        except Exception, err:
            logger.error("Failed to load client keys: %s" % request.to_dict())
            err = ClientRegistrationErrorResponse(
                error="invalid_configuration_parameter",
                error_description="%s" % err)
            return Response(err.to_json(), content="application/json",
                            status="400 Bad Request")

        return _cinfo

    #noinspection PyUnusedLocal
    def l_registration_endpoint(self, environ, **kwargs):
        try:
            _log_debug = kwargs["logger"].debug
            _log_info = kwargs["logger"].info
        except KeyError:
            _log_debug = logger.debug
            _log_info = logger.info

        _log_debug("@registration_endpoint")

        query = self.input(environ, **kwargs)
        if isinstance(query, Response):
            return query

        request = RegistrationRequest().deserialize(query, "urlencoded")
        _log_info("registration_request:%s" % request.to_dict())

        try:
            request.verify()
        except Exception, err:
            if "type" not in request:
                return self._error(environ, None, error="invalid_type")
            else:
                return self._error(environ, None,
                                   error="invalid_configuration_parameter")

        _keyjar = self.server.keyjar

        if request["type"] == "client_associate":
            # create new id och secret
            client_id = rndstr(12)
            while client_id in self.cdb:
                client_id = rndstr(12)

            client_secret = secret(self.seed, client_id)
            self.cdb[client_id] = {
                "client_secret":client_secret
            }
            resp = self.do_client_registration(request, client_id,
                                               ignore=["redirect_uris",
                                                       "policy_url",
                                                       "logo_url"])
            if isinstance(resp, Response) :
                return resp
            else:
                _cinfo = resp

            response = RegistrationResponseCARS(client_id=client_id)
            #if self.debug:
            #    _log_info("KEYSTORE: %s" % self.keyjar._store)

        elif request["type"] == "client_update" or \
             request["type"] == "rotate_secret":
            #  that these are an id,secret pair I know about
            client_id = request["client_id"]
            try:
                _cinfo = self.cdb[client_id].copy()
            except KeyError:
                _log_info("Unknown client id")
                return BadRequest()

            if _cinfo["client_secret"] != request["client_secret"]:
                _log_info("Wrong secret")
                return BadRequest()

            if request["type"] == "rotate_secret":
                # update secret
                client_secret = secret(self.seed, client_id)
                _cinfo["client_secret"] = client_secret

                _keyjar.remove_key(client_id, type="hmac",
                                   key=request["client_secret"])
                response = RegistrationResponseCARS(client_id=client_id)
            else: # client_update
                client_secret = None
                resp = self.do_client_registration(request, client_id,
                                                   ignore=["client_id",
                                                           "client_secret",
                                                           "policy_url",
                                                           "redirect_uris",
                                                           "logo_url"])

                if isinstance(resp, Response):
                    return resp
                else:
                    _cinfo = resp
                    response = RegistrationResponseCU(client_id=client_id)

            self.keyjar.provider_keys(request, client_id, replace=True)

        else:
            return BadRequest("Unknown request type: %s" % request.type)

        # Add the key to the keyjar
        if client_secret:
            _kc = KeyChain({"hmac": client_secret}, usage=["ver","sig"])
            try:
                _keyjar[client_id].append(_kc)
            except KeyError:
                _keyjar[client_id] = [_kc]

            _cinfo["registration_expires"] = time_util.time_sans_frac()+3600

            response["client_secret"] = client_secret
            response["expires_at"] = _cinfo["registration_expires"]

        self.cdb[client_id] = _cinfo
        _log_info("Client info: %s" % _cinfo)

        if self.test_mode:
            _log_info("registration_response: %s" % response.to_dict())

        return Response(response.to_json(), content="application/json",
                        headers=[("Cache-Control", "no-store")])

    def registration_endpoint(self, environ, start_response, **kwargs):
        resp = self.l_registration_endpoint(environ, **kwargs)
        return resp(environ, start_response)

    #noinspection PyUnusedLocal
    def providerinfo_endpoint(self, environ, start_response, **kwargs):
        try:
            _log_debug = kwargs["logger"].debug
            _log_info = kwargs["logger"].info
        except KeyError:
            _log_debug = logger.debug
            _log_info = logger.info

        _log_info("@providerinfo_endpoint")
        try:
            _response = ProviderConfigurationResponse(
                            issuer=self.baseurl,
                            token_endpoint_auth_types_supported=[
                                                        "client_secret_post",
                                                        "client_secret_basic",
                                                        "client_secret_jwt",
                                                        "private_key_jwt"],
                            scopes_supported=["openid"],
                            response_types_supported=["code", "token",
                                                      "id_token", "code token",
                                                      "code id_token",
                                                      "token id_token",
                                                      "code token id_token"],
                            user_id_types_supported=["public", "pairwise"],
                            #request_object_algs_supported=["HS256"]
                        )

            supported_algs = jws.SIGNER_ALGS.keys()
            for typ, algs in jwe.SUPPORTED.items():
                for alg in algs:
                    if alg not in supported_algs:
                        supported_algs.append(alg)

            _log_info("Supported algs: %s" % supported_algs)
            # local policy may remove some of these
            _response["request_object_algs_supported"] = supported_algs
            _response["userinfo_algs_supported"] = supported_algs
            _response["id_token_algs_supported"] = supported_algs

            if not self.baseurl.endswith("/"):
                self.baseurl += "/"

            #keys = self.keyjar.keys_by_owner(owner=".")
            #for cert in self.cert:
            #    _response["x509_url"] = "%s%s" % (self.baseurl, cert)

            if self.jwk:
                _response["jwk_url"] = self.jwk

            #_log_info("endpoints: %s" % self.endpoints)
            for endp in self.endpoints:
                #_log_info("# %s, %s" % (endp, endp.name))
                _response[endp.name] = "%s%s" % (self.baseurl, endp.type)

            #if self.test_mode:
                #print sys.stderr >> "providerinfo_endpoint.handle: %s" %
                # kwargs["handle"]

            _log_info("provider_info_response: %s" % (_response.to_dict(),))

            headers=[("Cache-Control", "no-store"), ("x-ffo", "bar")]
            if "handle" in kwargs:
                (key, timestamp) = kwargs["handle"]
                if key.startswith(STR) and key.endswith(STR):
                    cookie = self.cookie_func(self.cookie_name, key, self.seed,
                                              self.cookie_ttl)
                    headers.append(cookie)

            resp = Response(_response.to_json(), content="application/json",
                            headers=headers)
        except Exception, err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            resp = Response(message, content="html/text")

        return resp(environ, start_response)

    def discovery_endpoint(self, environ, start_response, **kwargs):
        try:
            _log_debug = kwargs["logger"].debug
        except KeyError:
            _log_debug = logger.debug

        _log_debug("@discovery_endpoint")

        query = self.input(environ, **kwargs)
        if isinstance(query, Response):
            return query(environ, start_response)

        request = DiscoveryRequest().deserialize(query, "urlencoded")
        _log_debug("discovery_request:%s" % (request.to_dict(),))

        try:
            assert request["service"] == SWD_ISSUER
        except AssertionError:
            resp = BadRequest("Unsupported service")
            return resp(environ, start_response)

        # verify that the principal is one of mine

        _response = DiscoveryResponse(locations=[self.baseurl])

        _log_debug("discovery_response:%s" % (_response.to_dict(),))

        headers=[("Cache-Control", "no-store")]
        (key, timestamp) = kwargs["handle"]
        if key.startswith(STR) and key.endswith(STR):
            cookie = self.cookie_func(self.cookie_name, key, self.seed,
                                      self.cookie_ttl)
            headers.append(cookie)

        resp = Response(_response.to_json(), content="application/json",
                        headers=headers)
        return resp(environ, start_response)

    def authenticated(self, environ, start_response, **kwargs):
        """
        After the authentication this is where you should end up
        """
        try:
            _log_debug = kwargs["logger"].debug
            #_log_info = kwargs["logger"].info
        except KeyError:
            _log_debug = logger.debug
            #_log_info = logger.info

        _log_debug("- in authenticated() -")

        issue_new_code = False
        if "active_auth" in kwargs:
            scode = kwargs["active_auth"]
            user_id = kwargs["user"]
            areq = kwargs["areq"]
            client_info = self.cdb[areq["client_id"]]
            if "code" in areq["response_type"]:
                issue_new_code = True
        else:
            # parse the form
            #noinspection PyDeprecation
            dic = parse_qs(get_post(environ))

            _log_debug("QS: %s" % dic)
            try:
                _log_debug("user: %s" % dic["login"])
            except KeyError:
                pass

            try:
                (verified, user_id) = self.function["verify_user"](dic)
                if not verified:
                    resp = Unauthorized("Wrong password")
                    return resp(environ, start_response)
            except AuthnFailure, err:
                resp = Unauthorized("%s" % (err,))
                return resp(environ, start_response)

            _log_debug("verified user_id: %s" % user_id)

            try:
                # Use the session identifier to find the session information
                b64scode = dic["sid"][0]
                scode = base64.b64decode(b64scode)
                if self.sdb.is_revoked(scode):
                    return self._error(environ, start_response,
                                       error="access_denied",
                                       descr="Token is revoked")
                asession = self.sdb[scode]
            except KeyError:
                resp = BadRequest("Could not find session")
                return resp(environ, start_response)

            _log_debug("asession[\"authzreq\"] = %s" % asession["authzreq"])
                #_log_info( "type: %s" % type(asession["authzreq"]))

            # pick up the original request
            areq = AuthorizationRequest().deserialize(asession["authzreq"],
                                                    "json")

            self.sdb.update(scode, "local_user_id", user_id)

            (redirect_uri, reply) = self.get_redirect_uri(areq)
            client_info = self.cdb[areq["client_id"]]
            sector_id = self.get_sector_id(redirect_uri, client_info)
            try:
                preferred_id_type = client_info["user_id_type"]
            except KeyError:
                preferred_id_type = self.preferred_id_type

            _log_debug("sector_id: %s, preferred_id_type: %s" % (sector_id,
                                                                 preferred_id_type))

            self.sdb.do_userid(scode, user_id, sector_id, preferred_id_type)

            _log_debug("areq: %s" % areq)
            _log_debug("session: %s" % self.sdb[scode])
            _log_debug("uid2sid: %s" % self.sdb.uid2sid)

        # Do the authorization
        try:
            permission = self.function["authorize"](user_id)
            self.sdb.update(scode, "permission", permission)
        except Exception:
            raise

        _log_debug("response type: %s" % areq["response_type"])
        _log_debug("client info: %s" % client_info)
        # create the response
        aresp = AuthorizationResponse()
        try:
            aresp["state"] = areq["state"]
        except KeyError:
            pass

        if "response_type" in areq and \
                len(areq["response_type"]) == 1 and \
                "none" in areq["response_type"]:
            pass
        else:
            if self.sdb.is_revoked(scode):
                return self._error(environ, start_response,
                                   error="access_denied",
                                   descr="Token is revoked")

            _sinfo = self.sdb[scode]

            try:
                aresp["scope"] = areq["scope"]
            except KeyError:
                pass

            _log_debug("_dic: %s" % _sinfo)

            rtype = set(areq["response_type"][:])
            if "code" in areq["response_type"]:
                if issue_new_code:
                    scode = self.sdb.duplicate(_sinfo)
                    _sinfo = self.sdb[scode]

                _code = aresp["code"] = _sinfo["code"]
                rtype.remove("code")
            else:
                self.sdb[scode]["code"] = None
                _code = None

            if "token" in areq["response_type"]:
                _dic = self.sdb.update_to_token(issue_refresh=False,
                                                key=scode)

                _log_debug("_dic: %s" % _dic)
                for key, val in _dic.items():
                    if key in aresp.parameters() and val is not None:
                        aresp[key] = val

                rtype.remove("token")

            try:
                _access_token = aresp["access_token"]
            except KeyError:
                _access_token = None

            if "id_token" in areq["response_type"]:
                user_info = self.userinfo_in_id_token_claims(_sinfo)

                id_token = self.sign_encrypt_id_token(_sinfo, client_info, areq,
                                                     code=_code,
                                                     access_token=_access_token,
                                                     user_info=user_info)

                aresp["id_token"] = id_token
                _sinfo["id_token"] = id_token
                rtype.remove("id_token")

            if len(rtype):
                resp = BadRequest("Unknown response type")
                return resp(environ, start_response)

        (redirect_uri, reply) = self.get_redirect_uri(areq)
        if reply: # shouldn't happen but want to be on the safe side
            return reply(environ, start_response)

        location = aresp.request(redirect_uri)

        logger.debug("Redirected to: '%s' (%s)" % (location, type(location)))

        if self.cookie_func and not "active_auth" in kwargs:
            try:
                (key, timestamp) = kwargs["handle"]
                b64scode = base64.b64encode(scode)
                self.re_link_log(key, b64scode)
                cookie = self.cookie_func(self.cookie_name, b64scode, self.seed,
                                          self.cookie_ttl)
                redirect = Redirect(str(location), headers=[cookie])
            except TypeError:
                redirect = Redirect(str(location))
        else:
            redirect = Redirect(str(location))

        return redirect(environ, start_response)


    #noinspection PyUnusedLocal
    def re_link_log(self, old, new):
        pass

    def key_setup(self, local_path, vault="keys", sig=None, enc=None):
        # my keys

        part, res = key_export(self.baseurl, local_path, vault, self.keyjar,
                               fqdn=self.hostname, sig=sig, enc=enc)

        for name, url in res.items():
            self.jwk.append(url)

# -----------------------------------------------------------------------------

class Endpoint(object):
    type = ""
    def __init__(self, func):
        self.func = func

    @property
    def name(self):
        return "%s_endpoint" % self.type

    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)

class AuthorizationEndpoint(Endpoint):
    type = "authorization"

class TokenEndpoint(Endpoint):
    type = "token"

class UserinfoEndpoint(Endpoint):
    type = "userinfo"

class RegistrationEndpoint(Endpoint) :
    type = "registration"