#!/usr/bin/env python

__author__ = 'rohe0002'

import random
import base64

from urlparse import parse_qs

from oic.oauth2.provider import Provider as AProvider

from oic.utils.http_util import *
from oic.utils import time_util

from oic.oauth2 import MissingRequiredAttribute
from oic.oauth2 import rndstr
from oic.oauth2.provider import AuthnFailure
from oic.oauth2.message import by_schema
from oic.oauth2.message import SCHEMA as OA2_SCHEMA

from oic.oic import Server

from oic.oic.message import msg_deser
from oic.oic.message import SCOPE2CLAIMS
from oic.oic.message import message
from oic.oic.message import SCHEMA
from oic.oic import JWT_BEARER

class OICError(Exception):
    pass

class MissingAttribute(OICError):
    pass

class UnsupportedMethod(OICError):
    pass

class AccessDenied(OICError):
    pass

class UnknownClient(OICError):
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

    aresp = message("AuthorizationResponse")

    for key in ["state", "nonce", "scope"]:
        try:
            aresp[key] = _areq[key]
        except KeyError:
            pass

    aresp["code"] = _scode

    _dic = _sdb.update_to_token(_scode, issue_refresh=False)
    for prop in SCHEMA["AccessTokenResponse"]["param"].keys():
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

ACR_LISTS = [
    ["0", "1", "2", "3", "4"],
]

def verify_acr_level(req, level):
    if req is None:
        return level
    elif req == {"optional": True}:
        return level
    else:
        for _r in req["values"]:
            for alist in ACR_LISTS:
                try:
                    if alist.index(_r) <= alist.index(level):
                        return level
                except ValueError:
                    pass

    raise AccessDenied

class Provider(AProvider):
    def __init__(self, name, sdb, cdb, function, userdb, urlmap=None,
                 debug=0, cache=None, timeout=None, proxy_info=None,
                 follow_redirects=True, ca_certs="", jwt_keys=None):

        AProvider.__init__(self, name, sdb, cdb, function, urlmap, debug)

        self.server = Server(jwt_keys=jwt_keys, cache=cache,
                                   time_out=timeout, proxy_info=proxy_info,
                                   follow_redirects=follow_redirects,
                                   ca_certs=ca_certs)
        self.keystore = self.server.keystore
        self.http = self.server.http

        self.userdb = userdb

        self.function = function
        self.endpoints = []
        self.baseurl = ""
        self.cert = []
        self.jwk = []
        self.cookie_func = None
        self.cookie_name = "pyoidc"
        self.seed = ""
        self.cookie_ttl = 0

    def _id_token(self, session, loa="2", info_log=None,
                  signature="symmetric"):
        #defaults
        inawhile = {"days": 1}
        # Handle the idtoken_claims
        extra = {}
        try:
            oidreq = msg_deser(session["oidreq"], "json", "OpenIDRequest")
            itc = oidreq["id_token"]
            info_log("ID Token claims: %s" % itc.to_dict())
            try:
                inawhile = {"seconds": itc["max_age"]}
            except KeyError:
                inawhile = {}
            if "claims" in itc:
                for key, val in itc["claims"].items():
                    if key == "auth_time":
                        extra["auth_time"] = time_util.utc_time_sans_frac()
                    elif key == "acr":
                        #["2","http://id.incommon.org/assurance/bronze"]
                        extra["acr"] = verify_acr_level(val, loa)
        except KeyError:
            pass

        idt = message("IdToken", iss=self.name, user_id=session["user_id"],
                      aud = session["client_id"],
                      exp = time_util.epoch_in_a_while(**inawhile), acr=loa)

        for key, val in extra.items():
            idt[key] = val

        if "nonce" in session:
            idt.nonce = session["nonce"]

        # sign with clients secret key
        _keystore = self.keystore
        if signature == "symmetric":
            ckey = _keystore.get_keys("sign", owner=session["client_id"])
        else: # own asymmetric key
            ckey = _keystore.get_sign_key()

        if info_log:
            info_log("Sign idtoken with '%s'" % ckey)

        return idt.to_jwt(key=ckey)

    def _error(self, environ, start_response, error, descr=None):
        response = message(OA2_SCHEMA["ErrorResponse"], error=error,
                           error_description=descr)
        resp = Response(response.to_json(), content="application/json")
        return resp(environ, start_response)

    def _authz_error(self, environ, start_response, error, descr=None):
        response = message("AuthorizationErrorResponse", error=error,
                           error_description=descr)
        
        resp = Response(response.to_json(), content="application/json")
        return resp(environ, start_response)

    def authorization_endpoint(self, environ, start_response, logger,
                               **kwargs):
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
            areq = self.server.parse_authorization_request(query=query)
        except MissingRequiredAttribute, err:
            resp = BadRequest("%s" % err)
            return resp(environ, start_response)
        except Exception,err:
            resp = BadRequest("%s" % err)
            return resp(environ, start_response)


        if "prompt" in areq:
            if self.debug:
                _log_info("Prompt: '%s'" % areq["prompt"])

            if "none" in areq["prompt"]:
                if len(areq["prompt"]) > 1:
                    return self._error(environ, start_response,
                                       "invalid_request")
                else:
                    return self._authz_error(environ, start_response,
                                             "login_required")


        if areq["client_id"] not in self.cdb:
            raise UnknownClient(areq["client_id"])

        # verify that the redirect URI is resonable
        if "redirect_uri" in areq:
            try:
                assert areq["redirect_uri"] in self.cdb[
                                            areq["client_id"]]["redirect_uris"]
            except AssertionError:
                return self._authz_error(environ, start_response,
                                         "invalid_request_redirect_uri")

        if self.debug:
            _log_info("AREQ keys: %s" % areq.keys())
        # Is there an request decode it
        openid_req = None
        if "request" in areq or "request_uri" in areq:
            if self.debug:
                _log_info("OpenID request")
            try:
                _keystore = self.server.keystore
                jwt_key = _keystore.get_keys("verify", owner=None)
            except KeyError: # TODO
                raise KeyError("Missing verifying key")
        
            if "request" in areq:
                try:
                    openid_req = message("OpenIDRequest").from_jwt(
                                                                areq["request"],
                                                                jwt_key)
                except Exception:
                    return self._authz_error(environ, start_response,
                                             "invalid_openid_request_object")

            elif "request_uri" in areq:
                # Do a HTTP get
                _req = self.http.request(areq["request_uri"])
                if not _req:
                    return self._authz_error(environ, start_response,
                                             "invalid_request_uri")

                try:
                    openid_req = message("OpenIDRequest").from_jwt(_req,
                                                                  jwt_key)
                except Exception:
                    return self._authz_error(environ, start_response,
                                             "invalid_openid_request_object")

        # Store session info
        sid = _sdb.create_authz_session("", areq, oidreq=openid_req)
        if self.debug:
            _log_info("session: %s" % _sdb[sid])

        bsid = base64.b64encode(sid)
        _log_info("SID:%s" % bsid)

        if openid_req:
            try:
                _max_age = openid_req["id_token"]["max_age"]
            except KeyError:
                _max_age = -1

            if _max_age >= 0:
                if "handle" in kwargs:
                    try:
                        (b64sid, timestamp) = kwargs["handle"]
                        if (int(time.time()) - int(timestamp)) <= _max_age:
                            _log_info("- SSO -")
                            _scode = base64.b64decode(b64sid)
                            user = self.sdb[_scode]["user_id"]
                            _sdb.update(sid, "user_id", user)
                            return self.authenticated(environ, start_response,
                                                      logger, active_auth=bsid,
                                                      areq=areq, user=user)
                    except ValueError:
                        pass
        else:
            if "handle" in kwargs:
                try:
                    (b64sid, timestamp) = kwargs["handle"]
                    _log_info("- SSO -")
                    _scode = base64.b64decode(b64sid)
                    user = self.sdb[_scode]["user_id"]
                    _sdb.update(sid, "user_id", user)
                    return self.authenticated(environ, start_response,
                                              logger, active_auth=bsid,
                                              areq=areq, user=user)
                except ValueError:
                    pass

        # DEFAULT: start the authentication process
        return self.function["authenticate"](environ, start_response, bsid)

    def verify_client(self, environ, areq, log_info=None):
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

            key_col = {areq["client_id"]:
                       self.keystore.get_verify_key(owner=areq["client_id"])}
            key_col.update({".":self.keystore.get_verify_key()})

            if log_info:
                log_info("key_col: %s" % (key_col,))

            bjwt = message("AuthnToken").from_jwt(areq["client_assertion"],
                                                 key_col)

            try:
                assert bjwt["iss"] == areq["client_id"] # Issuer = the client
                # Is this true bjwt.iss == areq.client_id
                assert str(bjwt["iss"]) in self.cdb # It's a client I know
                assert str(bjwt["aud"]) == geturl(environ, query=False)
                return True
            except AssertionError:
                pass

        return False

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

        areq = msg_deser(body, "urlencoded", "AccessTokenRequest")

        if self.debug:
            _log_info("environ: %s" % environ)

        if not self.verify_client(environ, areq, _log_info):
            _log_info("could not verify client")
            err = message("TokenErrorResponse", error="unathorized_client")
            resp = Unauthorized(err.to_json(), content="application/json")
            return resp(environ, start_response)

        if self.debug:
            _log_info("AccessTokenRequest: %s" % areq)

        assert areq["grant_type"] == "authorization_code"

        # assert that the code is valid
        _info = _sdb[areq["code"]]

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _info:
            assert areq["redirect_uri"] == _info["redirect_uri"]

        if self.debug:
            _log_info("All checks OK")

        if "id_token" not in _info and "openid" in _info["scope"]:
            try:
                _idtoken = self._id_token(_info, info_log=_log_info)
            except AccessDenied:
                return self._error(environ, start_response,
                                   error="access_denied")
        else:
            _idtoken = None

        try:
            _tinfo = _sdb.update_to_token(areq["code"], id_token=_idtoken)
        except Exception,err:
            _log_info("Error: %s" % err)
            raise

        if self.debug:
            _log_info("_tinfo: %s" % _tinfo)

        atr = message("AccessTokenResponse",
                      **by_schema(SCHEMA["AccessTokenResponse"], **_tinfo))

        if self.debug:
            _log_info("AccessTokenResponse: %s" % atr)

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

    #noinspection PyUnusedLocal
    def userinfo_endpoint(self, environ, start_response, logger, *args):

        # POST or GET
        try:
            query = get_or_post(environ)
        except UnsupportedMethod:
            resp = BadRequest("Unsupported method")
            return resp(environ, start_response)

        _log_info = logger.info

        _log_info("environ: %s" % environ)
        _log_info("userinfo_endpoint: %s" % query)
        if not query or "access_token" not in query:
            _token = self._bearer_auth(environ)
        else:
            uireq = self.server.parse_user_info_request(data=query)
            _log_info("user_info_request: %s" % uireq)
            _token = uireq["access_token"]

        # should be an access token
        typ, key = self.sdb.token.type_and_key(_token)
        _log_info("access_token type: '%s', key: '%s'" % (typ, key))

        try:
            assert typ == "T"
        except AssertionError:
            raise AuthnFailure("Wrong type of token")

        #logger.info("keys: %s" % self.sdb.keys())
        session = self.sdb[key]
        # Scope can translate to userinfo_claims

        uic = {}
        for scope in session["scope"]:
            try:
                claims = dict([(name, {"optional":True}) for name in
                                               SCOPE2CLAIMS[scope]])
                uic.update(claims)
            except KeyError:
                pass

        if "oidreq" in session:
            oidreq = msg_deser(session["oidreq"], "json", "OpenIDRequest")
            _log_info("OIDREQ: %s" % oidreq.to_dict())
            if "userinfo" in oidreq:
                userinfo_claims = oidreq["userinfo"]
                _claim = oidreq["userinfo"]["claims"]
                for key, val in uic.items():
                    if key not in _claim:
                        _claim[key] = val
            elif uic:
                userinfo_claims = message("UserInfoClaim", claims=uic)
            else:
                userinfo_claims = None
        elif uic:
            userinfo_claims = message("UserInfoClaim", claims=uic)
        else:
            userinfo_claims = None

        _log_info("userinfo_claim: %s" % userinfo_claims.to_dict())
        _log_info("userdb: %s" % self.userdb.keys())
        #logger.info("oidreq: %s[%s]" % (oidreq, type(oidreq)))
        info = self.function["userinfo"](self, self.userdb,
                                          session["user_id"],
                                          session["client_id"],
                                          userinfo_claims)

        _log_info("info: %s" % (info,))
        resp = Response(info.to_json(), content="application/json")
        return resp(environ, start_response)

    #noinspection PyUnusedLocal
    def check_session_endpoint(self, environ, start_response, logger, *args):

        try:
            info = get_or_post(environ)
        except UnsupportedMethod:
            resp = BadRequest("Unsupported method")
            return resp(environ, start_response)

        if not info:
            info = "id_token=%s" % self._bearer_auth(environ)

        idt = self.server.parse_check_session_request(query=info)

        resp = Response(idt.to_json(), content="application/json")
        return resp(environ, start_response)

    #noinspection PyUnusedLocal
    def check_id_endpoint(self, environ, start_response, logger, *args):

        try:
            info = get_or_post(environ)
        except UnsupportedMethod:
            resp = BadRequest("Unsupported method")
            return resp(environ, start_response)

        logger.info("environ: %s" % environ)
        logger.info("info: '%s'" % info)
        if not info:
            logger.info("HTTP_AUTHORIZATION: %s" %
                        environ["HTTP_AUTHORIZATION"])
            info = "access_token=%s" % self._bearer_auth(environ)

        logger.info("check_id_endpoint: query=%s" % info)
        idt = self.server.parse_check_id_request(query=info)

        resp = Response(idt.to_json(), content="application/json")
        return resp(environ, start_response)

    #noinspection PyUnusedLocal
    def registration_endpoint(self, environ, start_response, logger, *args):

        try:
            query = get_or_post(environ)
        except UnsupportedMethod:
            resp = BadRequest("Unsupported method")
            return resp(environ, start_response)

        request = msg_deser(query, "urlencoded", "RegistrationRequest")
        logger.info("RegistrationRequest:%s" % request.to_dict())

        _keystore = self.server.keystore
        if request["type"] == "client_associate":
            # create new id och secret
            client_id = rndstr(12)
            while client_id in self.cdb:
                client_id = rndstr(12)

            client_secret = secret(self.seed, client_id)
            self.cdb[client_id] = {
                "client_secret":client_secret
            }
            _cinfo = self.cdb[client_id]

            for key,val in request.items():
                _cinfo[key] = val

            self.keystore.load_keys(request, client_id)
            logger.info("KEYSTORE: %s" % self.keystore._store)

        elif request["type"] == "client_update":
            #  that these are an id,secret pair I know about
            client_id = request["client_id"]
            try:
                _cinfo = self.cdb[client_id]
            except KeyError:
                logger.info("Unknown client id")
                resp = BadRequest()
                return resp(environ, start_response)

            if _cinfo["client_secret"] != request["client_secret"]:
                logger.info("Wrong secret")
                resp = BadRequest()
                return resp(environ, start_response)

            # update secret
            client_secret = secret(self.seed, client_id)
            _cinfo["client_secret"] = client_secret

            old_key = request["client_secret"]
            _keystore.remove_key(old_key, client_id, type="hmac", usage="sign")
            _keystore.remove_key(old_key, client_id, type="hmac",
                                 usage="verify")

            for key,val in request.items():
                if key in ["client_id", "client_secret"]:
                    continue

                _cinfo[key] = val

            self.keystore.load_keys(request, client_id, replace=True)

        else:
            resp = BadRequest("Unknown request type: %s" % request.type)
            return resp(environ, start_response)

        # Add the key to the keystore

        _keystore.set_sign_key(client_secret, owner=client_id)
        _keystore.set_verify_key(client_secret, owner=client_id)

        # set expiration time
        _cinfo["registration_expires"] = time_util.time_sans_frac()+3600
        response = message("RegistrationResponse", client_id=client_id,
                           client_secret=client_secret,
                           expires_at=_cinfo["registration_expires"])

        logger.info("Registration response: %s" % response.to_dict())

        resp = Response(response.to_json(), content="application/json",
                        headers=[("Cache-Control", "no-store")])
        return resp(environ, start_response)

    #noinspection PyUnusedLocal
    def providerinfo_endpoint(self, environ, start_response, logger, *args):
        _response = message("ProviderConfigurationResponse",
            issuer=self.baseurl,
            token_endpoint_auth_types_supported=["client_secret_post",
                                                 "client_secret_basic",
                                                 "client_secret_jwt"],
            scopes_supported=["openid"],
            response_types_supported=["code", "token", "id_token",
                                      "code token", "code id_token",
                                      "token id_token", "code token id_token"],
            user_id_types_supported=["basic"],
            #request_object_algs_supported=["HS256"]
        )

        #keys = self.keystore.keys_by_owner(owner=".")
        for cert in self.cert:
            _response["x509_url"] = "%s%s" % (self.baseurl, cert)
        for jwk in self.jwk:
            _response["jwk_url"] = "%s%s" % (self.baseurl, jwk)

        if not self.baseurl.endswith("/"):
            self.baseurl += "/"
        logger.info("endpoints: %s" % self.endpoints)
        for endp in self.endpoints:
            logger.info("# %s, %s" % (endp, endp.name))
            _response[endp.name] = "%s%s" % (self.baseurl, endp.type)

        logger.info("provider_info_response: %s" % _response.to_dict())
        resp = Response(_response.to_json(), content="application/json",
                            headers=[("Cache-Control", "no-store")])
        return resp(environ, start_response)

    def authenticated(self, environ, start_response, logger, **kwargs):
        """
        After the authentication this is where you should end up
        """

        _log_info = logger.info

        if self.debug:
            _log_info("- in authenticated() -")

        if "active_auth" in kwargs:
            b64scode = kwargs["active_auth"]
            scode = base64.b64decode(b64scode)
            user = kwargs["user"]
            areq = kwargs["areq"]
        else:
            # parse the form
            #noinspection PyDeprecation
            dic = parse_qs(get_post(environ))
            _log_info("QS: %s" % dic)

            try:
                (verified, user) = self.function["verify_user"](dic)
                if not verified:
                    resp = Unauthorized("Wrong password")
                    return resp(environ, start_response)
            except AuthnFailure, err:
                resp = Unauthorized("%s" % (err,))
                return resp(environ, start_response)

            if self.debug:
                _log_info("verified user: %s" % user)

            try:
                # Use the session identifier to find the session information
                b64scode = dic["sid"][0]
                scode = base64.b64decode(b64scode)
                asession = self.sdb[scode]
            except KeyError:
                resp = BadRequest("Could not find session")
                return resp(environ, start_response)

            self.sdb.update(scode, "user_id", dic["login"][0])

            if self.debug:
                _log_info("asession[\"authzreq\"] = %s" % asession["authzreq"])
                #_log_info( "type: %s" % type(asession["authzreq"]))

            # pick up the original request
            areq = msg_deser(asession["authzreq"], "json",
                             "AuthorizationRequest")

            if self.debug:
                _log_info("areq: %s" % areq)


        # Do the authorization
        try:
            permission = self.function["authorize"](user)
            self.sdb.update(scode, "permission", permission)
        except Exception:
            raise

        _log_info("response type: %s" % areq["response_type"])

        # create the response
        aresp = message("AuthorizationResponse")
        try:
            aresp["state"] = areq["state"]
        except KeyError:
            pass

        if "response_type" in areq and \
                len(areq["response_type"]) == 1 and \
                "none" in areq["response_type"]:
            pass
        else:
            _sinfo = self.sdb[scode]

            try:
                aresp["scope"] = areq["scope"]
            except KeyError:
                pass

            if self.debug:
                _log_info("_dic: %s" % _sinfo)

            rtype = set(areq["response_type"][:])
            if "code" in areq["response_type"]:
                aresp["code"] = _sinfo["code"]
                rtype.remove("code")
            else:
                self.sdb[scode]["code"] = None

            if "id_token" in areq["response_type"]:
                id_token = self._id_token(_sinfo, info_log=_log_info)
                aresp["id_token"] = id_token
                _sinfo["id_token"] = id_token
                rtype.remove("id_token")

            if "token" in areq["response_type"]:
                _dic = self.sdb.update_to_token(issue_refresh=False,
                                                key=scode)

                if self.debug:
                    _log_info("_dic: %s" % _dic)
                for key, val in _dic.items():
                    if key in aresp.parameters():
                        aresp[key] = val

                rtype.remove("token")

            if len(rtype):
                resp = BadRequest("Unknown response type")
                return resp(environ, start_response)

        if "redirect_uri" in areq:
            assert areq["redirect_uri"] in self.cdb[
                                            areq["client_id"]]["redirect_uris"]
            redirect_uri = areq["redirect_uri"]
        else:
            redirect_uri = self.cdb[areq["client_id"]]["redirect_uris"][0]

        location = aresp.request(redirect_uri)

        if self.debug:
            _log_info("Redirected to: '%s' (%s)" % (location, type(location)))

        if self.cookie_func and not "active_auth" in kwargs:
            cookie = self.cookie_func(self.cookie_name, b64scode, self.seed,
                                      self.cookie_ttl)
            redirect = Redirect(str(location), headers=[cookie])
        else:
            redirect = Redirect(str(location))

        return redirect(environ, start_response)


# -----------------------------------------------------------------------------

class Endpoint(object):
    type = ""
    def __init__(self, func):
        self.func = func

    @property
    def name(self):
        return "%s_endpoint" % self.type

    def __call__(self, *args):
        return self.func(*args)

class AuthorizationEndpoint(Endpoint):
    type = "authorization"

class TokenEndpoint(Endpoint):
    type = "token"

class UserinfoEndpoint(Endpoint):
    type = "userinfo"

class CheckIDEndpoint(Endpoint):
    type = "check_id"

class RegistrationEndpoint(Endpoint) :
    type = "registration"