#!/usr/bin/env python
import hashlib
import logging
import os
import sys
import traceback

import six

from oic.exception import FailedAuthentication
from oic.exception import InvalidRequest
from oic.exception import MissingParameter
from oic.exception import ParameterError
from oic.exception import RedirectURIError
from oic.exception import UnknownClient
from oic.exception import URIError
from oic.oauth2 import Server
from oic.oauth2 import rndstr
from oic.oauth2.message import AccessTokenRequest
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import AuthorizationErrorResponse
from oic.oauth2.message import AuthorizationRequest
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import ErrorResponse
from oic.oauth2.message import MissingRequiredAttribute
from oic.oauth2.message import MissingRequiredValue
from oic.oauth2.message import NoneResponse
from oic.oauth2.message import TokenErrorResponse
from oic.oauth2.message import add_non_standard
from oic.oauth2.message import by_schema
from oic.utils.authn.user import NoSuchAuthentication
from oic.utils.authn.user import TamperAllert
from oic.utils.authn.user import ToOld
from oic.utils.http_util import BadRequest
from oic.utils.http_util import CookieDealer
from oic.utils.http_util import Redirect
from oic.utils.http_util import Response
from oic.utils.http_util import make_cookie
from oic.utils.sdb import AccessCodeUsed
from oic.utils.sdb import AuthnEvent
from six.moves.urllib import parse as urlparse

if six.PY3:
    from urllib.parse import splitquery
else:
    from urllib import splitquery

__author__ = 'rohe0002'

logger = logging.getLogger(__name__)
LOG_INFO = logger.info
LOG_DEBUG = logger.debug


class Endpoint(object):
    """
    Endpoint class

    @var etype: Endpoint type
    @url: Relative part of the url (will be joined with server.baseurl)
    """
    etype = ""
    url = ""

    def __init__(self, func=None):
        self.func = func


class AuthorizationEndpoint(Endpoint):
    etype = "authorization"
    url = "authorization"


class TokenEndpoint(Endpoint):
    etype = "token"
    url = "token"


def endpoint_ava(endp, baseurl):
    key = '{}_endpoint'.format(endp.etype)
    val = urlparse.urljoin(baseurl, endp.url)
    return {key: val}


def code_response(**kwargs):
    _areq = kwargs["areq"]
    _scode = kwargs["scode"]
    aresp = AuthorizationResponse()
    try:
        aresp["state"] = _areq["state"]
    except KeyError:
        pass
    aresp["code"] = _scode
    add_non_standard(_areq, aresp)
    return aresp


def token_response(**kwargs):
    _areq = kwargs["areq"]
    _scode = kwargs["scode"]
    _sdb = kwargs["sdb"]
    _dic = _sdb.upgrade_to_token(_scode, issue_refresh=False)

    aresp = AccessTokenResponse(**by_schema(AccessTokenResponse, **_dic))

    try:
        aresp["state"] = _areq["state"]
    except KeyError:
        pass

    add_non_standard(_areq, aresp)
    return aresp


# noinspection PyUnusedLocal
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


def max_age(areq):
    try:
        return areq["request"]["max_age"]
    except KeyError:
        try:
            return areq["max_age"]
        except KeyError:
            return 0


def re_authenticate(areq, authn):
    if "prompt" in areq and "login" in areq["prompt"]:
        if authn.done(areq):
            return True

    return False


class Provider(object):
    endp = [AuthorizationEndpoint, TokenEndpoint]

    def __init__(self, name, sdb, cdb, authn_broker, authz, client_authn,
                 symkey="", urlmap=None, iv=0, default_scope="",
                 ca_bundle=None, verify_ssl=True, default_acr=""):
        self.name = name
        self.sdb = sdb
        self.cdb = cdb
        self.server = Server(ca_certs=ca_bundle, verify_ssl=verify_ssl)

        self.authn_broker = authn_broker
        if authn_broker is None:
            # default cookie function
            self.cookie_func = CookieDealer(srv=self).create_cookie
        else:
            self.cookie_func = self.authn_broker[0][0].create_cookie
            for item in self.authn_broker:
                item.srv = self

        self.authz = authz
        self.client_authn = client_authn
        self.symkey = symkey
        self.seed = rndstr().encode("utf-8")
        self.iv = iv or os.urandom(16)
        self.cookie_name = "pyoidc"
        self.default_scope = default_scope
        self.sso_ttl = 0
        self.default_acr = default_acr

        if urlmap is None:
            self.urlmap = {}
        else:
            self.urlmap = urlmap

        self.response_type_map = {
            "code": code_response,
            "token": token_response,
            "none": none_response,
        }

        self.session_cookie_name = "pyoic_session"

    # def authn_reply(self, areq, aresp, bsid, **kwargs):
    #     """
    #
    #     :param areq: Authorization Request
    #     :param aresp: Authorization Response
    #     :param bsid: Session id
    #     :param kwargs: Additional keyword args
    #     :return:
    #     """
    #     if "redirect_uri" in areq:
    #         # TODO verify that the uri is reasonable
    #         redirect_uri = areq["redirect_uri"]
    #     else:
    #         redirect_uri = self.urlmap[areq["client_id"]]
    #
    #     location = location_url(areq["response_type"], redirect_uri,
    #                             aresp.to_urlencoded())
    #
    #     LOG_DEBUG("Redirected to: '%s' (%s)" % (location, type(location)))
    #
    #     # set cookie containing session ID
    #
    #     cookie = make_cookie(self.cookie_name, bsid, self.seed)
    #
    #     return Redirect(str(location), headers=[cookie])
    #
    # def authn_response(self, areq, **kwargs):
    #     """
    #
    #     :param areq: Authorization request
    #     :param kwargs: Extra keyword arguments
    #     :return:
    #     """
    #     scode = kwargs["code"]
    #     areq["response_type"].sort()
    #     _rtype = " ".join(areq["response_type"])
    #     return self.response_type_map[_rtype](areq=areq, scode=scode,
    #                                           sdb=self.sdb)

    @staticmethod
    def input(query="", post=None):
        # Support GET and POST
        if query:
            return query
        elif post:
            return post
        else:
            raise MissingParameter("No input")

    @staticmethod
    def _error_response(error, descr=None):
        logger.error("%s" % error)
        response = ErrorResponse(error=error, error_description=descr)
        return Response(response.to_json(), content="application/json",
                        status="400 Bad Request")

    @staticmethod
    def _error(error, descr=None):
        response = ErrorResponse(error=error, error_description=descr)
        return Response(response.to_json(), content="application/json",
                        status="400 Bad Request")

    @staticmethod
    def _authz_error(error, descr=None):

        response = AuthorizationErrorResponse(error=error)
        if descr:
            response["error_description"] = descr

        return Response(response.to_json(), content="application/json",
                        status="400 Bad Request")

    @staticmethod
    def _redirect_authz_error(error, redirect_uri, descr=None, state="",
                              return_type=None):
        err = AuthorizationErrorResponse(error=error)
        if descr:
            err["error_description"] = descr
        if state:
            err["state"] = state
        if return_type is None or return_type == ["code"]:
            location = err.request(redirect_uri)
        else:
            location = err.request(redirect_uri, True)
        return Redirect(location)

    def _verify_redirect_uri(self, areq):
        """
        MUST NOT contain a fragment
        MAY contain query component

        :return: An error response if the redirect URI is faulty otherwise
            None
        """
        try:
            _redirect_uri = urlparse.unquote(areq["redirect_uri"])

            part = urlparse.urlparse(_redirect_uri)
            if part.fragment:
                raise URIError("Contains fragment")

            (_base, _query) = splitquery(_redirect_uri)
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
                    # and vice versa, every query component in the redirect_uri
                    # must be registered
                    if _query:
                        if rquery is None:
                            raise ValueError
                        for key, vals in _query.items():
                            assert key in rquery
                            for val in vals:
                                assert val in rquery[key]
                    match = True
                    break
            if not match:
                raise RedirectURIError("Doesn't match any registered uris")
            # ignore query components that are not registered
            return None
        except Exception as err:
            logger.error("Faulty redirect_uri: %s" % areq["redirect_uri"])
            try:
                _cinfo = self.cdb[areq["client_id"]]
            except KeyError:
                logger.info("Unknown client: %s" % areq["client_id"])
                raise UnknownClient(areq["client_id"])
            else:
                logger.info("Registered redirect_uris: %s" % _cinfo)
                raise RedirectURIError(
                    "Faulty redirect_uri: %s" % areq["redirect_uri"])

    def get_redirect_uri(self, areq):
        """ verify that the redirect URI is reasonable

        :param areq: The Authorization request
        :return: Tuple of (redirect_uri, Response instance)
            Response instance is not None of matching redirect_uri failed
        """
        if 'redirect_uri' in areq:
            self._verify_redirect_uri(areq)
            uri = areq["redirect_uri"]
        else:
            raise ParameterError(
                "Missing redirect_uri and more than one or none registered")

        return uri

    def pick_auth(self, areq, comparision_type=""):
        """

        :param areq: AuthorizationRequest instance
        :param comparision_type: How to pick the authentication method
        :return: An authentication method and its authn class ref
        """
        if comparision_type == "any":
            return self.authn_broker[0]

        try:
            if len(self.authn_broker) == 1:
                return self.authn_broker[0]
            elif "acr_values" in areq:
                if not comparision_type:
                    comparision_type = "exact"

                if not isinstance(areq["acr_values"], list):
                    areq["acr_values"] = [areq["acr_values"]]

                for acr in areq["acr_values"]:
                    res = self.authn_broker.pick(acr, comparision_type)
                    logger.debug("Picked AuthN broker for ACR %s: %s" % (
                        str(acr), str(res)))
                    if res:
                        # Return the best guess by pick.
                        return res[0]
            else:  # same as any
                try:
                    acrs = areq["claims"]["id_token"]["acr"]["values"]
                except KeyError:
                    return self.authn_broker[0]
                else:
                    for acr in acrs:
                        res = self.authn_broker.pick(acr, comparision_type)
                        logger.debug("Picked AuthN broker for ACR %s: %s" % (
                            str(acr), str(res)))
                        if res:
                            # Return the best guess by pick.
                            return res[0]

        except KeyError as exc:
            logger.debug(
                "An error occured while picking the authN broker: %s" % str(
                    exc))

        # return the best I have
        return None, None

    def auth_init(self, request, request_class=AuthorizationRequest):
        """

        :param request: The AuthorizationRequest
        :return:
        """
        logger.debug("Request: '%s'" % request)
        # Same serialization used for GET and POST
        try:
            areq = self.server.parse_authorization_request(
                request=request_class, query=request)
        except (MissingRequiredValue, MissingRequiredAttribute) as err:
            logger.debug("%s" % err)
            areq = request_class().deserialize(request, "urlencoded")
            try:
                redirect_uri = self.get_redirect_uri(areq)
            except (RedirectURIError, ParameterError) as err:
                return self._error("invalid_request", "%s" % err)
            try:
                _rtype = areq["response_type"]
            except:
                _rtype = ["code"]
            return self._redirect_authz_error("invalid_request", redirect_uri,
                                              "%s" % err, areq["state"],
                                              _rtype)
        except KeyError:
            areq = request_class().deserialize(request, "urlencoded")
            # verify the redirect_uri
            try:
                self.get_redirect_uri(areq)
            except (RedirectURIError, ParameterError) as err:
                return self._error("invalid_request", "%s" % err)
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            logger.debug("Bad request: %s (%s)" % (err, err.__class__.__name__))
            return BadRequest("%s" % err)

        if not areq:
            logger.debug("No AuthzRequest")
            return self._error("invalid_request", "Can not parse AuthzRequest")

        logger.debug("AuthzRequest: %s" % (areq.to_dict(),))
        try:
            redirect_uri = self.get_redirect_uri(areq)
        except (RedirectURIError, ParameterError, UnknownClient) as err:
            return self._error("invalid_request", "%s" % err)

        try:
            keyjar = self.keyjar
        except AttributeError:
            keyjar = ""

        try:
            # verify that the request message is correct
            areq.verify(keyjar=keyjar, opponent_id=areq["client_id"])
        except (MissingRequiredAttribute, ValueError) as err:
            return self._redirect_authz_error("invalid_request", redirect_uri,
                                              "%s" % err)

        return {"areq": areq, "redirect_uri": redirect_uri}

    @staticmethod
    def _acr_claims(areq):
        try:
            acrdef = areq["claims"]["id_token"]["acr"]
        except KeyError:
            return None
        else:
            if isinstance(acrdef, dict):
                try:
                    return [acrdef["value"]]
                except KeyError:
                    try:
                        return acrdef["values"]
                    except KeyError:
                        pass

        return None

    def do_auth(self, areq, redirect_uri, cinfo, request, cookie, **kwargs):
        """

        :param areq:
        :param redirect_uri:
        :param cinfo:
        :param request:
        :param cookie:
        :param authn:
        :param kwargs:
        :return:
        """
        acrs = self._acr_claims(areq)
        if acrs:
            # If acr claims are present the picked acr value MUST match
            # one of the given
            tup = (None, None)
            for acr in acrs:
                res = self.authn_broker.pick(acr, "exact")
                logger.debug("Picked AuthN broker for ACR %s: %s" % (
                    str(acr), str(res)))
                if res:  # Return the best guess by pick.
                    tup = res[0]
                    break
            authn, authn_class_ref = tup
        else:
            authn, authn_class_ref = self.pick_auth(areq)
            if not authn:
                authn, authn_class_ref = self.pick_auth(areq, "better")
                if not authn:
                    authn, authn_class_ref = self.pick_auth(areq, "any")

        if authn is None:
            return self._redirect_authz_error("access_denied", redirect_uri,
                                              return_type=areq["response_type"])

        try:
            try:
                _auth_info = kwargs["authn"]
            except KeyError:
                _auth_info = ""

            if "upm_answer" in areq and areq["upm_answer"] == "true":
                _max_age = 0
            else:
                _max_age = max_age(areq)

            identity, _ts = authn.authenticated_as(
                cookie, authorization=_auth_info, max_age=_max_age)
        except (NoSuchAuthentication, TamperAllert):
            identity = None
            _ts = 0
        except ToOld:
            logger.info("Too old authentication")
            identity = None
            _ts = 0
        else:
            logger.info("No active authentication")

        # gather information to be used by the authentication method
        authn_args = {"query": request,
                      "authn_class_ref": authn_class_ref}

        if "req_user" in kwargs:
            authn_args["as_user"] = kwargs["req_user"],

        for attr in ["policy_uri", "logo_uri", "tos_uri"]:
            try:
                authn_args[attr] = cinfo[attr]
            except KeyError:
                pass

        for attr in ["ui_locales", "acr_values"]:
            try:
                authn_args[attr] = areq[attr]
            except KeyError:
                pass

        # To authenticate or Not
        if identity is None:  # No!
            if "prompt" in areq and "none" in areq["prompt"]:
                # Need to authenticate but not allowed
                return self._redirect_authz_error(
                    "login_required", redirect_uri,
                    return_type=areq["response_type"])
            else:
                return authn(**authn_args)
        else:
            if re_authenticate(areq, authn):
                # demand re-authentication
                return authn(**authn_args)
            else:
                # I get back a dictionary
                user = identity["uid"]
                if "req_user" in kwargs:
                    sids_for_sub = self.sdb.get_sids_by_sub(kwargs["req_user"])
                    if sids_for_sub and user != self.sdb.get_authentication_event(
                            sids_for_sub[-1]).uid:
                        logger.debug("Wanted to be someone else!")
                        if "prompt" in areq and "none" in areq["prompt"]:
                            # Need to authenticate but not allowed
                            return self._redirect_authz_error("login_required",
                                                              redirect_uri)
                        else:
                            return authn(**authn_args)

        authn_event = AuthnEvent(identity["uid"], identity.get('salt', ''),
                                 authn_info=authn_class_ref,
                                 time_stamp=_ts)

        return {"authn_event": authn_event, "identity": identity, "user": user}

    def setup_session(self, areq, authn_event, cinfo):
        sid = self.sdb.create_authz_session(authn_event, areq)
        self.sdb.do_sub(sid, '')
        return sid

    def authorization_endpoint(self, request="", cookie="", **kwargs):
        """ The AuthorizationRequest endpoint

        :param request: The client request
        """

        info = self.auth_init(request)
        if isinstance(info, Response):
            return info

        _cid = info["areq"]["client_id"]
        cinfo = self.cdb[_cid]

        authnres = self.do_auth(info["areq"], info["redirect_uri"],
                                cinfo, request, cookie, **kwargs)

        if isinstance(authnres, Response):
            return authnres

        logger.debug("- authenticated -")
        logger.debug("AREQ keys: %s" % info["areq"].keys())

        sid = self.setup_session(info["areq"], authnres["authn_event"],
                                 cinfo)

        return self.authz_part2(authnres["user"], info["areq"], sid,
                                cookie=cookie)

    def aresp_check(self, aresp, areq):
        return ""

    def create_authn_response(self, areq, sid):
        rtype = areq["response_type"][0]
        _func = self.response_type_map[rtype]
        aresp = _func(areq=areq, scode=self.sdb[sid]["code"], sdb=self.sdb)

        if rtype == "code":
            fragment_enc = False
        else:
            fragment_enc = True

        return aresp, fragment_enc

    def response_mode(self, areq, fragment_enc, **kwargs):
        resp_mode = areq["response_mode"]

        if resp_mode == 'fragment' and not fragment_enc:
            # Can't be done
            raise InvalidRequest("wrong response_mode")
        elif resp_mode == 'query' and fragment_enc:
            # Can't be done
            return InvalidRequest("wrong response_mode")
        return None

    def authz_part2(self, user, areq, sid, **kwargs):
        """
        After the authentication this is where you should end up

        :param user:
        :param areq: The Authorization Request
        :param sid: Session key
        :param kwargs: possible other parameters
        :return: A redirect to the redirect_uri of the client
        """
        result = self._complete_authz(user, areq, sid, **kwargs)
        if isinstance(result, Response):
            return result
        else:
            aresp, headers, redirect_uri, fragment_enc = result

        # Just do whatever is the default
        location = aresp.request(redirect_uri, fragment_enc)
        logger.debug("Redirected to: '%s' (%s)" % (location, type(location)))
        return Redirect(str(location), headers=headers)

    def _complete_authz(self, user, areq, sid, **kwargs):
        _log_debug = logger.debug
        _log_debug("- in authenticated() -")

        # Do the authorization
        try:
            permission = self.authz(user, client_id=areq['client_id'])
            self.sdb.update(sid, "permission", permission)
        except Exception:
            raise

        _log_debug("response type: %s" % areq["response_type"])

        if self.sdb.is_revoked(sid):
            return self._error(error="access_denied",
                               descr="Token is revoked")

        info = self.create_authn_response(areq, sid)
        if isinstance(info, Response):
            return info
        else:
            aresp, fragment_enc = info

        try:
            redirect_uri = self.get_redirect_uri(areq)
        except (RedirectURIError, ParameterError) as err:
            return BadRequest("%s" % err)

        # Must not use HTTP unless implicit grant type and native application

        info = self.aresp_check(aresp, areq)
        if isinstance(info, Response):
            return info

        headers = []
        try:
            _kaka = kwargs["cookie"]
        except KeyError:
            pass
        else:
            if _kaka and self.cookie_name not in _kaka:  # Don't overwrite cookie
                headers.append(
                    self.cookie_func(user, typ="sso", ttl=self.sso_ttl))

        # Now about the response_mode. Should not be set if it's obvious
        # from the response_type. Knows about 'query', 'fragment' and
        # 'form_post'.

        if "response_mode" in areq:
            try:
                resp = self.response_mode(areq, fragment_enc, aresp=aresp,
                                          redirect_uri=redirect_uri,
                                          headers=headers)
            except InvalidRequest as err:
                return self._error("invalid_request", err)
            else:
                if resp is not None:
                    return resp

        return aresp, headers, redirect_uri, fragment_enc

    def token_scope_check(self, areq, info):
        """ Not implemented here """
        # if not self.subset(areq["scope"], _info["scope"]):
        # LOG_INFO("Asked for scope which is not subset of previous defined")
        # err = TokenErrorResponse(error="invalid_scope")
        #     return Response(err.to_json(), content="application/json")
        return None

    def token_endpoint(self, authn="", **kwargs):
        """
        This is where clients come to get their access tokens
        """

        _sdb = self.sdb

        LOG_DEBUG("- token -")
        body = kwargs["request"]
        LOG_DEBUG("body: %s" % body)

        areq = AccessTokenRequest().deserialize(body, "urlencoded")

        try:
            client = self.client_authn(self, areq, authn)
        except FailedAuthentication as err:
            err = TokenErrorResponse(error="unauthorized_client",
                                     error_description="%s" % err)
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        LOG_DEBUG("AccessTokenRequest: %s" % areq)

        try:
            assert areq["grant_type"] == "authorization_code"
        except AssertionError:
            err = TokenErrorResponse(error="invalid_request",
                                     error_description="Wrong grant type")
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        # assert that the code is valid
        _info = _sdb[areq["code"]]

        resp = self.token_scope_check(areq, _info)
        if resp:
            return resp

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _info:
            assert areq["redirect_uri"] == _info["redirect_uri"]

        try:
            _tinfo = _sdb.upgrade_to_token(areq["code"])
        except AccessCodeUsed:
            err = TokenErrorResponse(error="invalid_grant",
                                     error_description="Access grant used")
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        LOG_DEBUG("_tinfo: %s" % _tinfo)

        atr = AccessTokenResponse(**by_schema(AccessTokenResponse, **_tinfo))

        LOG_DEBUG("AccessTokenResponse: %s" % atr)

        return Response(atr.to_json(), content="application/json")

    def verify_endpoint(self, request="", cookie=None, **kwargs):
        _req = urlparse.parse_qs(request)
        try:
            areq = urlparse.parse_qs(_req["query"][0])
        except KeyError:
            return BadRequest()

        authn, acr = self.pick_auth(areq=areq)
        kwargs["cookie"] = cookie
        return authn.verify(_req, **kwargs)

    def write_session_cookie(self, value):
        return make_cookie(self.session_cookie_name, value, self.seed, path="/")

    def delete_session_cookie(self):
        return make_cookie(self.session_cookie_name, "", b"", path="/",
                           expire=-1)

    def _compute_session_state(self, state, salt, client_id, redirect_uri):
        parsed_uri = urlparse.urlparse(redirect_uri)
        rp_origin_url = "{uri.scheme}://{uri.netloc}".format(uri=parsed_uri)
        session_str = client_id + " " + rp_origin_url + " " + state + " " + salt
        return hashlib.sha256(session_str.encode("utf-8")).hexdigest() + "." + salt
