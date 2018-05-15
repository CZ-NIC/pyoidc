#!/usr/bin/env python
from future.backports.urllib.parse import splitquery
from future.backports.urllib.parse import unquote
from future.backports.urllib.parse import urljoin
from future.backports.urllib.parse import urlparse
from future.moves.urllib.parse import parse_qs

import hashlib
import logging
import os
import sys
import traceback
import warnings
from http.cookies import SimpleCookie

from six import PY2

from oic import rndstr
from oic.exception import AuthzError
from oic.exception import FailedAuthentication
from oic.exception import InvalidRequest
from oic.exception import MissingParameter
from oic.exception import ParameterError
from oic.exception import RedirectURIError
from oic.exception import UnknownClient
from oic.exception import UnSupported
from oic.exception import URIError
from oic.oauth2 import ErrorResponse
from oic.oauth2 import Server
from oic.oauth2 import error_response
from oic.oauth2 import none_response
from oic.oauth2 import redirect_authz_error
from oic.oauth2.message import AccessTokenRequest
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import AuthorizationRequest
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import Message
from oic.oauth2.message import MissingRequiredAttribute
from oic.oauth2.message import MissingRequiredValue
from oic.oauth2.message import TokenErrorResponse
from oic.oauth2.message import add_non_standard
from oic.oauth2.message import by_schema
from oic.utils.authn.user import NoSuchAuthentication
from oic.utils.authn.user import TamperAllert
from oic.utils.authn.user import ToOld
from oic.utils.clientdb import BaseClientDatabase
from oic.utils.http_util import OAUTH2_NOCACHE_HEADERS
from oic.utils.http_util import BadRequest
from oic.utils.http_util import CookieDealer
from oic.utils.http_util import Response
from oic.utils.http_util import SeeOther
from oic.utils.http_util import Unauthorized
from oic.utils.http_util import make_cookie
from oic.utils.sanitize import sanitize
from oic.utils.sdb import AccessCodeUsed
from oic.utils.sdb import AuthnEvent

__author__ = 'rohe0002'

logger = logging.getLogger(__name__)


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

    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)


class AuthorizationEndpoint(Endpoint):
    etype = "authorization"
    url = "authorization"


class TokenEndpoint(Endpoint):
    etype = "token"
    url = "token"


def endpoint_ava(endp, baseurl):
    key = '{}_endpoint'.format(endp.etype)
    val = urljoin(baseurl, endp.url)
    return {key: val}


def code_response(**kwargs):
    aresp = AuthorizationResponse()
    _areq = kwargs["areq"]
    try:
        aresp["state"] = _areq["state"]
    except KeyError:
        pass
    aresp["code"] = kwargs["scode"]
    # TODO Add 'iss' and 'client_id'
    if kwargs['myself']:
        aresp['iss'] = kwargs['myself']
    aresp['client_id'] = _areq['client_id']
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
                 symkey=None, urlmap=None, iv=0, default_scope="",
                 verify_ssl=True, default_acr="",
                 baseurl='', server_cls=Server, client_cert=None):
        self.name = name
        self.sdb = sdb
        if not isinstance(cdb, BaseClientDatabase):
            warnings.warn('ClientDatabase should be an instance of '
                          'oic.utils.clientdb.BaseClientDatabase to ensure proper API.')
        self.cdb = cdb
        self.server = server_cls(verify_ssl=verify_ssl, client_cert=client_cert)

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
        self.cookie_domain = ""
        self.cookie_path = ""
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
        self.baseurl = baseurl
        self.keyjar = None
        self.trace = None
        self.events = None

    @staticmethod
    def input(query="", post=None):
        # Support GET and POST
        if query:
            return query
        elif post:
            return post
        else:
            raise MissingParameter("No input")

    def endpoints(self):
        return [endp.url for endp in self.endp]

    def _verify_redirect_uri(self, areq):
        """
        MUST NOT contain a fragment
        MAY contain query component

        :return: An error response if the redirect URI is faulty otherwise
            None
        """
        try:
            _redirect_uri = unquote(areq["redirect_uri"])

            part = urlparse(_redirect_uri)
            if part.fragment:
                raise URIError("Contains fragment")

            (_base, _query) = splitquery(_redirect_uri)
            if _query:
                _query = parse_qs(_query)

            match = False
            for regbase, rquery in self.cdb[str(areq["client_id"])]["redirect_uris"]:
                # The URI MUST exactly match one of the Redirection URI
                if _base != regbase:
                    continue

                if not rquery and not _query:
                    match = True
                    break

                if not rquery or not _query:
                    continue

                # every registered query component must exist in the
                # redirect_uri
                is_match_query = True
                for key, vals in _query.items():
                    if key not in rquery:
                        is_match_query = False
                        break

                    for val in vals:
                        if val not in rquery[key]:
                            is_match_query = False
                            break

                    if not is_match_query:
                        break

                if not is_match_query:
                    continue

                match = True
                break

            if not match:
                raise RedirectURIError("Doesn't match any registered uris")
            # ignore query components that are not registered
            return None
        except Exception:
            logger.error("Faulty redirect_uri: %s" % areq["redirect_uri"])
            try:
                _cinfo = self.cdb[str(areq["client_id"])]
            except KeyError:
                try:
                    cid = areq["client_id"]
                except KeyError:
                    logger.error('No client id found')
                    raise UnknownClient('No client_id provided')
                else:
                    logger.info("Unknown client: %s" % cid)
                    raise UnknownClient(areq["client_id"])
            else:
                logger.info("Registered redirect_uris: %s" % sanitize(_cinfo))
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

    def filter_request(self, req):
        return req

    def auth_init(self, request, request_class=AuthorizationRequest):
        """

        :param request: The AuthorizationRequest
        :return:
        """
        logger.debug("Request: '%s'" % sanitize(request))
        # Same serialization used for GET and POST

        try:
            areq = self.server.parse_authorization_request(
                request=request_class, query=request)
        except (MissingRequiredValue, MissingRequiredAttribute,
                AuthzError) as err:
            logger.debug("%s" % err)
            areq = request_class()
            areq.lax = True
            if isinstance(request, dict):
                areq.from_dict(request)
            else:
                areq.deserialize(request, "urlencoded")
            try:
                redirect_uri = self.get_redirect_uri(areq)
            except (RedirectURIError, ParameterError, UnknownClient) as err:
                return error_response("invalid_request", "%s" % err)
            try:
                _rtype = areq["response_type"]
            except KeyError:
                _rtype = ["code"]
            try:
                _state = areq["state"]
            except KeyError:
                _state = ''

            return redirect_authz_error("invalid_request", redirect_uri,
                                        "%s" % err, _state, _rtype)
        except KeyError:
            areq = request_class().deserialize(request, "urlencoded")
            # verify the redirect_uri
            try:
                self.get_redirect_uri(areq)
            except (RedirectURIError, ParameterError) as err:
                return error_response("invalid_request", "%s" % err)
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            logger.debug("Bad request: %s (%s)" % (err, err.__class__.__name__))
            err = ErrorResponse(error='invalid_request',
                                error_description=str(err))
            return BadRequest(err.to_json(), content='application/json')

        if not areq:
            logger.debug("No AuthzRequest")
            return error_response("invalid_request", "Can not parse AuthzRequest")

        areq = self.filter_request(areq)

        if self.events:
            self.events.store('Protocol request', areq)

        try:
            _cinfo = self.cdb[areq['client_id']]
        except KeyError:
            logger.error(
                'Client ID ({}) not in client database'.format(
                    areq['client_id']))
            return error_response('unauthorized_client', 'unknown client')
        else:
            try:
                _registered = [set(rt.split(' ')) for rt in
                               _cinfo['response_types']]
            except KeyError:
                # If no response_type is registered by the client then we'll
                # code which it the default according to the OIDC spec.
                _registered = [{'code'}]

            _wanted = set(areq["response_type"])
            if _wanted not in _registered:
                return error_response("invalid_request", "Trying to use unregistered response_typ")

        logger.debug("AuthzRequest: %s" % (sanitize(areq.to_dict()),))
        try:
            redirect_uri = self.get_redirect_uri(areq)
        except (RedirectURIError, ParameterError, UnknownClient) as err:
            return error_response("invalid_request", "{}:{}".format(err.__class__.__name__, err))

        try:
            keyjar = self.keyjar
        except AttributeError:
            keyjar = ""

        try:
            # verify that the request message is correct
            areq.verify(keyjar=keyjar, opponent_id=areq["client_id"])
        except (MissingRequiredAttribute, ValueError,
                MissingRequiredValue) as err:
            return redirect_authz_error("invalid_request", redirect_uri,
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
            return redirect_authz_error("access_denied", redirect_uri,
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
        authn_args = {"authn_class_ref": authn_class_ref}
        # Can't be something like JSON because it can't contain '"'
        if isinstance(request, Message):
            authn_args["query"] = request.to_urlencoded()
        elif isinstance(request, dict):
            authn_args["query"] = Message(**request).to_urlencoded()
        else:
            authn_args["query"] = request

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
                return redirect_authz_error(
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
                    if sids_for_sub and user != \
                            self.sdb.get_authentication_event(
                                sids_for_sub[-1]).uid:
                        logger.debug("Wanted to be someone else!")
                        if "prompt" in areq and "none" in areq["prompt"]:
                            # Need to authenticate but not allowed
                            return redirect_authz_error("login_required",
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
        aresp = _func(areq=areq, scode=self.sdb[sid]["code"], sdb=self.sdb,
                      myself=self.baseurl)

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

        # Mix-Up mitigation
        aresp['iss'] = self.baseurl
        aresp['client_id'] = areq['client_id']

        # Just do whatever is the default
        location = aresp.request(redirect_uri, fragment_enc)
        logger.debug("Redirected to: '%s' (%s)" % (location, type(location)))
        return SeeOther(str(location), headers=headers)

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
            return error_response("access_denied", descr="Token is revoked")

        try:
            info = self.create_authn_response(areq, sid)
        except UnSupported as err:
            return error_response(*err.args)

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
            if _kaka:
                if isinstance(_kaka, dict):
                    for name, val in _kaka.items():
                        _c = SimpleCookie()
                        _c[name] = val
                        _x = _c.output()
                        if PY2:
                            _x = str(_x)
                        headers.append(tuple(_x.split(": ", 1)))
                else:
                    _c = SimpleCookie()
                    _c.load(_kaka)
                    for x in _c.output().split('\r\n'):
                        if PY2:
                            x = str(x)
                        headers.append(tuple(x.split(": ", 1)))

                if self.cookie_name not in _kaka:  # Don't overwrite
                    header = self.cookie_func(user, typ="sso", ttl=self.sso_ttl)
                    if header:
                        headers.append(header)
            else:
                header = self.cookie_func(user, typ="sso", ttl=self.sso_ttl)
                if header:
                    headers.append(header)

        # Now about the response_mode. Should not be set if it's obvious
        # from the response_type. Knows about 'query', 'fragment' and
        # 'form_post'.

        if "response_mode" in areq:
            try:
                resp = self.response_mode(areq, fragment_enc, aresp=aresp,
                                          redirect_uri=redirect_uri,
                                          headers=headers)
            except InvalidRequest as err:
                return error_response("invalid_request", str(err))
            else:
                if resp is not None:
                    return resp

        return aresp, headers, redirect_uri, fragment_enc

    def token_scope_check(self, areq, info):
        """ Not implemented here """
        # if not self.subset(areq["scope"], _info["scope"]):
        # logger.info("Asked for scope which is not subset of previous defined")
        # err = TokenErrorResponse(error="invalid_scope")
        #     return Response(err.to_json(), content="application/json")
        return None

    def token_endpoint(self, authn="", **kwargs):
        """
        This is where clients come to get their access tokens
        """

        _sdb = self.sdb

        logger.debug("- token -")
        body = kwargs["request"]
        logger.debug("body: %s" % sanitize(body))

        areq = AccessTokenRequest().deserialize(body, "urlencoded")

        try:
            self.client_authn(self, areq, authn)
        except FailedAuthentication as err:
            logger.error(err)
            err = TokenErrorResponse(error="unauthorized_client",
                                     error_description="%s" % err)
            return Response(err.to_json(), content="application/json", status_code=401)

        logger.debug("AccessTokenRequest: %s" % sanitize(areq))

        if areq["grant_type"] != "authorization_code":
            err = TokenErrorResponse(error="invalid_request", error_description="Wrong grant type")
            return Response(err.to_json(), content="application/json", status="401 Unauthorized")

        # assert that the code is valid
        _info = _sdb[areq["code"]]

        resp = self.token_scope_check(areq, _info)
        if resp:
            return resp

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _info and areq["redirect_uri"] != _info["redirect_uri"]:
            logger.error('Redirect_uri mismatch')
            err = TokenErrorResponse(error="unauthorized_client")
            return Unauthorized(err.to_json(), content="application/json")

        try:
            _tinfo = _sdb.upgrade_to_token(areq["code"], issue_refresh=True)
        except AccessCodeUsed:
            err = TokenErrorResponse(error="invalid_grant",
                                     error_description="Access grant used")
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        logger.debug("_tinfo: %s" % sanitize(_tinfo))

        atr = AccessTokenResponse(**by_schema(AccessTokenResponse, **_tinfo))

        logger.debug("AccessTokenResponse: %s" % sanitize(atr))

        return Response(atr.to_json(), content="application/json", headers=OAUTH2_NOCACHE_HEADERS)

    def verify_endpoint(self, request="", cookie=None, **kwargs):
        _req = parse_qs(request)
        try:
            areq = parse_qs(_req["query"][0])
        except KeyError:
            return BadRequest('Could not verify endpoint')

        authn, acr = self.pick_auth(areq=areq)
        kwargs["cookie"] = cookie
        return authn.verify(_req, **kwargs)

    def write_session_cookie(self, value):
        return make_cookie(self.session_cookie_name, value, self.seed, path="/")

    def delete_session_cookie(self):
        return make_cookie(self.session_cookie_name, "", b"", path="/",
                           expire=-1)

    def _compute_session_state(self, state, salt, client_id, redirect_uri):
        parsed_uri = urlparse(redirect_uri)
        rp_origin_url = "{uri.scheme}://{uri.netloc}".format(uri=parsed_uri)
        session_str = client_id + " " + rp_origin_url + " " + state + " " + salt
        return hashlib.sha256(
            session_str.encode("utf-8")).hexdigest() + "." + salt
