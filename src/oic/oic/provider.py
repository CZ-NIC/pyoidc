#!/usr/bin/env python
import hashlib
import hmac
import itertools
import json
import logging
import os
import random
import socket
import sys
import time
import traceback
import urllib

import six
from requests import ConnectionError

from jwkest import b64d
from jwkest import jwe
from jwkest import jws
from jwkest.jwe import JWE
from jwkest.jwe import JWEException
from jwkest.jwe import NotSupportedAlgorithm
from jwkest.jwk import SYMKey
from jwkest.jws import NoSuitableSigningKeys
from jwkest.jws import alg2keytype
from oic.exception import *
from oic.oauth2 import rndstr
from oic.oauth2.exception import CapabilitiesMisMatch
from oic.oauth2.message import by_schema
from oic.oauth2.provider import Provider as AProvider
from oic.oauth2.provider import Endpoint
from oic.oic import PREFERENCE2PROVIDER
from oic.oic import PROVIDER_DEFAULT
from oic.oic import Server
from oic.oic import claims_match
from oic.oic.message import SCOPE2CLAIMS
from oic.oic.message import AccessTokenRequest
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AuthorizationResponse
from oic.oic.message import Claims
from oic.oic.message import ClientRegistrationErrorResponse
from oic.oic.message import DiscoveryRequest
from oic.oic.message import DiscoveryResponse
from oic.oic.message import EndSessionRequest
from oic.oic.message import IdToken
from oic.oic.message import OpenIDRequest
from oic.oic.message import OpenIDSchema
from oic.oic.message import ProviderConfigurationResponse
from oic.oic.message import RefreshAccessTokenRequest
from oic.oic.message import RegistrationRequest
from oic.oic.message import RegistrationResponse
from oic.oic.message import TokenErrorResponse
from oic.utils.http_util import BadRequest
from oic.utils.http_util import Redirect
from oic.utils.http_util import Response
from oic.utils.http_util import Unauthorized
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import dump_jwks
from oic.utils.keyio import key_export
from oic.utils.time_util import utc_time_sans_frac
from six.moves.urllib import parse as urlparse

if six.PY3:
    from urllib.parse import splitquery
else:
    from urllib import splitquery


__author__ = 'rohe0002'


logger = logging.getLogger(__name__)

SWD_ISSUER = "http://openid.net/specs/connect/1.0/issuer"
STR = 5 * "_"


class InvalidRedirectURIError(Exception):
    pass


# noinspection PyUnusedLocal
def devnull(txt):
    pass


# noinspection PyUnusedLocal
def do_authorization(user):
    return ""


def secret(seed, sid):
    msg = "{}{:.6f}{}".format(time.time(), random.random(), sid).encode("utf-8")
    csum = hmac.new(seed, msg, hashlib.sha224)
    return csum.hexdigest()


# def update_info(aresp, sdict):
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

    _dic = _sdb.upgrade_to_token(_scode, issue_refresh=False)
    for prop in AccessTokenResponse.c_param.keys():
        try:
            aresp[prop] = _dic[prop]
        except KeyError:
            pass

    return aresp


def location_url(response_type, redirect_uri, query):
    if response_type in [["code"], ["token"], ["none"]]:
        return "%s?%s" % (redirect_uri, query)
    else:
        return "%s#%s" % (redirect_uri, query)


def construct_uri(item):
    (base_url, query) = item
    if query:
        return "%s?%s" % (base_url, urllib.urlencode(query))
    else:
        return base_url


class AuthorizationEndpoint(Endpoint):
    etype = "authorization"
    url = 'authorization'


class TokenEndpoint(Endpoint):
    etype = "token"
    url = 'token'


class UserinfoEndpoint(Endpoint):
    etype = "userinfo"
    url = 'userinfo'


class RegistrationEndpoint(Endpoint):
    etype = "registration"
    url = 'registration'


class EndSessionEndpoint(Endpoint):
    etype = "end_session"
    url = 'end_session'


RESPONSE_TYPES_SUPPORTED = [
    ["code"], ["token"], ["id_token"], ["code", "token"], ["code", "id_token"],
    ["id_token", "token"], ["code", "token", "id_token"]]

CAPABILITIES = {
    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post", "client_secret_basic",
        "client_secret_jwt", "private_key_jwt"],
    "response_modes_supported": ['query', 'fragment', 'form_post'],
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": [
        "authorization_code", "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer"],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
}


class Provider(AProvider):
    def __init__(self, name, sdb, cdb, authn_broker, userinfo, authz,
                 client_authn, symkey, urlmap=None, ca_certs="", keyjar=None,
                 hostname="", template_lookup=None, template=None,
                 verify_ssl=True, capabilities=None, schema=OpenIDSchema):

        AProvider.__init__(self, name, sdb, cdb, authn_broker, authz,
                           client_authn, symkey, urlmap, ca_bundle=ca_certs,
                           verify_ssl=verify_ssl)

        # Should be a OIC Server not an OAuth2 server
        self.server = Server(ca_certs=ca_certs, verify_ssl=verify_ssl)

        self.endp.extend([UserinfoEndpoint, RegistrationEndpoint,
                          EndSessionEndpoint])

        self.userinfo = userinfo

        if keyjar:
            self.server.keyjar = keyjar
        self.template_lookup = template_lookup
        self.template = template or {}
        self.keyjar = self.server.keyjar
        self.baseurl = ""
        self.cert = []
        self.cert_encryption = []

        self.cookie_name = "pyoidc"
        self.seed = b""
        self.sso_ttl = 0
        self.test_mode = False

        # where the jwks file kan be found by outsiders
        self.jwks_uri = []
        # Local filename
        self.jwks_name = ""

        self.authn_as = None
        self.preferred_id_type = "public"
        self.hostname = hostname or socket.gethostname

        for endp in self.endp:
            if endp.etype == 'registration':
                self.register_endpoint = urlparse.urljoin(self.baseurl,
                                                          endp.url)
                break

        self.jwx_def = {}
        for _typ in ["sign_alg", "enc_alg", "enc_enc"]:
            self.jwx_def[_typ] = {}
            for item in ["request_object", "id_token", "userinfo"]:
                self.jwx_def[_typ][item] = ""

        self.jwx_def["sign_alg"]["id_token"] = "RS256"

        self.force_jws = {}
        for item in ["request_object", "id_token", "userinfo"]:
            self.force_jws[item] = False

        if capabilities:
            self.verify_capabilities(capabilities)
            self.capabilities = ProviderConfigurationResponse(**capabilities)
        else:
            self.capabilities = self.provider_features()
        self.capabilities["issuer"] = self.name
        self.kid = {"sig": {}, "enc": {}}

        # Allow custom schema (inheriting from OpenIDSchema) to be used -
        # additional attributes
        self.schema = schema

    def set_mode(self, mode):
        """
        The mode is a set of parameters that govern how this OP will behave.

        :param mode:
        :return:
        """

        # Is there a signing algorithm I should use
        try:
            self.jwx_def["sign_alg"]["id_token"] = mode["sign"]
            self.jwx_def["sign_alg"]["userinfo"] = mode["sign"]
        except KeyError:
            pass
        else:
            # make sure id_token_signed_response_alg is set in client register
            # response. This will make it happen in match_preferences()
            for val in PREFERENCE2PROVIDER.values():
                if val.endswith("signing_alg_values_supported"):
                    self.capabilities[val] = [mode["sign"]]

        # Is there a encryption algorithm I should use
        try:
            _enc_alg = mode["enc_alg"]
        except KeyError:
            pass
        else:
            # make sure id_token_signed_response_alg is set in client register
            # response. This will make it happen in match_preferences()
            for val in PREFERENCE2PROVIDER.values():
                if val.endswith("encryption_alg_values_supported"):
                    self.capabilities[val] = [_enc_alg]

        # Is there a encryption enc algorithm I should use
        try:
            _enc_enc = mode["enc_enc"]
        except KeyError:
            pass
        else:
            # make sure id_token_signed_response_alg is set in client register
            # response. This will make it happen in match_preferences()
            for val in PREFERENCE2PROVIDER.values():
                if val.endswith("encryption_enc_values_supported"):
                    self.capabilities[val] = [_enc_enc]

    def id_token_as_signed_jwt(self, session, loa="2", alg="", code=None,
                               access_token=None, user_info=None, auth_time=0,
                               exp=None, extra_claims=None):

        if alg == "":
            alg = self.jwx_def["sign_alg"]["id_token"]

        if alg:
            logger.debug("Signing alg: %s [%s]" % (alg, alg2keytype(alg)))
        else:
            alg = "none"

        _idt = self.server.make_id_token(session, loa, self.baseurl, alg, code,
                                         access_token, user_info, auth_time,
                                         exp, extra_claims)

        logger.debug("id_token: %s" % _idt.to_dict())
        # My signing key if its RS*, can use client secret if HS*
        if alg.startswith("HS"):
            logger.debug("client_id: %s" % session["client_id"])
            ckey = self.keyjar.get_signing_key(alg2keytype(alg),
                                               session["client_id"])
            if not ckey:  # create a new key
                _secret = self.cdb[session["client_id"]]["client_secret"]
                ckey = [SYMKey(key=_secret)]
        else:
            if "" in self.keyjar:
                for b in self.keyjar[""]:
                    logger.debug("OC3 server keys: %s" % b)
                ckey = self.keyjar.get_signing_key(alg2keytype(alg), "",
                                                   alg=alg)
            else:
                ckey = None
        logger.debug("ckey: %s" % ckey)
        _signed_jwt = _idt.to_jwt(key=ckey, algorithm=alg)

        return _signed_jwt

    def _parse_openid_request(self, request):
        return OpenIDRequest().from_jwt(request, keyjar=self.keyjar)

    def _parse_id_token(self, id_token, redirect_uri):
        try:
            return IdToken().from_jwt(id_token, keyjar=self.keyjar)
        except Exception as err:
            logger.error("Faulty id_token: %s" % id_token)
            logger.error("Exception: %s" % (err.__class__.__name__,))
            id_token = IdToken().from_jwt(id_token, verify=False)
            logger.error("IdToken: %s" % id_token.to_dict())
            return self._redirect_authz_error("invalid_id_token_object",
                                              redirect_uri)

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

        (_base, _query) = splitquery(_redirect_uri)

        sid = ""
        try:
            if _base in client_info["si_redirects"]:
                sid = client_info["sector_id"]
        except KeyError:
            try:
                uit = client_info["subject_type"]
                if uit == "pairwise":
                    sid = _base
            except KeyError:
                pass

        return sid

    def handle_oidc_request(self, areq, redirect_uri):
        """

        :param areq:
        :param redirect_uri:
        :return:
        """
        if "request_uri" in areq:
            # Do a HTTP get
            try:
                _req = self.server.http_request(areq["request_uri"])
            except ConnectionError:
                return self._authz_error("invalid_request_uri")

            if not _req:
                return self._authz_error("invalid_request_uri")

            try:
                resq = self._parse_openid_request(_req.text)
            except Exception as err:
                return self._redirect_authz_error(
                    "invalid_openid_request_object", redirect_uri)

            areq["request"] = resq

        # The "request" in areq case is handled by .verify()

        return areq

    def _verify_client(self, areq, aud):
        if areq["client_id"] in aud:
            return True
        else:
            return False

    def required_user(self, areq):
        req_user = ""
        try:
            _req = areq["request"]
        except KeyError:
            _req = areq

        if "id_token_hint" in _req:
            try:
                req_user = _req["id_token_hint"]["sub"]
                aud = _req["id_token_hint"]["aud"]
            except (KeyError, TypeError):
                # A signed jwt, should verify signature if I can
                jso = json.loads(b64d(str(_req["id_token_hint"].split(".")[1])))
                req_user = jso["sub"]
                aud = jso["aud"]

            if not self._verify_client(areq, aud):
                req_user = ""

        return req_user

    def pick_auth(self, areq, comparision_type=""):
        """

        :param areq: AuthorizationRequest instance
        :param comparision_type: How to pick the authentication method
        :return: An authentication method and its authn class ref
        """

        if comparision_type == "any":
            return self.authn_broker[0]

        try:
            if "acr_values" in areq:
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
                return self.authn_broker[0]
        except KeyError as exc:
            logger.debug(
                "An error occured while picking the authN broker: %s" % str(
                    exc))

        # return the best I have
        return None, None

    def verify_post_logout_redirect_uri(self, esreq, cookie):
        """

        :param esreq: End session request
        :param cookie:
        :return:
        """
        try:
            redirect_uri = esreq["post_logout_redirect_uri"]
        except KeyError:
            logger.debug("Missing post_logout_redirect_uri parameter")
            return None

        try:
            authn, acr = self.pick_auth(esreq)
        except Exception as err:
            logger.exception("%s", err)
            raise

        try:
            uid, _ts = authn.authenticated_as(cookie)
            client_ids = self.sdb.get_client_ids_for_uid(uid["uid"])
            accepted_urls = [self.cdb[cid]["post_logout_redirect_uris"] for cid
                             in client_ids]
            if self._verify_url(redirect_uri,
                                itertools.chain.from_iterable(accepted_urls)):
                return redirect_uri
        except Exception as exc:
            logger.debug(
                "An error occurred while verifying redirect URI: %s" % str(exc))

        return None

    def is_session_revoked(self, request="", cookie=None):
        areq = urlparse.parse_qs(request)
        authn, acr = self.pick_auth(areq)
        identity, _ts = authn.authenticated_as(cookie)
        return self.sdb.is_revoke_uid(identity["uid"])

    def let_user_verify_logout(self, uid, esr, cookie, redirect_uri):
        if cookie:
            headers = [cookie]
        else:
            headers = []
        mte = self.template_lookup.get_template(self.template["verify_logout"])
        self.sdb.set_verified_logout(uid)
        if redirect_uri is not None:
            redirect = redirect_uri
        else:
            redirect = "/"
        try:
            tmp_id_token_hint = esr["id_token_hint"]
        except:
            tmp_id_token_hint = ""
        argv = {
            "id_token_hint": tmp_id_token_hint,
            "post_logout_redirect_uri": esr["post_logout_redirect_uri"],
            "key": self.sdb.get_verify_logout(uid),
            "redirect": redirect,
            "action": "/" + EndSessionEndpoint("").etype
        }
        return Response(mte.render(**argv), headers=[])

    def end_session_endpoint(self, request="", cookie=None, **kwargs):
        esr = EndSessionRequest().from_urlencoded(request)

        logger.debug("End session request: {}".format(esr.to_dict()))

        redirect_uri = None
        if "post_logout_redirect_uri" in esr:
            redirect_uri = self.verify_post_logout_redirect_uri(esr, cookie)
            if not redirect_uri:
                return self._error_response(
                    "Not allowed (Post logout redirect URI verification "
                    "failed)!")

        authn, acr = self.pick_auth(esr)

        sid = None
        if "id_token_hint" in esr:
            id_token_hint = OpenIDRequest().from_jwt(esr["id_token_hint"],
                                                     keyjar=self.keyjar,
                                                     verify=True)
            sub = id_token_hint["sub"]
            try:
                sid = self.sdb.get_sids_by_sub(sub)[
                    0]  # any sid will do, choose the first
            except IndexError:
                pass
        else:
            identity, _ts = authn.authenticated_as(cookie)
            if identity:
                uid = identity["uid"]
                try:
                    sid = self.sdb.uid2sid[uid][
                        0]  # any sid will do, choose the first
                except (KeyError, IndexError):
                    pass
            else:
                return self._error_response(
                    "Not allowed (UID could not be retrieved)!")

        # if self.sdb.get_verified_logout(uid):
        #    return self.let_user_verify_logout(uid, esr, cookie, redirect_uri)

        if sid is not None:
            del self.sdb[sid]

        # Delete cookies
        headers = [authn.delete_cookie(), self.delete_session_cookie()]

        if redirect_uri is not None:
            return Redirect(str(redirect_uri), headers=headers)

        return Response("Successful logout", headers=headers)

    def verify_endpoint(self, request="", cookie=None, **kwargs):
        """

        :param request:
        :param cookie:
        :param kwargs:
        :return:
        """
        logger.debug("verify request: %s" % request)

        _req = urlparse.parse_qs(request)
        if "query" in _req:
            try:
                # TODO FIX THIS !!! Why query ?
                areq = urlparse.parse_qs(_req["query"][0])
            except KeyError:
                return BadRequest()
        else:
            areq = _req

        logger.debug("REQ: %s" % areq)
        try:
            authn, acr = self.pick_auth(areq, "exact")
        except Exception as err:
            logger.exception("%s", err)
            raise

        kwargs["cookie"] = cookie
        return authn.verify(_req, **kwargs)

    def setup_session(self, areq, authn_event, cinfo):
        try:
            oidc_req = areq["request"]
        except KeyError:
            oidc_req = None

        sid = self.sdb.create_authz_session(authn_event, areq, oidreq=oidc_req)
        kwargs = {}
        for param in ["sector_id", "subject_type"]:
            try:
                kwargs[param] = cinfo[param]
            except KeyError:
                pass

        self.sdb.do_sub(sid, cinfo['client_salt'], **kwargs)
        return sid

    def authorization_endpoint(self, request="", cookie=None, **kwargs):
        """ The AuthorizationRequest endpoint

        :param request: The client request
        """

        info = self.auth_init(request, request_class=AuthorizationRequest)
        if isinstance(info, Response):
            return info

        areq = self.handle_oidc_request(info["areq"], info["redirect_uri"])
        if isinstance(areq, Response):
            return areq

        logger.debug("AuthzRequest+oidc_request: %s" % (areq.to_dict(),))

        _cid = areq["client_id"]
        cinfo = self.cdb[_cid]
        if _cid not in self.keyjar.issuer_keys:
            if "jwks_uri" in cinfo:
                self.keyjar.issuer_keys[_cid] = []
                self.keyjar.add(_cid, cinfo["jwks_uri"])

        req_user = self.required_user(areq)
        if req_user:
            sids = self.sdb.get_sids_by_sub(req_user)
            if sids:
                # anyone will do
                authn_event = self.sdb[sids[-1]]["authn_event"]
                # Is the authentication event to be regarded as valid ?
                if authn_event.valid():
                    sid = self.setup_session(areq, authn_event, cinfo)
                    return self.authz_part2(authn_event.uid, areq, sid,
                                            cookie=cookie)

            kwargs["req_user"] = req_user

        authnres = self.do_auth(info["areq"], info["redirect_uri"],
                                cinfo, request, cookie, **kwargs)

        if isinstance(authnres, Response):
            return authnres

        logger.debug("- authenticated -")
        logger.debug("AREQ keys: %s" % list(areq.keys()))

        sid = self.setup_session(areq, authnres["authn_event"], cinfo)
        return self.authz_part2(authnres["user"], areq, sid, cookie=cookie)

    def authz_part2(self, user, areq, sid, **kwargs):
        result = self._complete_authz(user, areq, sid, **kwargs)
        if isinstance(result, Response):
            return result
        else:
            aresp, headers, redirect_uri, fragment_enc = result

        if "check_session_iframe" in self.capabilities:
            salt = rndstr()
            state = str(self.sdb.get_authentication_event(
                sid).authn_time)  # use the last session
            aresp["session_state"] = self._compute_session_state(
                state, salt, areq["client_id"], redirect_uri)
            headers.append(self.write_session_cookie(state))

        location = aresp.request(redirect_uri, fragment_enc)
        logger.debug("Redirected to: '%s' (%s)" % (location, type(location)))
        return Redirect(str(location), headers=headers)

    def userinfo_in_id_token_claims(self, session):
        """
        Put userinfo claims in the id token
        :param session:
        :return:
        """
        itc = self.server.id_token_claims(session)
        if not itc:
            return None

        _claims = by_schema(self.schema, **itc)

        if _claims:
            return self._collect_user_info(session, _claims)
        else:
            return None

    def encrypt(self, payload, client_info, cid, val_type="id_token", cty=""):
        """
        Handles the encryption of a payload.
        Shouldn't get here unless there are encrypt parameters in client info

        :param payload: The information to be encrypted
        :param client_info: Client information
        :param cid: Client id
        :return: The encrypted information as a JWT
        """

        try:
            alg = client_info["%s_encrypted_response_alg" % val_type]
            enc = client_info["%s_encrypted_response_enc" % val_type]
        except KeyError as err:  # both must be defined
            logger.warning("undefined parameter: %s" % err)
            raise JWEException("%s undefined" % err)

        logger.debug("alg=%s, enc=%s, val_type=%s" % (alg, enc, val_type))
        keys = self.keyjar.get_encrypt_key(owner=cid)
        logger.debug("Encryption keys for %s: %s" % (cid, keys))
        try:
            _ckeys = self.keyjar[cid]
        except KeyError:
            # Weird, but try to recuperate
            logger.warning(
                "Lost keys for {} trying to recuperate!!".format(cid))
            self.keyjar.issuer_keys[cid] = []
            self.keyjar.add(cid, client_info["jwks_uri"])
            _ckeys = self.keyjar[cid]

        logger.debug("keys for %s: %s" % (
            cid, "[" + ", ".join([str(x) for x in _ckeys])) + "]")

        kwargs = {"alg": alg, "enc": enc}
        if cty:
            kwargs["cty"] = cty

        # use the clients public key for encryption
        _jwe = JWE(payload, **kwargs)
        return _jwe.encrypt(keys, context="public")

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
            try:
                alg = self.jwx_def["sign_alg"]["id_token"]
            except KeyError:
                alg = PROVIDER_DEFAULT["id_token_signed_response_alg"]
            else:
                if not alg:
                    alg = PROVIDER_DEFAULT["id_token_signed_response_alg"]

        _authn_event = sinfo["authn_event"]
        id_token = self.id_token_as_signed_jwt(
            sinfo, loa=_authn_event.authn_info, alg=alg, code=code,
            access_token=access_token, user_info=user_info,
            auth_time=_authn_event.authn_time)

        # Then encrypt
        if "id_token_encrypted_response_alg" in client_info:
            id_token = self.encrypt(id_token, client_info, areq["client_id"],
                                    "id_token", "JWT")

        return id_token

    def _access_token_endpoint(self, req, **kwargs):

        _sdb = self.sdb
        _log_debug = logger.debug

        client_info = self.cdb[req["client_id"]]

        assert req["grant_type"] == "authorization_code"

        _access_code = req["code"]
        # assert that the code is valid
        if self.sdb.is_revoked(_access_code):
            return self._error(error="access_denied", descr="Token is revoked")

        _info = _sdb[_access_code]

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _info:
            try:
                assert req["redirect_uri"] == _info["redirect_uri"]
            except AssertionError:
                return self._error(error="access_denied",
                                   descr="redirect_uri mismatch")

        _log_debug("All checks OK")

        if "issue_refresh" in kwargs:
            args = {"issue_refresh": kwargs["issue_refresh"]}
        else:
            args = {}

        try:
            _sdb.upgrade_to_token(_access_code, **args)
        except Exception as err:
            logger.error("%s" % err)
            # Should revoke the token issued to this access code
            _sdb.revoke_all_tokens(_access_code)
            return self._error(error="access_denied", descr="%s" % err)

        if "openid" in _info["scope"]:
            userinfo = self.userinfo_in_id_token_claims(_info)
            # _authn_event = _info["authn_event"]
            try:
                _idtoken = self.sign_encrypt_id_token(
                    _info, client_info, req, user_info=userinfo)
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                return self._error(error="access_denied",
                                   descr="Could not sign/encrypt id_token")

            _sdb.update_by_token(_access_code, "id_token", _idtoken)

        # Refresh the _tinfo
        _tinfo = _sdb[_access_code]

        _log_debug("_tinfo: %s" % _tinfo)

        atr = AccessTokenResponse(**by_schema(AccessTokenResponse, **_tinfo))

        _log_debug("access_token_response: %s" % atr.to_dict())

        return Response(atr.to_json(), content="application/json")

    def _refresh_access_token_endpoint(self, req, **kwargs):
        _sdb = self.sdb
        _log_debug = logger.debug

        client_info = self.cdb[req["client_id"]]

        assert req["grant_type"] == "refresh_token"
        rtoken = req["refresh_token"]
        _info = _sdb.refresh_token(rtoken)

        if "openid" in _info["scope"]:
            userinfo = self.userinfo_in_id_token_claims(_info)
            try:
                _idtoken = self.sign_encrypt_id_token(
                    _info, client_info, req, user_info=userinfo)
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                return self._error(error="access_denied",
                                   descr="Could not sign/encrypt id_token")

            sid = _sdb.token.get_key(rtoken)
            _sdb.update(sid, "id_token", _idtoken)

        _log_debug("_info: %s" % _info)

        atr = AccessTokenResponse(**by_schema(AccessTokenResponse, **_info))

        _log_debug("access_token_response: %s" % atr.to_dict())

        return Response(atr.to_json(), content="application/json")

    # noinspection PyUnusedLocal
    def token_endpoint(self, request="", authn=None, dtype='urlencoded',
                       **kwargs):
        """
        This is where clients come to get their access tokens

        :param request: The request
        :param authn: Authentication info, comes from HTTP header
        :returns:
        """
        logger.debug("- token -")
        logger.info("token_request: %s" % request)

        req = AccessTokenRequest().deserialize(request, dtype)
        if "refresh_token" in req:
            req = RefreshAccessTokenRequest().deserialize(request, dtype)

        logger.debug("%s: %s" % (req.__class__.__name__, req))

        try:
            client_id = self.client_authn(self, req, authn)
        except Exception as err:
            logger.error("Failed to verify client due to: %s" % err)
            client_id = ""

        if not client_id:
            err = TokenErrorResponse(error="unauthorized_client")
            return Unauthorized(err.to_json(), content="application/json")

        if "client_id" not in req:  # Optional for access token request
            req["client_id"] = client_id

        if isinstance(req, AccessTokenRequest):
            try:
                return self._access_token_endpoint(req, **kwargs)
            except JWEException as err:
                return self._error_response("invalid_request",
                                            descr="%s" % err)

        else:
            return self._refresh_access_token_endpoint(req, **kwargs)

    def _collect_user_info(self, session, userinfo_claims=None):
        """
        Collect information about a user.
        This can happen in two cases, either when constructing an IdToken or
        when returning user info through the UserInfo endpoint

        :param session: Session information
        :param userinfo_claims: user info claims
        :return: User info
        """
        if userinfo_claims is None:
            uic = self._scope2claims(session["scope"])

            # Get only keys allowed by user and update the dict if such info
            # is stored in session
            perm_set = session.get('permission')
            if perm_set:
                uic = {key: uic[key] for key in uic if key in perm_set}

            if "oidreq" in session:
                uic = self.server.update_claims(session, "oidreq", "userinfo",
                                                uic)
            else:
                uic = self.server.update_claims(session, "authzreq", "userinfo",
                                                uic)
            if uic:
                userinfo_claims = Claims(**uic)
            else:
                userinfo_claims = None

            logger.debug("userinfo_claim: %s" % userinfo_claims.to_dict())

        logger.debug("Session info: %s" % session)
        info = self.userinfo(session["authn_event"].uid, session['client_id'],
                             userinfo_claims)

        if "sub" in userinfo_claims:
            if not claims_match(session["sub"], userinfo_claims["sub"]):
                raise FailedAuthentication("Unmatched sub claim")

        info["sub"] = session["sub"]
        logger.debug("user_info_response: %s" % (info,))

        return info

    def signed_userinfo(self, client_info, userinfo, session):
        """
        Will create a JWS with the userinfo as payload.

        :param client_info: Client registration information
        :param userinfo: An OpenIDSchema instance
        :param session: Session information
        :return: A JWS containing the userinfo as a JWT
        """
        try:
            algo = client_info["userinfo_signed_response_alg"]
        except KeyError:  # Fall back to default
            algo = self.jwx_def["sign_alg"]["userinfo"]

        if algo == "none":
            key = []
        else:
            if algo.startswith("HS"):
                key = self.keyjar.get_signing_key(alg2keytype(algo),
                                                  client_info["client_id"],
                                                  alg=algo)
            else:
                # Use my key for signing
                key = self.keyjar.get_signing_key(alg2keytype(algo), "",
                                                  alg=algo)
            if not key:
                return self._error(error="access_denied",
                                   descr="Missing signing key")

        jinfo = userinfo.to_jwt(key, algo)
        if "userinfo_encrypted_response_alg" in client_info:
            # encrypt with clients public key
            jinfo = self.encrypt(jinfo, client_info, session["client_id"],
                                 "userinfo", "JWT")
        return jinfo

    # noinspection PyUnusedLocal
    def userinfo_endpoint(self, request="", **kwargs):
        """
        :param request: The request in a string format
        """
        try:
            _log_debug = kwargs["logger"].debug
            _log_info = kwargs["logger"].info
        except KeyError:
            _log_debug = logger.debug
            _log_info = logger.info

        _sdb = self.sdb

        if not request or "access_token" not in request:
            _token = kwargs["authn"]
            assert _token.startswith("Bearer ")
            _token = _token[len("Bearer "):]
            logger.debug("Bearer token: '%s'" % _token)
        else:
            uireq = self.server.parse_user_info_request(data=request)
            logger.debug("user_info_request: %s" % uireq)
            _token = uireq["access_token"].replace(' ', '+')

        # should be an access token
        typ, key = _sdb.token.type_and_key(_token)
        _log_debug("access_token type: '%s'" % (typ,))

        try:
            assert typ == "T"
        except AssertionError:
            raise FailedAuthentication("Wrong type of token")

        # _log_info("keys: %s" % self.sdb.keys())
        if _sdb.is_revoked(key):
            return self._error(error="access_denied", descr="Token is revoked")
        session = _sdb[key]

        # Scope can translate to userinfo_claims

        info = self.schema(**self._collect_user_info(session))

        # Should I return a JSON or a JWT ?
        _cinfo = self.cdb[session["client_id"]]
        try:
            if "userinfo_signed_response_alg" in _cinfo:
                # Will also encrypt if defined in cinfo
                jinfo = self.signed_userinfo(_cinfo, info, session)
                content_type = "application/jwt"
                cty = "JWT"
            elif "userinfo_encrypted_response_alg" in _cinfo:
                jinfo = info.to_json()
                jinfo = self.encrypt(jinfo, _cinfo, session["client_id"],
                                     "userinfo", "")
                content_type = "application/jwt"
            else:
                jinfo = info.to_json()
                content_type = "application/json"
                cty = ""
        except NotSupportedAlgorithm as err:
            return self._error(error="access_denied",
                               descr="Not supported algorithm: {}".format(
                                   err.args[0]))
        except JWEException:
            return self._error(error="access_denied",
                               descr="Could not encrypt")

        return Response(jinfo, content=content_type)

    # noinspection PyUnusedLocal
    def check_session_endpoint(self, request, **kwargs):
        """
        """
        try:
            _log_debug = kwargs["logger"].debug
            _log_info = kwargs["logger"].info
        except KeyError:
            _log_debug = logger.debug
            _log_info = logger.info

        if not request:
            _tok = kwargs["authn"]
            if not _tok:
                return self._error(error="access_denied", descr="Illegal token")
            else:
                info = "id_token=%s" % _tok

        if self.test_mode:
            _log_info("check_session_request: %s" % request)
        idt = self.server.parse_check_session_request(query=request)
        if self.test_mode:
            _log_info("check_session_response: %s" % idt.to_dict())

        return Response(idt.to_json(), content="application/json")

    @staticmethod
    def _verify_url(url, urlset):
        part = urlparse.urlparse(url)

        for reg, qp in urlset:
            _part = urlparse.urlparse(reg)
            if part.scheme == _part.scheme and part.netloc == _part.netloc:
                return True

        return False

    def match_client_request(self, request):
        for _pref, _prov in PREFERENCE2PROVIDER.items():
            if _pref in request:
                if _pref == "response_types":
                    for val in request[_pref]:
                        match = False
                        p = set(val.split(" "))
                        for cv in RESPONSE_TYPES_SUPPORTED:
                            if p == set(cv):
                                match = True
                                break
                        if not match:
                            raise CapabilitiesMisMatch(_pref)
                else:
                    if isinstance(request[_pref], six.string_types):
                        try:
                            assert request[_pref] in self.capabilities[_prov]
                        except AssertionError:
                            raise CapabilitiesMisMatch(_pref)
                    else:
                        if not set(request[_pref]).issubset(
                                set(self.capabilities[_prov])):
                            raise CapabilitiesMisMatch(_pref)

    def do_client_registration(self, request, client_id, ignore=None):
        if ignore is None:
            ignore = []

        _cinfo = self.cdb[client_id].copy()
        logger.debug("_cinfo: %s" % _cinfo)

        for key, val in request.items():
            if key not in ignore:
                _cinfo[key] = val

        if "post_logout_redirect_uris" in request:
            plruri = []
            for uri in request["post_logout_redirect_uris"]:
                if urlparse.urlparse(uri).fragment:
                    err = ClientRegistrationErrorResponse(
                        error="invalid_configuration_parameter",
                        error_description="post_logout_redirect_uris contains "
                                          "fragment")
                    return Response(err.to_json(),
                                    content="application/json",
                                    status="400 Bad Request")
                base, query = splitquery(uri)
                if query:
                    plruri.append((base, urlparse.parse_qs(query)))
                else:
                    plruri.append((base, query))
            _cinfo["post_logout_redirect_uris"] = plruri

        if "redirect_uris" in request:
            try:
                ruri = self._verify_redirect_uris(request)
                _cinfo["redirect_uris"] = ruri
            except InvalidRedirectURIError as e:
                err = ClientRegistrationErrorResponse(
                    error="invalid_redirect_uri",
                    error_description=str(e))
                return Response(err.to_json(),
                                content="application/json",
                                status="400 Bad Request")

        if "sector_identifier_uri" in request:
            si_url = request["sector_identifier_uri"]
            try:
                res = self.server.http_request(si_url)
            except ConnectionError as err:
                logger.error("%s" % err)
                return self._error_response(
                    "invalid_configuration_parameter",
                    descr="Couldn't open sector_identifier_uri")

            if not res:
                return self._error_response(
                    "invalid_configuration_parameter",
                    descr="Couldn't open sector_identifier_uri")

            logger.debug("sector_identifier_uri => %s" % res.text)

            try:
                si_redirects = json.loads(res.text)
            except ValueError:
                return self._error_response(
                    "invalid_configuration_parameter",
                    descr="Error deserializing sector_identifier_uri content")

            if "redirect_uris" in request:
                logger.debug("redirect_uris: %s" % request["redirect_uris"])
                for uri in request["redirect_uris"]:
                    try:
                        assert uri in si_redirects
                    except AssertionError:
                        return self._error_response(
                            "invalid_configuration_parameter",
                            descr="redirect_uri missing from sector_identifiers"
                        )

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
                                descr="'sector_identifier_uri' must be "
                                      "registered")

        for item in ["policy_uri", "logo_uri", "tos_uri"]:
            if item in request:
                if self._verify_url(request[item], _cinfo["redirect_uris"]):
                    _cinfo[item] = request[item]
                else:
                    return self._error_response(
                        "invalid_configuration_parameter",
                        descr="%s pointed to illegal URL" % item)

        # Do I have the necessary keys
        for item in ["id_token_signed_response_alg",
                     "userinfo_signed_response_alg"]:
            if item in request:
                if request[item] in self.capabilities[
                    PREFERENCE2PROVIDER[item]]:
                    ktyp = jws.alg2keytype(request[item])
                    # do I have this ktyp and for EC type keys the curve
                    if ktyp not in ["none", "oct"]:
                        _k = self.keyjar.get_signing_key(ktyp,
                                                         alg=request[item])
                        if not _k:
                            del _cinfo[item]

        try:
            self.keyjar.load_keys(request, client_id)
            try:
                logger.debug("keys for %s: [%s]" % (
                    client_id,
                    ",".join(["%s" % x for x in self.keyjar[client_id]])))
            except KeyError:
                pass
        except Exception as err:
            logger.error("Failed to load client keys: %s" % request.to_dict())
            logger.error("%s", err)
            err = ClientRegistrationErrorResponse(
                error="invalid_configuration_parameter",
                error_description="%s" % err)
            return Response(err.to_json(), content="application/json",
                            status="400 Bad Request")

        return _cinfo

    def _verify_redirect_uris(self, registration_request):
        verified_redirect_uris = []
        try:
            client_type = registration_request["application_type"]
        except KeyError:  # default
            client_type = "web"

        if client_type == "web":
            try:
                if registration_request["response_types"] == ["code"]:
                    must_https = False
                else:  # one has to be implicit or hybrid
                    must_https = True
            except KeyError:
                must_https = True
        else:
            must_https = False

        for uri in registration_request["redirect_uris"]:
            p = urlparse.urlparse(uri)
            if client_type == "native" and p.scheme == "http":
                if p.hostname != "localhost":
                    raise InvalidRedirectURIError(
                        "Http redirect_uri must use localhost")
            elif must_https and p.scheme != "https":
                raise InvalidRedirectURIError(
                    "None https redirect_uri not allowed")
            elif p.fragment:
                raise InvalidRedirectURIError(
                    "redirect_uri contains fragment")
            # This rule will break local testing.
            # elif must_https and p.hostname == "localhost":
            #     err = InvalidRedirectURIError(
            # "https redirect_uri with host localhost")

            base, query = splitquery(uri)
            if query:
                verified_redirect_uris.append((base, urlparse.parse_qs(query)))
            else:
                verified_redirect_uris.append((base, query))

        return verified_redirect_uris

    @staticmethod
    def comb_uri(args):
        for param in ["redirect_uris", "post_logout_redirect_uris"]:
            if param not in args:
                continue

            val = []
            for base, query in args[param]:
                if query:
                    val.append("%s?%s" % (base, query))
                else:
                    val.append(base)

            args[param] = val

    # noinspection PyUnusedLocal
    def l_registration_endpoint(self, request, authn=None, **kwargs):
        _log_debug = logger.debug
        _log_info = logger.info

        _log_debug("@registration_endpoint: <<%s>>" % request)

        try:
            request = RegistrationRequest().deserialize(request, "json")
        except ValueError:
            request = RegistrationRequest().deserialize(request)

        _log_info("registration_request:%s" % request.to_dict())
        resp_keys = request.keys()

        try:
            request.verify()
        except MessageException as err:
            if "type" not in request:
                return self._error(error="invalid_type",
                                   descr="%s" % err)
            else:
                return self._error(error="invalid_configuration_parameter",
                                   descr="%s" % err)

        request.rm_blanks()
        try:
            self.match_client_request(request)
        except CapabilitiesMisMatch as err:
            return self._error(error="invalid_request",
                               descr="Don't support proposed %s" % err)

        # create new id och secret
        client_id = rndstr(12)
        while client_id in self.cdb:
            client_id = rndstr(12)

        client_secret = secret(self.seed, client_id)

        _rat = rndstr(32)
        reg_enp = ""
        for endp in self.endp:
            if endp.etype == 'registration':
                reg_enp = urlparse.urljoin(self.baseurl, endp.url)
                break

        self.cdb[client_id] = {
            "client_id": client_id,
            "client_secret": client_secret,
            "registration_access_token": _rat,
            "registration_client_uri": "%s?client_id=%s" % (reg_enp, client_id),
            "client_secret_expires_at": utc_time_sans_frac() + 86400,
            "client_id_issued_at": utc_time_sans_frac(),
            "client_salt": rndstr(8)}

        self.cdb[_rat] = client_id

        _cinfo = self.do_client_registration(request, client_id,
                                             ignore=["redirect_uris",
                                                     "policy_uri", "logo_uri",
                                                     "tos_uri"])
        if isinstance(_cinfo, Response):
            return _cinfo

        args = dict([(k, v) for k, v in _cinfo.items()
                     if k in RegistrationResponse.c_param])

        self.comb_uri(args)
        response = RegistrationResponse(**args)

        # Add the client_secret as a symmetric key to the keyjar
        if client_secret:
            _kc = KeyBundle([{"kty": "oct", "key": client_secret,
                              "use": "ver"},
                             {"kty": "oct", "key": client_secret,
                              "use": "sig"}])
            try:
                self.keyjar[client_id].append(_kc)
            except KeyError:
                self.keyjar[client_id] = [_kc]

        self.cdb[client_id] = _cinfo

        try:
            self.cdb.sync()
        except AttributeError:  # Not all databases can be sync'ed
            pass

        _log_info("Client info: %s" % _cinfo)

        logger.debug("registration_response: %s" % response.to_dict())

        return Response(response.to_json(), content="application/json",
                        headers=[("Cache-Control", "no-store")])

    def registration_endpoint(self, request, authn=None, **kwargs):
        return self.l_registration_endpoint(request, authn, **kwargs)

    def read_registration(self, authn, request, **kwargs):
        """
        Read all information this server has on a client.
        Authorization is done by using the access token that was return as
        part of the client registration result.

        :param authn: The Authorization HTTP header
        :param request: The query part of the URL
        :param kwargs: Any other arguments
        :return:
        """

        logger.debug("authn: %s, request: %s" % (authn, request))

        # verify the access token, has to be key into the client information
        # database.
        assert authn.startswith("Bearer ")
        token = authn[len("Bearer "):]

        client_id = self.cdb[token]

        # extra check
        _info = urlparse.parse_qs(request)
        assert _info["client_id"][0] == client_id

        logger.debug("Client '%s' reads client info" % client_id)
        args = dict([(k, v) for k, v in self.cdb[client_id].items()
                     if k in RegistrationResponse.c_param])

        self.comb_uri(args)
        response = RegistrationResponse(**args)

        return Response(response.to_json(), content="application/json",
                        headers=[("Cache-Control", "no-store")])

    def create_providerinfo(self, pcr_class=ProviderConfigurationResponse,
                            setup=None):
        """
        Dynamically create the provider info response
        :param pcr_class:
        :param setup:
        :return:
        """

        _provider_info = self.capabilities

        if self.jwks_uri and self.keyjar:
            _provider_info["jwks_uri"] = self.jwks_uri

        for endp in self.endp:
            # _log_info("# %s, %s" % (endp, endp.name))
            _provider_info['{}_endpoint'.format(endp.etype)] = os.path.join(
                self.baseurl,
                endp.url)

        if setup and isinstance(setup, dict):
            for key in pcr_class.c_param.keys():
                if key in setup:
                    _provider_info[key] = setup[key]

        _provider_info["issuer"] = self.baseurl
        _provider_info["version"] = "3.0"

        return _provider_info

    def provider_features(self, pcr_class=ProviderConfigurationResponse):
        """
        Specifies what the server capabilities are.

        :param pcr_class:
        :return: ProviderConfigurationResponse instance
        """

        _provider_info = pcr_class(**CAPABILITIES)

        _claims = []
        for _cl in SCOPE2CLAIMS.values():
            _claims.extend(_cl)
        _provider_info["claims_supported"] = list(set(_claims))

        _scopes = list(SCOPE2CLAIMS.keys())
        _scopes.append("openid")
        _provider_info["scopes_supported"] = _scopes

        sign_algs = list(jws.SIGNER_ALGS.keys())
        for typ in ["userinfo", "id_token", "request_object"]:
            _provider_info["%s_signing_alg_values_supported" % typ] = sign_algs

        # Remove 'none' for token_endpoint_auth_signing_alg_values_supported
        # since it is not allowed
        sign_algs = sign_algs[:]
        sign_algs.remove('none')
        _provider_info[
            "token_endpoint_auth_signing_alg_values_supported"] = sign_algs

        algs = jwe.SUPPORTED["alg"]
        for typ in ["userinfo", "id_token", "request_object"]:
            _provider_info["%s_encryption_alg_values_supported" % typ] = algs

        encs = jwe.SUPPORTED["enc"]
        for typ in ["userinfo", "id_token", "request_object"]:
            _provider_info["%s_encryption_enc_values_supported" % typ] = encs

        # acr_values
        if self.authn_broker:
            acr_values = self.authn_broker.getAcrValuesString()
            if acr_values is not None:
                _provider_info["acr_values_supported"] = acr_values

        return _provider_info

    def verify_capabilities(self, capabilities):
        """
        Verify that what the admin wants the server to do actually
        can be done by this implementation.

        :param capabilities: The asked for capabilities as a dictionary
        or a ProviderConfigurationResponse instance. The later can be
        treated as a dictionary.
        :return: True or False
        """
        _pinfo = self.provider_features()
        for key, val in capabilities.items():
            if isinstance(val, six.string_types):
                try:
                    if val in _pinfo[key]:
                        continue
                    else:
                        return False
                except KeyError:
                    return False

        return True

    # noinspection PyUnusedLocal
    def providerinfo_endpoint(self, handle="", **kwargs):
        _log_debug = logger.debug
        _log_info = logger.info

        _log_info("@providerinfo_endpoint")
        try:
            _response = self.create_providerinfo()
            _log_info("provider_info_response: %s" % (_response.to_dict(),))

            headers = [("Cache-Control", "no-store"), ("x-ffo", "bar")]
            if handle:
                (key, timestamp) = handle
                if key.startswith(STR) and key.endswith(STR):
                    cookie = self.cookie_func(key, self.cookie_name, "pinfo",
                                              self.sso_ttl)
                    headers.append(cookie)

            resp = Response(_response.to_json(), content="application/json",
                            headers=headers)
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            resp = Response(message, content="html/text")

        return resp

    # noinspection PyUnusedLocal
    def discovery_endpoint(self, request, handle=None, **kwargs):
        """
        :param request:
        :param handle:
        """

        _log_debug = logger.debug

        _log_debug("@discovery_endpoint")

        request = DiscoveryRequest().deserialize(request, "urlencoded")
        _log_debug("discovery_request:%s" % (request.to_dict(),))

        try:
            assert request["service"] == SWD_ISSUER
        except AssertionError:
            return BadRequest("Unsupported service")

        # verify that the principal is one of mine

        _response = DiscoveryResponse(locations=[self.baseurl])

        _log_debug("discovery_response:%s" % (_response.to_dict(),))

        headers = [("Cache-Control", "no-store")]
        (key, timestamp) = handle
        if key.startswith(STR) and key.endswith(STR):
            cookie = self.cookie_func(key, self.cookie_name, "disc",
                                      self.sso_ttl)
            headers.append(cookie)

        return Response(_response.to_json(), content="application/json",
                        headers=headers)

    def auth_resp_extension(self, aresp, areq, sid, rtype):
        if "id_token" in areq["response_type"]:
            _sinfo = self.sdb[sid]

            if "code" in areq["response_type"]:
                _code = aresp["code"] = _sinfo["code"]
                rtype.remove("code")
            else:
                _sinfo[sid]["code"] = None
                _code = None

            try:
                _access_token = aresp["access_token"]
            except KeyError:
                _access_token = None

            user_info = self.userinfo_in_id_token_claims(_sinfo)
            client_info = self.cdb[areq["client_id"]]

            hargs = {}
            if set(areq["response_type"]) == {'code', 'id_token', 'token'}:
                hargs = {"code": _code, "access_token": _access_token}
            elif set(areq["response_type"]) == {'code', 'id_token'}:
                hargs = {"code": _code}
            elif set(areq["response_type"]) == {'id_token', 'token'}:
                hargs = {"access_token": _access_token}

            # or 'code id_token'
            id_token = self.sign_encrypt_id_token(
                _sinfo, client_info, areq, user_info=user_info, **hargs)

            aresp["id_token"] = id_token
            _sinfo["id_token"] = id_token
            rtype.remove("id_token")

        return aresp

    def aresp_check(self, aresp, areq):
        # Use of the nonce is REQUIRED for all requests where an ID Token is
        # returned directly from the Authorization Endpoint
        if "id_token" in aresp:
            try:
                assert "nonce" in areq
            except AssertionError:
                return self._error("invalid_request", "Missing nonce value")
        return None

    def response_mode(self, areq, fragment_enc, **kwargs):
        resp_mode = areq["response_mode"]
        if resp_mode == "form_post":
            argv = {"form_args": kwargs["aresp"].to_dict(),
                    "action": kwargs["redirect_uri"]}
            mte = self.template_lookup.get_template(
                self.template["form_post"])
            return Response(mte.render(**argv), headers=kwargs["headers"])
        elif resp_mode == 'fragment' and not fragment_enc:
            # Can't be done
            raise InvalidRequest("wrong response_mode")
        elif resp_mode == 'query' and fragment_enc:
            # Can't be done
            raise InvalidRequest("wrong response_mode")
        return None

    @staticmethod
    def _scope2claims(scopes):
        res = {}
        for scope in scopes:
            try:
                claims = dict([(name, None) for name in SCOPE2CLAIMS[scope]])
                res.update(claims)
            except KeyError:
                pass
        return res

    def create_authn_response(self, areq, sid):
        # create the response
        aresp = AuthorizationResponse()
        try:
            aresp["state"] = areq["state"]
        except KeyError:
            pass

        if "response_type" in areq and areq["response_type"] == ["none"]:
            fragment_enc = False
        else:
            _sinfo = self.sdb[sid]

            try:
                aresp["scope"] = areq["scope"]
            except KeyError:
                pass

            rtype = set(areq["response_type"][:])
            if len(rtype) == 1 and "code" in rtype:
                fragment_enc = False
            else:
                fragment_enc = True

            if "code" in areq["response_type"]:
                _code = aresp["code"] = self.sdb[sid]["code"]
                rtype.remove("code")
            else:
                self.sdb[sid]["code"] = None
                _code = None

            if "token" in rtype:
                _dic = self.sdb.upgrade_to_token(issue_refresh=False, key=sid)

                logger.debug("_dic: %s" % _dic)
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
                if areq["response_type"] == ["id_token"]:
                    #  scopes should be returned here
                    info = self._collect_user_info(_sinfo)
                    if user_info is None:
                        user_info = info
                    else:
                        user_info.update(info)

                client_info = self.cdb[areq["client_id"]]

                hargs = {}
                if set(areq["response_type"]) == {'code', 'id_token', 'token'}:
                    hargs = {"code": _code, "access_token": _access_token}
                elif set(areq["response_type"]) == {'code', 'id_token'}:
                    hargs = {"code": _code}
                elif set(areq["response_type"]) == {'id_token', 'token'}:
                    hargs = {"access_token": _access_token}

                # or 'code id_token'
                try:
                    id_token = self.sign_encrypt_id_token(
                        _sinfo, client_info, areq, user_info=user_info, **hargs)
                except (JWEException, NoSuitableSigningKeys) as err:
                    logger.warning(str(err))
                    return self._error(error="access_denied",
                                       descr="Could not sign/encrypt id_token")

                aresp["id_token"] = id_token
                _sinfo["id_token"] = id_token
                rtype.remove("id_token")

            if len(rtype):
                return BadRequest("Unknown response type: %s" % rtype)

        return aresp, fragment_enc

    def key_setup(self, local_path, vault="keys", sig=None, enc=None):
        """
        my keys
        :param local_path: The path to where the JWKs should be stored
        :param vault: Where the private key will be stored
        :param sig: Key for signature
        :param enc: Key for encryption
        :return: A URL the RP can use to download the key.
        """
        self.jwks_uri = key_export(self.baseurl, local_path, vault, self.keyjar,
                                   fqdn=self.hostname, sig=sig, enc=enc)

    def register_endpoint(self, request="", **kwargs):
        pass

    def endsession_endpoint(self, request="", **kwargs):
        """

        :param request:
        :param kwargs:
        :return: Either a Response instance or a tuple (Response, args)
        """
        return self.end_session_endpoint(request, **kwargs)

    def do_key_rollover(self, jwks, kid_template):
        """
        Handle key roll-over by importing new keys and inactivating the
        ones in the keyjar that are of the same type and usage.

        :param jwk: A JWK
        """

        kb = KeyBundle()
        kb.do_keys(jwks["keys"])

        kid = 0
        for k in kb.keys():
            if not k.kid:
                k.kid = kid_template % kid
                kid += 1
            self.kid[k.use][k.kty] = k.kid

            # find the old key for this key type and usage and mark that
            # as inactive
            for _kb in self.keyjar.issuer_keys[""]:
                for key in _kb.keys():
                    if key.kty == k.kty and key.use == k.use:
                        if k.kty == "EC":
                            if key.crv == k.crv:
                                key.inactive_since = time.time()
                        else:
                            key.inactive_since = time.time()

        self.keyjar.add_kb("", kb)

        if self.jwks_name:
            # print to the jwks file
            dump_jwks(self.keyjar[""], self.jwks_name)

    def remove_inactive_keys(self, more_then=3600):
        """
        Remove all keys that has been inactive 'more_then' seconds

        :param more_then: An integer (default = 3600 seconds == 1 hour)
        """
        now = time.time()
        for kb in self.keyjar.issuer_keys[""]:
            for key in kb.keys():
                if key.inactive_since:
                    if now - key.inactive_since > more_then:
                        kb.remove(key)
            if len(kb) == 0:
                self.keyjar.issuer_keys[""].remove(kb)
