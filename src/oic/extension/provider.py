from functools import cmp_to_key
import json
import logging
import os
import traceback
import sys
import six
import socket

from future.backports.urllib.parse import parse_qs
from future.backports.urllib.parse import splitquery

from jwkest import jws, b64e

from oic import rndstr

from oic.exception import FailedAuthentication
from oic.exception import ModificationForbidden
from oic.exception import RestrictionError
from oic.exception import UnSupported
from oic.exception import UnknownAssertionType
from oic.extension.message import ClientInfoResponse
from oic.extension.message import ClientRegistrationError
from oic.extension.message import ServerMetadata
from oic.extension.client import CC_METHOD
from oic.extension.message import ClientUpdateRequest
from oic.extension.message import RegistrationRequest
from oic.extension.message import InvalidRedirectUri
from oic.extension.message import MissingPage
from oic.extension.message import TokenRevocationRequest
from oic.extension.message import TokenIntrospectionRequest
from oic.extension.message import TokenIntrospectionResponse
from oic.oauth2 import provider
from oic.oauth2 import AccessTokenRequest
from oic.oauth2 import TokenErrorResponse
from oic.oauth2 import AccessTokenResponse
from oic.oauth2 import by_schema
from oic.oauth2.provider import Endpoint
from oic.oauth2.exception import VerificationError
from oic.oauth2.exception import CapabilitiesMisMatch
from oic.oauth2.message import ASConfigurationResponse
from oic.oauth2.message import ErrorResponse

from oic.oic import PREFERENCE2PROVIDER
from oic.oic.provider import RegistrationEndpoint
from oic.oic.provider import STR
from oic.oic.provider import secret
from oic.utils import restrict
from oic.utils import sort_sign_alg
from oic.utils.authn.client import AuthnFailure
from oic.utils.authn.client import UnknownAuthnMethod
from oic.utils.authn.client import get_client_id
from oic.utils.authn.client import valid_client_info
from oic.utils.http_util import Unauthorized
from oic.utils.http_util import NoContent
from oic.utils.http_util import Response
from oic.utils.http_util import BadRequest
from oic.utils.http_util import Forbidden
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from oic.utils.keyio import key_export
from oic.utils.sdb import AccessCodeUsed
from oic.utils.sanitize import sanitize
from oic.utils.time_util import utc_time_sans_frac
from oic.utils.token_handler import NotAllowed
from oic.utils.token_handler import TokenHandler

__author__ = 'roland'

logger = logging.getLogger(__name__)

CAPABILITIES = {
    "response_types_supported": ["code", "token"],
    "response_modes_supported": ['query', 'fragment', 'form_post'],
    "grant_types_supported": [
        "authorization_code", "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer"],
}

AUTH_METHODS_SUPPORTED = ["client_secret_post", "client_secret_basic",
                          "client_secret_jwt", "private_key_jwt"]


class ClientInfoEndpoint(Endpoint):
    etype = "clientinfo"
    url = 'clientinfo'


class RevocationEndpoint(Endpoint):
    etype = "revocation"
    url = 'revocation'


class IntrospectionEndpoint(Endpoint):
    etype = "introspection"
    url = 'introspection'


class Provider(provider.Provider):
    """
    A OAuth2 RP that knows all the OAuth2 extensions I've implemented
    """

    def __init__(self, name, sdb, cdb, authn_broker, authz, client_authn,
                 symkey="", urlmap=None, iv=0, default_scope="",
                 ca_bundle=None, seed=b"", client_authn_methods=None,
                 authn_at_registration="", client_info_url="",
                 secret_lifetime=86400, jwks_uri='', keyjar=None,
                 capabilities=None, verify_ssl=True, baseurl='', hostname='',
                 config=None, behavior=None, lifetime_policy=None, **kwargs):

        if not name.endswith("/"):
            name += "/"

        try:
            args = {'server_cls': kwargs['server_cls']}
        except KeyError:
            args = {}

        provider.Provider.__init__(self, name, sdb, cdb, authn_broker, authz,
                                   client_authn, symkey, urlmap, iv,
                                   default_scope, ca_bundle, **args)

        self.endp.extend([RegistrationEndpoint, ClientInfoEndpoint,
                          RevocationEndpoint, IntrospectionEndpoint])

        # dictionary of client authentication methods
        self.client_authn_methods = client_authn_methods
        if authn_at_registration:
            if authn_at_registration not in client_authn_methods:
                raise UnknownAuthnMethod(authn_at_registration)

        self.authn_at_registration = authn_at_registration
        self.seed = seed
        self.client_info_url = client_info_url
        self.secret_lifetime = secret_lifetime
        self.jwks_uri = jwks_uri
        self.verify_ssl = verify_ssl
        try:
            self.scopes = kwargs['scopes']
        except KeyError:
            self.scopes = ['offline_access']
        self.keyjar = keyjar
        if self.keyjar is None:
            self.keyjar = KeyJar(verify_ssl=self.verify_ssl)

        if capabilities:
            self.capabilities = self.provider_features(
                provider_config=capabilities)
        else:
            self.capabilities = self.provider_features()
        self.baseurl = baseurl or name
        self.hostname = hostname or socket.gethostname()
        self.kid = {"sig": {}, "enc": {}}
        self.config = config or {}
        self.behavior = behavior or {}
        self.token_policy = {'access_token': {}, 'refresh_token': {}}
        if lifetime_policy is None:
            self.lifetime_policy = {
                'access_token': {
                    'code': 600,
                    'token': 120,
                    'implicit': 120,
                    'authorization_code': 600,
                    'client_credentials': 600,
                    'password': 600
                },
                'refresh_token': {
                    'code': 3600,
                    'token': 3600,
                    'implicit': 3600,
                    'authorization_code': 3600,
                    'client_credentials': 3600,
                    'password': 3600
                }
            }
        else:
            self.lifetime_policy = lifetime_policy

        self.token_handler = TokenHandler(self.baseurl, self.token_policy,
                                          keyjar=self.keyjar)

    @staticmethod
    def _uris_to_tuples(uris):
        tup = []
        for uri in uris:
            base, query = splitquery(uri)
            if query:
                tup.append((base, query))
            else:
                tup.append((base, ""))
        return tup

    @staticmethod
    def _tuples_to_uris(items):
        _uri = []
        for url, query in items:
            if query:
                _uri.append("%s?%s" % (url, query))
            else:
                _uri.append(url)
        return _uri

    def load_keys(self, request, client_id, client_secret):
        try:
            self.keyjar.load_keys(request, client_id)
            try:
                n_keys = len(self.keyjar[client_id])
                msg = "Found {} keys for client_id={}"
                logger.debug(msg.format(n_keys, client_id))
            except KeyError:
                pass
        except Exception as err:
            msg = "Failed to load client keys: {}"
            logger.error(msg.format(sanitize(request.to_dict())))
            logger.error("%s", err)
            err = ClientRegistrationError(
                error="invalid_configuration_parameter",
                error_description="%s" % err)
            return Response(err.to_json(), content="application/json",
                            status="400 Bad Request")

        # Add the client_secret as a symmetric key to the keyjar
        _kc = KeyBundle([{"kty": "oct", "key": client_secret,
                          "use": "ver"},
                         {"kty": "oct", "key": client_secret,
                          "use": "sig"}])
        try:
            self.keyjar[client_id].append(_kc)
        except KeyError:
            self.keyjar[client_id] = [_kc]

    @staticmethod
    def verify_correct(cinfo, restrictions):
        for fname, arg in restrictions.items():
            func = restrict.factory(fname)
            res = func(arg, cinfo)
            if res:
                raise RestrictionError(res)

    def set_token_policy(self, cid, cinfo):
        for ttyp in ['access_token', 'refresh_token']:
            pol = {}
            for rgtyp in ['response_type', 'grant_type']:
                try:
                    rtyp = cinfo[rgtyp]
                except KeyError:
                    pass
                else:
                    for typ in rtyp:
                        try:
                            pol[typ] = self.lifetime_policy[ttyp][typ]
                        except KeyError:
                            pass

            self.token_policy[ttyp][cid] = pol

    def create_new_client(self, request, restrictions):
        """

        :param request: The Client registration request
        :param restrictions: Restrictions on the client
        :return: The client_id
        """

        _cinfo = request.to_dict()

        self.match_client_request(_cinfo)

        # create new id and secret
        _id = rndstr(12)
        while _id in self.cdb:
            _id = rndstr(12)

        _cinfo["client_id"] = _id
        _cinfo["client_secret"] = secret(self.seed, _id)
        _cinfo["client_id_issued_at"] = utc_time_sans_frac()
        _cinfo["client_secret_expires_at"] = utc_time_sans_frac() + \
                                             self.secret_lifetime

        # If I support client info endpoint
        if ClientInfoEndpoint in self.endp:
            _cinfo["registration_access_token"] = rndstr(32)
            _cinfo["registration_client_uri"] = "%s%s%s?client_id=%s" % (
                self.name, self.client_info_url, ClientInfoEndpoint.etype,
                _id)

        if "redirect_uris" in request:
            _cinfo["redirect_uris"] = self._uris_to_tuples(
                request["redirect_uris"])

        self.load_keys(request, _id, _cinfo["client_secret"])

        try:
            _behav = self.behavior['client_registration']
        except KeyError:
            pass
        else:
            self.verify_correct(_cinfo, _behav)

        self.set_token_policy(_id, _cinfo)
        self.cdb[_id] = _cinfo

        return _id

    def match_client_request(self, request):
        for _pref, _prov in PREFERENCE2PROVIDER.items():
            if _pref in request:
                if _pref == "response_types":
                    for val in request[_pref]:
                        match = False
                        p = set(val.split(" "))
                        for cv in self.capabilities[_prov]:
                            if p == set(cv.split(' ')):
                                match = True
                                break
                        if not match:
                            raise CapabilitiesMisMatch(
                                'Not allowed {}'.format(_pref))
                else:
                    if isinstance(request[_pref], six.string_types):
                        if request[_pref] not in self.capabilities[_prov]:
                            raise CapabilitiesMisMatch(
                                'Not allowed {}'.format(_pref))
                    else:
                        if not set(request[_pref]).issubset(
                                set(self.capabilities[_prov])):
                            raise CapabilitiesMisMatch(
                                'Not allowed {}'.format(_pref))

    def client_info(self, client_id):
        _cinfo = self.cdb[client_id].copy()
        if not valid_client_info(_cinfo):
            err = ErrorResponse(
                error="invalid_client",
                error_description="Invalid client secret")
            return BadRequest(err.to_json(), content="application/json")

        try:
            _cinfo["redirect_uris"] = self._tuples_to_uris(
                _cinfo["redirect_uris"])
        except KeyError:
            pass

        msg = ClientInfoResponse(**_cinfo)
        return Response(msg.to_json(), content="application/json")

    def client_info_update(self, client_id, request):
        _cinfo = self.cdb[client_id].copy()
        try:
            _cinfo["redirect_uris"] = self._tuples_to_uris(
                _cinfo["redirect_uris"])
        except KeyError:
            pass

        for key, value in request.items():
            if key in ["client_secret", "client_id"]:
                # assure it's the same
                try:
                    assert value == _cinfo[key]
                except AssertionError:
                    raise ModificationForbidden("Not allowed to change")
            else:
                _cinfo[key] = value

        for key in list(_cinfo.keys()):
            if key in ["client_id_issued_at", "client_secret_expires_at",
                       "registration_access_token", "registration_client_uri"]:
                continue
            if key not in request:
                del _cinfo[key]

        if "redirect_uris" in request:
            _cinfo["redirect_uris"] = self._uris_to_tuples(
                request["redirect_uris"])

        self.cdb[client_id] = _cinfo

    def verify_client(self, environ, areq, authn_method, client_id=""):
        """

        :param environ: WSGI environ
        :param areq: The request
        :param authn_method: client authentication method
        :return:
        """

        if not client_id:
            client_id = get_client_id(self.cdb, areq,
                                      environ["HTTP_AUTHORIZATION"])

        try:
            method = self.client_authn_methods[authn_method]
        except KeyError:
            raise UnSupported()
        return method(self).verify(environ, client_id=client_id)

    def consume_software_statement(self, software_statement):
        return {}

    def registration_endpoint(self, **kwargs):
        """

        :param request: The request
        :param authn: Client authentication information
        :param kwargs: extra keyword arguments
        :return: A Response instance
        """

        _request = RegistrationRequest().deserialize(kwargs['request'], "json")
        try:
            _request.verify(keyjar=self.keyjar)
        except InvalidRedirectUri as err:
            msg = ClientRegistrationError(error="invalid_redirect_uri",
                                          error_description="%s" % err)
            return BadRequest(msg.to_json(), content="application/json")
        except (MissingPage, VerificationError) as err:
            msg = ClientRegistrationError(error="invalid_client_metadata",
                                          error_description="%s" % err)
            return BadRequest(msg.to_json(), content="application/json")

        # If authentication is necessary at registration
        if self.authn_at_registration:
            try:
                self.verify_client(kwargs['environ'], _request,
                                   self.authn_at_registration)
            except (AuthnFailure, UnknownAssertionType):
                return Unauthorized()

        client_restrictions = {}
        if 'parsed_software_statement' in _request:
            for ss in _request['parsed_software_statement']:
                client_restrictions.update(self.consume_software_statement(ss))
            del _request['software_statement']
            del _request['parsed_software_statement']

        try:
            client_id = self.create_new_client(_request, client_restrictions)
        except CapabilitiesMisMatch as err:
            msg = ClientRegistrationError(error="invalid_client_metadata",
                                          error_description="%s" % err)
            return BadRequest(msg.to_json(), content="application/json")
        except RestrictionError as err:
            msg = ClientRegistrationError(error="invalid_client_metadata",
                                          error_description="%s" % err)
            return BadRequest(msg.to_json(), content="application/json")

        return self.client_info(client_id)

    def client_info_endpoint(self, method="GET", **kwargs):
        """
        Operations on this endpoint are switched through the use of different
        HTTP methods

        :param method: HTTP method used for the request
        :param kwargs: keyword arguments
        :return: A Response instance
        """

        _query = parse_qs(kwargs['query'])
        try:
            _id = _query["client_id"][0]
        except KeyError:
            return BadRequest("Missing query component")

        try:
            assert _id in self.cdb
        except AssertionError:
            return Unauthorized()

        # authenticated client
        try:
            self.verify_client(kwargs['environ'], kwargs['request'],
                               "bearer_header", client_id=_id)
        except (AuthnFailure, UnknownAssertionType):
            return Unauthorized()

        if method == "GET":
            return self.client_info(_id)
        elif method == "PUT":
            try:
                _request = ClientUpdateRequest().from_json(kwargs['request'])
            except ValueError as err:
                return BadRequest(str(err))

            try:
                _request.verify()
            except InvalidRedirectUri as err:
                msg = ClientRegistrationError(error="invalid_redirect_uri",
                                              error_description="%s" % err)
                return BadRequest(msg.to_json(), content="application/json")
            except (MissingPage, VerificationError) as err:
                msg = ClientRegistrationError(error="invalid_client_metadata",
                                              error_description="%s" % err)
                return BadRequest(msg.to_json(), content="application/json")

            try:
                self.client_info_update(_id, _request)
                return self.client_info(_id)
            except ModificationForbidden:
                return Forbidden()
        elif method == "DELETE":
            try:
                del self.cdb[_id]
            except KeyError:
                return Unauthorized()
            else:
                return NoContent()

    def provider_features(self, pcr_class=ServerMetadata, provider_config=None):
        """
        Specifies what the server capabilities are.

        :param pcr_class:
        :return: ProviderConfigurationResponse instance
        """

        _provider_info = pcr_class(**CAPABILITIES)
        _provider_info["scopes_supported"] = self.scopes

        sign_algs = list(jws.SIGNER_ALGS.keys())
        sign_algs.remove('none')
        sign_algs = sorted(sign_algs, key=cmp_to_key(sort_sign_alg))

        _pat1 = "{}_endpoint_auth_signing_alg_values_supported"
        _pat2 = "{}_endpoint_auth_methods_supported"
        for typ in ["token", "revocation", "introspection"]:
            _provider_info[_pat1.format(typ)] = sign_algs
            _provider_info[_pat2.format(typ)] = AUTH_METHODS_SUPPORTED

        if provider_config:
            _provider_info.update(provider_config)

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

    def create_providerinfo(self, pcr_class=ASConfigurationResponse,
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
                self.baseurl, endp.url)

        if setup and isinstance(setup, dict):
            for key in pcr_class.c_param.keys():
                if key in setup:
                    _provider_info[key] = setup[key]

        _provider_info["issuer"] = self.baseurl
        _provider_info["version"] = "3.0"

        return _provider_info

    def providerinfo_endpoint(self, **kwargs):
        _log_info = logger.info

        _log_info("@providerinfo_endpoint")
        try:
            _response = self.create_providerinfo()
            _log_info("provider_info_response: %s" % (_response.to_dict(),))

            headers = [("Cache-Control", "no-store"), ("x-ffo", "bar")]
            if 'handle' in kwargs:
                (key, timestamp) = kwargs['handle']
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

    @staticmethod
    def verify_code_challenge(code_verifier, code_challenge,
                              code_challenge_method='S256'):
        """
        Verify a PKCE (RFC7636) code challenge

        :param code_verifier: The origin
        :param code_challenge: The transformed verifier used as challenge
        :return:
        """
        _h = CC_METHOD[code_challenge_method](
            code_verifier.encode()).hexdigest()
        _cc = b64e(_h.encode())
        if _cc.decode() != code_challenge:
            logger.error('PCKE Code Challenge check failed')
            err = TokenErrorResponse(error="invalid_request",
                                     error_description="PCKE check failed")
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")
        return True

    def do_access_token_response(self, access_token, atinfo, state,
                                 refresh_token=None):
        _tinfo = {'access_token': access_token, 'expires_in': atinfo['exp'],
                  'token_type': 'bearer', 'state': state}
        try:
            _tinfo['scope'] = atinfo['scope']
        except KeyError:
            pass

        if refresh_token:
            _tinfo['refresh_token'] = refresh_token

        return AccessTokenResponse(**by_schema(AccessTokenResponse, **_tinfo))

    def code_grant_type(self, areq):
        # assert that the code is valid
        try:
            _info = self.sdb[areq["code"]]
        except KeyError:
            err = TokenErrorResponse(error="invalid_grant",
                                     error_description="Unknown access grant")
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        authzreq = json.loads(_info['authzreq'])
        if 'code_verifier' in areq:
            try:
                _method = authzreq['code_challenge_method']
            except KeyError:
                _method = 'S256'

            resp = self.verify_code_challenge(areq['code_verifier'],
                                              authzreq['code_challenge'],
                                              _method)
            if resp:
                return resp

        if 'state' in areq:
            if self.sdb[areq['code']]['state'] != areq['state']:
                logger.error('State value mismatch')
                err = TokenErrorResponse(error="unauthorized_client")
                return Unauthorized(err.to_json(), content="application/json")

        resp = self.token_scope_check(areq, _info)
        if resp:
            return resp

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _info:
            assert areq["redirect_uri"] == _info["redirect_uri"]

        issue_refresh = False
        if 'scope' in authzreq and 'offline_access' in authzreq['scope']:
            if authzreq['response_type'] == 'code':
                issue_refresh = True

        try:
            _tinfo = self.sdb.upgrade_to_token(areq["code"],
                                               issue_refresh=issue_refresh)
        except AccessCodeUsed:
            err = TokenErrorResponse(error="invalid_grant",
                                     error_description="Access grant used")
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        logger.debug("_tinfo: %s" % _tinfo)

        atr = AccessTokenResponse(**by_schema(AccessTokenResponse, **_tinfo))

        logger.debug("AccessTokenResponse: %s" % atr)

        return Response(atr.to_json(), content="application/json")

    def client_credentials_grant_type(self, areq):
        _at = self.token_handler.get_access_token(areq['client_id'],
                                                  scope=areq['scope'],
                                                  grant_type='client_credentials')
        _info = self.token_handler.token_factory.get_info(_at)
        try:
            _rt = self.token_handler.get_refresh_token(
                self.baseurl, _info['access_token'], 'client_credentials')
        except NotAllowed:
            atr = self.do_access_token_response(_at, _info, areq['state'])
        else:
            atr = self.do_access_token_response(_at, _info, areq['state'], _rt)

        return Response(atr.to_json(), content="application/json")

    def password_grant_type(self, areq):
        _at = self.token_handler.get_access_token(areq['client_id'],
                                                  scope=areq['scope'],
                                                  grant_type='password')
        _info = self.token_handler.token_factory.get_info(_at)
        try:
            _rt = self.token_handler.get_refresh_token(
                self.baseurl, _info['access_token'], 'password')
        except NotAllowed:
            atr = self.do_access_token_response(_at, _info, areq['state'])
        else:
            atr = self.do_access_token_response(_at, _info, areq['state'], _rt)

        return Response(atr.to_json(), content="application/json")

    def refresh_token_grant_type(self, areq):
        at = self.token_handler.refresh_access_token(
            self.baseurl, areq['access_token'], 'refresh_token')

        atr = AccessTokenResponse(**by_schema(AccessTokenResponse, **at))
        return Response(atr.to_json(), content="application/json")

    def token_endpoint(self, authn="", **kwargs):
        """
        This is where clients come to get their access tokens
        """

        _sdb = self.sdb

        logger.debug("- token -")
        body = kwargs["request"]
        logger.debug("body: %s" % body)

        areq = AccessTokenRequest().deserialize(body, "urlencoded")

        try:
            client_id = self.client_authn(self, areq, authn)
        except FailedAuthentication as err:
            logger.error(err)
            err = TokenErrorResponse(error="unauthorized_client",
                                     error_description="%s" % err)
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        logger.debug("AccessTokenRequest: %s" % areq)

        _grant_type = areq["grant_type"]
        if _grant_type == "authorization_code":
            return self.code_grant_type(areq)
        elif _grant_type == 'client_credentials':
            return self.client_credentials_grant_type(areq)
        elif _grant_type == 'password':
            return self.password_grant_type(areq)
        elif _grant_type == 'refresh_token':
            return self.refresh_token_grant_type(areq)
        else:
            raise UnSupported('grant_type: {}'.format(_grant_type))

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

    @staticmethod
    def token_access(endpoint, client_id, token_info):
        # simple rules: if client_id in azp or aud it's allow to introspect
        # to revoke it has to be in azr
        allow = False
        if endpoint == 'revocation_endpoint':
            if 'azr' in token_info and client_id == token_info['azr']:
                allow = True
            elif len(token_info['aud']) == 1 and token_info['aud'] == [
                client_id]:
                allow = True
        else:  # has to be introspection endpoint
            if 'azr' in token_info and client_id == token_info['azr']:
                allow = True
            elif 'aud' in token_info:
                if client_id in token_info['aud']:
                    allow = True
        return allow

    def get_token_info(self, authn, req, endpoint):
        """

        :param authn:
        :param req:
        :return:
        """
        try:
            client_id = self.client_authn(self, req, authn)
        except FailedAuthentication as err:
            logger.error(err)
            err = TokenErrorResponse(error="unauthorized_client",
                                     error_description="%s" % err)
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        logger.debug('{}: {} requesting {}'.format(endpoint, client_id,
                                                   req.to_dict()))

        try:
            token_type = req['token_type_hint']
        except KeyError:
            try:
                _info = self.sdb.token_factory['access_token'].info(
                    req['token'])
            except KeyError:
                try:
                    _info = self.sdb.token_factory['refresh_token'].get_info(
                        req['token'])
                except KeyError:
                    raise
                else:
                    token_type = 'refresh_token'
            else:
                token_type = 'access_token'
        else:
            try:
                _info = self.sdb.token_factory[token_type].get_info(
                    req['token'])
            except KeyError:
                raise

        if not self.token_access(endpoint, client_id, _info):
            return BadRequest()

        return client_id, token_type, _info

    def revocation_endpoint(self, authn='', request=None, **kwargs):
        """
        Implements RFC7009 allows a client to invalidate an access or refresh
        token.

        :param authn: Client Authentication information
        :param request: The revocation request
        :param kwargs:
        :return:
        """

        trr = TokenRevocationRequest().deserialize(request, "urlencoded")

        resp = self.get_token_info(authn, trr, 'revocation_endpoint')

        if isinstance(resp, Response):
            return resp
        else:
            client_id, token_type, _info = resp

        logger.info('{} token revocation: {}'.format(client_id, trr.to_dict()))

        try:
            self.sdb.token_factory[token_type].invalidate(trr['token'])
        except KeyError:
            return BadRequest()
        else:
            return Response('OK')

    def introspection_endpoint(self, authn='', request=None, **kwargs):
        """
        Implements RFC7662

        :param authn: Client Authentication information
        :param request: The introspection request
        :param kwargs:
        :return:
        """

        tir = TokenIntrospectionRequest().deserialize(request, "urlencoded")

        resp = self.get_token_info(authn, tir, 'introspection_endpoint')

        if isinstance(resp, Response):
            return resp
        else:
            client_id, token_type, _info = resp

        logger.info('{} token introspection: {}'.format(client_id,
                                                        tir.to_dict()))

        ir = TokenIntrospectionResponse(
            active=self.sdb.token_factory[token_type].is_valid(_info),
            **_info.to_dict())

        ir.weed()

        return Response(ir.to_json(), content="application/json")
