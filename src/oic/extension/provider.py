import logging
import os
import traceback
import six
from future.backports.urllib.parse import parse_qs
from future.backports.urllib.parse import splitquery
from jwkest import jws
from jwkest import jwe
import sys

from oic.exception import UnSupported, FailedAuthentication
from oic.exception import UnknownAssertionType
from oic.extension.dynreg import ClientInfoResponse
from oic.extension.dynreg import ClientUpdateRequest
from oic.extension.dynreg import ModificationForbidden
from oic.extension.dynreg import RegistrationRequest
from oic.extension.dynreg import InvalidRedirectUri
from oic.extension.dynreg import ClientRegistrationError
from oic.extension.dynreg import MissingPage
from oic.oauth2 import provider, AccessTokenRequest, TokenErrorResponse, \
    AccessTokenResponse, by_schema
from oic.oauth2 import rndstr
from oic.oauth2.provider import Endpoint
from oic.oauth2.exception import VerificationError
from oic.oic import ProviderConfigurationResponse
from oic.oic.message import SCOPE2CLAIMS
from oic.oic.provider import RegistrationEndpoint
from oic.oic.provider import STR
from oic.oic.provider import CAPABILITIES
from oic.oic.provider import secret
from oic.utils.authn.client import AuthnFailure
from oic.utils.authn.client import UnknownAuthnMethod
from oic.utils.authn.client import get_client_id
from oic.utils.http_util import Unauthorized
from oic.utils.http_util import NoContent
from oic.utils.http_util import Response
from oic.utils.http_util import BadRequest
from oic.utils.http_util import Forbidden
from oic.utils.keyio import KeyBundle, KeyJar
from oic.utils.sdb import AccessCodeUsed
from oic.utils.time_util import utc_time_sans_frac

__author__ = 'roland'


logger = logging.getLogger(__name__)


class ClientInfoEndpoint(Endpoint):
    etype = "clientinfo"


class Provider(provider.Provider):
    """
    A OAuth2 RP that knows all the OAuth2 extensions I've implemented
    """
    def __init__(self, name, sdb, cdb, authn_broker, authz, client_authn,
                 symkey="", urlmap=None, iv=0, default_scope="",
                 ca_bundle=None, seed=b"", client_authn_methods=None,
                 authn_at_registration="", client_info_url="",
                 secret_lifetime=86400, jwks_uri=None, keyjar=None,
                 capabilities=None, verify_ssl=True):

        if not name.endswith("/"):
            name += "/"
        provider.Provider.__init__(self, name, sdb, cdb, authn_broker, authz,
                                   client_authn, symkey, urlmap, iv,
                                   default_scope, ca_bundle)

        self.endp.extend([RegistrationEndpoint, ClientInfoEndpoint])

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

        self.keyjar = keyjar
        if self.keyjar is None:
            self.keyjar = KeyJar(verify_ssl=self.verify_ssl)

        if capabilities:
            self.verify_capabilities(capabilities)
            self.capabilities = ProviderConfigurationResponse(**capabilities)
        else:
            self.capabilities = self.provider_features()
        self.baseurl = ""

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
                logger.debug("keys for %s: [%s]" % (
                    client_id,
                    ",".join(["%s" % x for x in self.keyjar[client_id]])))
            except KeyError:
                pass
        except Exception as err:
            logger.error("Failed to load client keys: %s" % request.to_dict())
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

    def create_new_client(self, request):
        """

        :param request: The Client registration request
        :return: The client_id
        """

        _cinfo = request.to_dict()

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
        self.cdb[_id] = _cinfo


        return _id

    def client_info(self, client_id):
        _cinfo = self.cdb[client_id].copy()
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

    def registration_endpoint(self, **kwargs):
        """

        :param request: The request
        :param authn: Client authentication information
        :param kwargs: extra keyword arguments
        :return: A Response instance
        """

        _request = RegistrationRequest().deserialize(kwargs['request'], "json")
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

        # authenticated client
        if self.authn_at_registration:
            try:
                _ = self.verify_client(kwargs['environ'], _request,
                                       self.authn_at_registration)
            except (AuthnFailure, UnknownAssertionType):
                return Unauthorized()

        client_id = self.create_new_client(_request)

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
            _ = self.verify_client(kwargs['environ'], kwargs['request'],
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
            client = self.client_authn(self, areq, authn)
        except FailedAuthentication as err:
            err = TokenErrorResponse(error="unauthorized_client",
                                     error_description="%s" % err)
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        logger.debug("AccessTokenRequest: %s" % areq)

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
            _tinfo = _sdb.upgrade_to_token(areq["code"], issue_refresh=True)
        except AccessCodeUsed:
            err = TokenErrorResponse(error="invalid_grant",
                                     error_description="Access grant used")
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        logger.debug("_tinfo: %s" % _tinfo)

        atr = AccessTokenResponse(**by_schema(AccessTokenResponse, **_tinfo))

        logger.debug("AccessTokenResponse: %s" % atr)

        return Response(atr.to_json(), content="application/json")
