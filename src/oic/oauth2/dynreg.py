import logging
import requests

from six.moves.urllib import parse as urlparse

from oic import oauth2
from oic.exception import UnSupported
from oic.exception import UnknownAssertionType
from oic.exception import PyoidcError
from oic.exception import AuthzError
from oic.oic import OIDCONF_PATTERN
from oic.oic.message import ProviderConfigurationResponse, AuthorizationResponse
from oic.oic.provider import secret
from oic.oic.provider import RegistrationEndpoint
from oic.oic.provider import Endpoint
from oic.utils.keyio import KeyJar
from oic.utils.time_util import utc_time_sans_frac
from oic.oauth2 import provider
from oic.oauth2 import rndstr
from oic.oauth2 import ErrorResponse
from oic.oauth2 import Message
from oic.oauth2 import message
from oic.oauth2 import SINGLE_REQUIRED_STRING
from oic.oauth2 import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oic.oauth2 import REQUIRED_LIST_OF_STRINGS
from oic.oauth2 import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2 import SINGLE_OPTIONAL_STRING
from oic.oauth2 import SINGLE_OPTIONAL_INT
from oic.oauth2.exception import VerificationError
from oic.utils.authn.client import AuthnFailure, get_client_id
from oic.utils.http_util import Unauthorized
from oic.utils.http_util import NoContent
from oic.utils.http_util import Response
from oic.utils.http_util import BadRequest
from oic.utils.http_util import Forbidden

import six
if six.PY3:
    from urllib.parse import splitquery
else:
    from urllib import splitquery


logger = logging.getLogger(__name__)

__author__ = 'roland'

# -----------------------------------------------------------------------------
SUCCESSFUL = [200, 201, 202, 203, 204, 205, 206]


class InvalidRedirectUri(Exception):
    pass


class MissingPage(Exception):
    pass


class ModificationForbidden(Exception):
    pass


class RegistrationRequest(Message):
    c_param = {
        "redirect_uris": REQUIRED_LIST_OF_STRINGS,
        "client_name": SINGLE_OPTIONAL_STRING,
        "client_uri": SINGLE_OPTIONAL_STRING,
        "logo_uri": SINGLE_OPTIONAL_STRING,
        "contacts": OPTIONAL_LIST_OF_STRINGS,
        "tos_uri": SINGLE_OPTIONAL_STRING,
        "policy_uri": SINGLE_OPTIONAL_STRING,
        "token_endpoint_auth_method": SINGLE_OPTIONAL_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "grant_types": OPTIONAL_LIST_OF_STRINGS,
        "response_types": OPTIONAL_LIST_OF_STRINGS,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "software_id": SINGLE_OPTIONAL_STRING,
        "software_version": SINGLE_OPTIONAL_STRING,
    }

    def verify(self, **kwargs):
        if "initiate_login_uri" in self:
            assert self["initiate_login_uri"].startswith("https:")

        if "redirect_uris" in self:
            for uri in self["redirect_uris"]:
                if urlparse.urlparse(uri).fragment:
                    raise InvalidRedirectUri(
                        "redirect_uri contains fragment: %s" % uri)

        for uri in ["client_uri", "logo_uri", "tos_uri", "policy_uri"]:
            if uri in self:
                try:
                    resp = requests.request("GET", str(self[uri]),
                                            allow_redirects=True,
                                            verify=False)
                except requests.ConnectionError:
                    raise MissingPage(self[uri])

                if resp.status_code not in SUCCESSFUL:
                    raise MissingPage(self[uri])

        if "grant_types" in self and "response_types" in self:
            for typ in self["grant_types"]:
                if typ == "authorization_code":
                    try:
                        assert "code" in self["response_types"]
                    except AssertionError:
                        self["response_types"].append("code")
                elif typ == "implicit":
                    try:
                        assert "token" in self["response_types"]
                    except AssertionError:
                        self["response_types"].append("token")

        return super(RegistrationRequest, self).verify(**kwargs)


class ClientInfoResponse(RegistrationRequest):
    c_param = RegistrationRequest.c_param.copy()
    c_param.update({
        "client_id": SINGLE_REQUIRED_STRING,
        "client_secret": SINGLE_OPTIONAL_STRING,
        "client_id_issued_at": SINGLE_OPTIONAL_INT,
        "client_secret_expires_at": SINGLE_OPTIONAL_INT,
        "registration_access_token": SINGLE_REQUIRED_STRING,
        "registration_client_uri": SINGLE_REQUIRED_STRING
    })


class ClientRegistrationError(ErrorResponse):
    c_param = ErrorResponse.c_param.copy()
    c_param.update({"state": SINGLE_OPTIONAL_STRING})
    c_allowed_values = ErrorResponse.c_allowed_values.copy()
    c_allowed_values.update({"error": ["invalid_redirect_uri",
                                       "invalid_client_metadata",
                                       "invalid_client_id"]})


class ClientUpdateRequest(RegistrationRequest):
    c_param = RegistrationRequest.c_param.copy()
    c_param.update({
        "client_id": SINGLE_REQUIRED_STRING,
        "client_secret": SINGLE_OPTIONAL_STRING,
    })


MSG = {
    "RegistrationRequest": RegistrationRequest,
    "ClientInfoResponse": ClientInfoResponse,
    "ClientRegistrationError": ClientRegistrationError,
    "ClientUpdateRequest": ClientUpdateRequest
}


def factory(msgtype):
    try:
        return MSG[msgtype]
    except KeyError:
        return message.factory(msgtype)


# -----------------------------------------------------------------------------
class ClientInfoEndpoint(Endpoint):
    etype = "clientinfo"


class Provider(provider.Provider):
    def __init__(self, name, sdb, cdb, authn_broker, authz, client_authn,
                 symkey="", urlmap=None, iv=0, default_scope="",
                 ca_bundle=None, seed=b"", client_authn_methods=None,
                 authn_at_registration="", client_info_url="",
                 secret_lifetime=86400):

        if not name.endswith("/"):
            name += "/"
        provider.Provider.__init__(self, name, sdb, cdb, authn_broker, authz,
                                   client_authn, symkey, urlmap, iv,
                                   default_scope, ca_bundle)

        self.endp.extend([RegistrationEndpoint, ClientInfoEndpoint])

        # dictionary of client authentication methods
        self.client_authn_methods = client_authn_methods
        if authn_at_registration:
            assert authn_at_registration in client_authn_methods
        self.authn_at_registration = authn_at_registration
        self.seed = seed
        self.client_info_url = client_info_url
        self.secret_lifetime = secret_lifetime

    # @staticmethod
    # def _uris_to_dict(uris):
    # ruri = {}
    # for uri in uris:
    #         base, query = urllib.splitquery(uri)
    #         if query:
    #             try:
    #                 ruri[base].append(urlparse.parse_qs(query))
    #             except KeyError:
    #                 ruri[base] = [urlparse.parse_qs(query)]
    #         else:
    #             ruri[base] = [""]
    #     return ruri
    #
    # @staticmethod
    # def _dict_to_uris(spec):
    #     _uri = []
    #     for url, qlist in spec.items():
    #         for query in qlist:
    #             if query:
    #                 _uri.append("%s?%s" % (url, query))
    #             else:
    #                 _uri.append(url)
    #     return _uri

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

    def registration_endpoint(self, request, environ, **kwargs):
        """

        :param request: The request
        :param authn: Client authentication information
        :param kwargs: extra keyword arguments
        :return: A Response instance
        """

        _request = RegistrationRequest().deserialize(request, "json")
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
                _ = self.verify_client(environ, _request,
                                       self.authn_at_registration)
            except (AuthnFailure, UnknownAssertionType):
                return Unauthorized()

        client_id = self.create_new_client(_request)

        return self.client_info(client_id)

    def client_info_endpoint(self, request, environ,
                             method="GET", query="", **kwargs):
        """
        Operations on this endpoint are switched through the use of different
        HTTP methods

        :param request: The request
        :param authn: Client authentication information
        :param method: HTTP method used for the request
        :param query: The query part of the URL used, this is where the
            client_id is supposed to reside.
        :param kwargs: extra keyword arguments
        :return: A Response instance
        """

        _query = urlparse.parse_qs(query)
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
            _ = self.verify_client(environ, request, "bearer_header",
                                   client_id=_id)
        except (AuthnFailure, UnknownAssertionType):
            return Unauthorized()

        if method == "GET":
            return self.client_info(_id)
        elif method == "PUT":
            try:
                _request = ClientUpdateRequest().from_json(request)
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

    def providerinfo_endpoint(self):
        pass


RESPONSE2ERROR = {
    "ClientInfoResponse": [ClientRegistrationError],
    "ClientUpdateRequest": [ClientRegistrationError]
}


class Client(oauth2.Client):
    def __init__(self, client_id=None, ca_certs=None,
                 client_authn_method=None, keyjar=None, verify_ssl=True):
        oauth2.Client.__init__(self, client_id=client_id, ca_certs=ca_certs,
                               client_authn_method=client_authn_method,
                               keyjar=keyjar, verify_ssl=verify_ssl)
        self.allow = {}
        self.request2endpoint.update({
            "RegistrationRequest": "registration_endpoint",
            "ClientUpdateRequest": "clientinfo_endpoint"
        })
        self.registration_response = None

    def construct_RegistrationRequest(self, request=RegistrationRequest,
                                      request_args=None, extra_args=None,
                                      **kwargs):

        if request_args is None:
            request_args = {}

        return self.construct_request(request, request_args, extra_args)

    def construct_ClientUpdateRequest(self, request=ClientUpdateRequest,
                                      request_args=None, extra_args=None,
                                      **kwargs):

        if request_args is None:
            request_args = {}

        return self.construct_request(request, request_args, extra_args)

    def do_client_registration(self, request=RegistrationRequest,
                               body_type="", method="GET",
                               request_args=None, extra_args=None,
                               http_args=None,
                               response_cls=ClientInfoResponse,
                               **kwargs):

        url, body, ht_args, csi = self.request_info(request, method,
                                                    request_args, extra_args,
                                                    **kwargs)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        resp = self.request_and_return(url, response_cls, method, body,
                                       body_type, http_args=http_args)

        return resp

    def do_client_read_request(self, request=ClientUpdateRequest,
                               body_type="", method="GET",
                               request_args=None, extra_args=None,
                               http_args=None,
                               response_cls=ClientInfoResponse,
                               **kwargs):

        url, body, ht_args, csi = self.request_info(request, method,
                                                    request_args, extra_args,
                                                    **kwargs)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        resp = self.request_and_return(url, response_cls, method, body,
                                       body_type, http_args=http_args)

        return resp

    def do_client_update_request(self, request=ClientUpdateRequest,
                                 body_type="", method="PUT",
                                 request_args=None, extra_args=None,
                                 http_args=None,
                                 response_cls=ClientInfoResponse,
                                 **kwargs):

        url, body, ht_args, csi = self.request_info(request, method,
                                                    request_args, extra_args,
                                                    **kwargs)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        resp = self.request_and_return(url, response_cls, method, body,
                                       body_type, http_args=http_args)

        return resp

    def do_client_delete_request(self, request=ClientUpdateRequest,
                                 body_type="", method="DELETE",
                                 request_args=None, extra_args=None,
                                 http_args=None,
                                 response_cls=ClientInfoResponse,
                                 **kwargs):

        url, body, ht_args, csi = self.request_info(request, method,
                                                    request_args, extra_args,
                                                    **kwargs)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        resp = self.request_and_return(url, response_cls, method, body,
                                       body_type, http_args=http_args)

        return resp

    def handle_provider_config(self, pcr, issuer, keys=True, endpoints=True):
        """
        Deal with Provider Config Response
        :param pcr: The ProviderConfigResponse instance
        :param issuer: The one I thought should be the issuer of the config
        :param keys: Should I deal with keys
        :param endpoints: Should I deal with endpoints, that is store them
        as attributes in self.
        """

        if "issuer" in pcr:
            _pcr_issuer = pcr["issuer"]
            if pcr["issuer"].endswith("/"):
                if issuer.endswith("/"):
                    _issuer = issuer
                else:
                    _issuer = issuer + "/"
            else:
                if issuer.endswith("/"):
                    _issuer = issuer[:-1]
                else:
                    _issuer = issuer

            try:
                _ = self.allow["issuer_mismatch"]
            except KeyError:
                try:
                    assert _issuer == _pcr_issuer
                except AssertionError:
                    raise PyoidcError(
                        "provider info issuer mismatch '%s' != '%s'" % (
                            _issuer, _pcr_issuer))

            self.provider_info = pcr
        else:
            _pcr_issuer = issuer

        if endpoints:
            for key, val in pcr.items():
                if key.endswith("_endpoint"):
                    setattr(self, key, val)

        if keys:
            if self.keyjar is None:
                self.keyjar = KeyJar()

            self.keyjar.load_keys(pcr, _pcr_issuer)

    def provider_config(self, issuer, keys=True, endpoints=True,
                        response_cls=ProviderConfigurationResponse,
                        serv_pattern=OIDCONF_PATTERN):
        if issuer.endswith("/"):
            _issuer = issuer[:-1]
        else:
            _issuer = issuer

        url = serv_pattern % _issuer

        pcr = None
        r = self.http_request(url)
        if r.status_code == 200:
            pcr = response_cls().from_json(r.text)
        elif r.status_code == 302:
            while r.status_code == 302:
                r = self.http_request(r.headers["location"])
                if r.status_code == 200:
                    pcr = response_cls().from_json(r.text)
                    break

        if pcr is None:
            raise PyoidcError("Trying '%s', status %s" % (url, r.status_code))

        self.handle_provider_config(pcr, issuer, keys, endpoints)

        return pcr

    def store_registration_info(self, reginfo):
        self.registration_response = reginfo
        self.client_secret = reginfo["client_secret"]
        self.client_id = reginfo["client_id"]
        self.redirect_uris = reginfo["redirect_uris"]

    def handle_registration_info(self, response):
        if response.status_code in SUCCESSFUL:
            resp = ClientInfoResponse().deserialize(response.text, "json")
            self.store_registration_info(resp)
        else:
            err = ErrorResponse().deserialize(response.text, "json")
            raise PyoidcError("Registration failed: %s" % err.to_json())

        return resp

    def register(self, url, **kwargs):
        """
        Register the client at an OP

        :param url: The OPs registration endpoint
        :param kwargs: parameters to the registration request
        :return:
        """
        req = self.construct_RegistrationRequest(request_args=kwargs)

        headers = {"content-type": "application/json"}

        rsp = self.http_request(url, "POST", data=req.to_json(),
                                headers=headers)

        return self.handle_registration_info(rsp)

    def parse_authz_response(self, query):
        aresp = self.parse_response(AuthorizationResponse,
                                    info=query,
                                    sformat="urlencoded",
                                    keyjar=self.keyjar)
        if aresp.type() == "ErrorResponse":
            logger.info("ErrorResponse: %s" % aresp)
            raise AuthzError(aresp.error)

        logger.info("Aresp: %s" % aresp)

        return aresp