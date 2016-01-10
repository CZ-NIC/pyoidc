import logging
from oic.extension.message import ASConfigurationResponse
import requests

from six.moves.urllib import parse as urlparse

from oic import oauth2
from oic.exception import PyoidcError
from oic.exception import AuthzError
from oic.oic import OIDCONF_PATTERN
from oic.oic.message import AuthorizationResponse
from oic.utils.keyio import KeyJar
from oic.oauth2 import ErrorResponse
from oic.oauth2 import Message
from oic.oauth2 import message
from oic.oauth2 import SINGLE_REQUIRED_STRING
from oic.oauth2 import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oic.oauth2 import REQUIRED_LIST_OF_STRINGS
from oic.oauth2 import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2 import SINGLE_OPTIONAL_STRING
from oic.oauth2 import SINGLE_OPTIONAL_INT

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
                        response_cls=ASConfigurationResponse,
                        serv_pattern=OIDCONF_PATTERN):
        if issuer.endswith("/"):
            _issuer = issuer[:-1]
        else:
            _issuer = issuer

        url = serv_pattern % _issuer

        pcr = None
        r = self.http_request(url)
        if r.status_code == 200:
            if self.event_store is not None:
                self.event_store.store('response_msg', r.text, ref=url)
            pcr = response_cls().from_json(r.text)
        elif r.status_code == 302:
            while r.status_code == 302:
                r = self.http_request(r.headers["location"])
                if r.status_code == 200:
                    pcr = response_cls().from_json(r.text)
                    break

        if pcr is None:
            raise PyoidcError("Trying '%s', status %s" % (url, r.status_code))

        if self.event_store is not None:
            self.event_store.store('protocol_response', (pcr, r.text), ref=url)

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
            self.store_response(resp, response.text)
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
