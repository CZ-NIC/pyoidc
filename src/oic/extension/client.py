import logging
import random
import string
import hashlib

from jwkest import b64e
from oic import oauth2
from oic.extension.message import TokenRevocationRequest
from oic.extension.message import ClientUpdateRequest
from oic.extension.message import ClientInfoResponse
from oic.extension.message import RegistrationRequest
from oic.extension.message import ClientRegistrationError
from oic.extension.message import TokenIntrospectionRequest
from oic.extension.message import TokenIntrospectionResponse

from oic.exception import PyoidcError
from oic.exception import AuthzError

from oic.oic import OIDCONF_PATTERN
from oic.oic.message import AuthorizationResponse
from oic.utils.http_util import SUCCESSFUL
from oic.utils.keyio import KeyJar

from oic.oauth2.message import ErrorResponse
from oic.oauth2.exception import Unsupported
from oic.oauth2.message import AuthorizationRequest
from oic.oauth2.message import ASConfigurationResponse

logger = logging.getLogger(__name__)

__author__ = 'roland'

# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------

RESPONSE2ERROR = {
    "ClientInfoResponse": [ClientRegistrationError],
    "ClientUpdateRequest": [ClientRegistrationError]
}

BASECH = string.ascii_letters + string.digits + '-._~'


def unreserved(size=64):
    """
    Returns a string of random ascii characters, digits and unreserve characters

    :param size: The length of the string
    :return: string
    """

    return "".join([random.choice(BASECH) for _ in range(size)])


CC_METHOD = {
    'S256': hashlib.sha256,
    'S384': hashlib.sha384,
    'S512': hashlib.sha512,
}


class Client(oauth2.Client):
    def __init__(self, client_id=None, ca_certs=None,
                 client_authn_method=None, keyjar=None, verify_ssl=True,
                 config=None):
        oauth2.Client.__init__(self, client_id=client_id, ca_certs=ca_certs,
                               client_authn_method=client_authn_method,
                               keyjar=keyjar, verify_ssl=verify_ssl,
                               config=config)
        self.allow = {}
        self.request2endpoint.update({
            "RegistrationRequest": "registration_endpoint",
            "ClientUpdateRequest": "clientinfo_endpoint",
            'TokenIntrospectionRequest': 'introspection_endpoint',
            'TokenRevocationRequest': 'revocation_endpoint'
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

    def _token_interaction_setup(self, request_args=None, **kwargs):
        if request_args is None or 'token' not in request_args:
            token = self.get_token(**kwargs)
            try:
                _token_type_hint = kwargs['token_type_hint']
            except KeyError:
                _token_type_hint = 'access_token'

            request_args = {'token_type_hint': _token_type_hint,
                            'token': getattr(token, _token_type_hint)}

        if "client_id" not in request_args:
            request_args["client_id"] = self.client_id
        elif not request_args["client_id"]:
            request_args["client_id"] = self.client_id

        return request_args

    def construct_TokenIntrospectionRequest(self,
                                            request=TokenIntrospectionRequest,
                                            request_args=None, extra_args=None,
                                            **kwargs):
        request_args = self._token_interaction_setup(request_args, **kwargs)
        return self.construct_request(request, request_args, extra_args)

    def construct_TokenRevocationRequest(self,
                                         request=TokenRevocationRequest,
                                         request_args=None, extra_args=None,
                                         **kwargs):

        request_args = self._token_interaction_setup(request_args, **kwargs)

        return self.construct_request(request, request_args, extra_args)

    def do_op(self, request, body_type='', method='GET', request_args=None,
              extra_args=None, http_args=None, response_cls=None, **kwargs):

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

    def do_client_registration(self, request=RegistrationRequest,
                               body_type="", method="GET",
                               request_args=None, extra_args=None,
                               http_args=None,
                               response_cls=ClientInfoResponse,
                               **kwargs):

        return self.do_op(request=request, body_type=body_type, method=method,
                          request_args=request_args, extra_args=extra_args,
                          http_args=http_args, response_cls=response_cls,
                          **kwargs)

    def do_client_read_request(self, request=ClientUpdateRequest,
                               body_type="", method="GET",
                               request_args=None, extra_args=None,
                               http_args=None,
                               response_cls=ClientInfoResponse,
                               **kwargs):

        return self.do_op(request=request, body_type=body_type, method=method,
                          request_args=request_args, extra_args=extra_args,
                          http_args=http_args, response_cls=response_cls,
                          **kwargs)

    def do_client_update_request(self, request=ClientUpdateRequest,
                                 body_type="", method="PUT",
                                 request_args=None, extra_args=None,
                                 http_args=None,
                                 response_cls=ClientInfoResponse,
                                 **kwargs):

        return self.do_op(request=request, body_type=body_type, method=method,
                          request_args=request_args, extra_args=extra_args,
                          http_args=http_args, response_cls=response_cls,
                          **kwargs)

    def do_client_delete_request(self, request=ClientUpdateRequest,
                                 body_type="", method="DELETE",
                                 request_args=None, extra_args=None,
                                 http_args=None,
                                 response_cls=ClientInfoResponse,
                                 **kwargs):

        return self.do_op(request=request, body_type=body_type, method=method,
                          request_args=request_args, extra_args=extra_args,
                          http_args=http_args, response_cls=response_cls,
                          **kwargs)

    def do_token_introspection(
            self, request=TokenIntrospectionRequest, body_type="json",
            method="POST", request_args=None, extra_args=None,
            http_args=None, response_cls=TokenIntrospectionResponse, **kwargs):

        return self.do_op(request=request, body_type=body_type, method=method,
                          request_args=request_args, extra_args=extra_args,
                          http_args=http_args, response_cls=response_cls,
                          **kwargs)

    def do_token_revocation(
            self, request=TokenRevocationRequest, body_type="",
            method="POST", request_args=None, extra_args=None,
            http_args=None, response_cls=None, **kwargs):

        return self.do_op(request=request, body_type=body_type, method=method,
                          request_args=request_args, extra_args=extra_args,
                          http_args=http_args, response_cls=response_cls,
                          **kwargs)

    def add_code_challenge(self):
        try:
            cv_len = self.config['code_challenge']['length']
        except KeyError:
            cv_len = 64  # Use default

        code_verifier = unreserved(cv_len)
        _cv = code_verifier.encode()

        try:
            _method = self.config['code_challenge']['method']
        except KeyError:
            _method = 'S256'

        try:
            _h = CC_METHOD[_method](_cv).hexdigest()
            code_challenge = b64e(_h.encode()).decode()
        except KeyError:
            raise Unsupported(
                'PKCE Transformation method:{}'.format(_method))

        # TODO store code_verifier

        return {"code_challenge": code_challenge,
                "code_challenge_method": _method}, code_verifier

    def do_authorization_request(
            self, request=AuthorizationRequest, state="", body_type="",
            method="GET", request_args=None, extra_args=None, http_args=None,
            response_cls=AuthorizationResponse, **kwargs):

        if 'code_challenge' in self.config and self.config['code_challenge']:
            _args, code_verifier = self.add_code_challenge()
            request_args.update(_args)

        oauth2.Client.do_authorization_request(self,
                                               request=request, state=state,
                                               body_type=body_type,
                                               method=method,
                                               request_args=request_args,
                                               extra_args=extra_args,
                                               http_args=http_args,
                                               response_cls=response_cls,
                                               **kwargs)

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

        if self.event_store:
            self.event_store.store('http response header', r.headers)

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
            self.store_response(resp, response.text)
            self.store_registration_info(resp)
        else:
            resp = ErrorResponse().deserialize(response.text, "json")
            try:
                resp.verify()
                self.store_response(resp, response.text)
            except Exception as err:
                raise PyoidcError(
                    'Registration failed: {}'.format(response.text))

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
