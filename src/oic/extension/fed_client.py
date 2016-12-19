import logging

from oic.exception import RegistrationError

from oic import oic
from oic.extension.oidc_fed import ClientMetadataStatement
from oic.extension.oidc_fed import FederationEntity
from oic.oauth2 import ErrorResponse
from oic.oauth2 import MissingRequiredAttribute
from oic.oauth2 import sanitize
from oic.oic import RegistrationResponse

try:
    from json import JSONDecodeError
except ImportError:  # Only works for >= 3.5
    _decode_err = ValueError
else:
    _decode_err = JSONDecodeError

logger = logging.getLogger(__name__)

__author__ = 'roland'


class Client(oic.Client, FederationEntity):
    def __init__(self, client_id=None, ca_certs=None,
                 client_prefs=None, client_authn_method=None, keyjar=None,
                 verify_ssl=True, config=None, client_cert=None,
                 fo_keyjar=None, signed_metadata_statements=None,
                 fo_priority_order=None):
        oic.Client.__init__(
            self, client_id=client_id, ca_certs=ca_certs,
            client_prefs=client_prefs, client_authn_method=client_authn_method,
            keyjar=keyjar, verify_ssl=verify_ssl, config=config,
            client_cert=client_cert)

        FederationEntity.__init__(
            self, signed_metadata_statements=signed_metadata_statements,
            fo_keyjar=fo_keyjar, keyjar=keyjar, eid=client_id,
            fo_priority_order=fo_priority_order, ms_cls=ClientMetadataStatement)

    def handle_registration_info(self, response):
        err_msg = 'Got error response: {}'
        unk_msg = 'Unknown response: {}'
        if response.status_code in [200, 201]:
            resp = RegistrationResponse().deserialize(response.text, "json")
            # Some implementations sends back a 200 with an error message inside
            if resp.verify():  # got a proper registration response
                resp = self.get_metadata_statement(resp)
                if resp is None: # No metadata statement that I can use
                    raise RegistrationError('No trusted metadata')
                self.store_response(resp, response.text)
                self.store_registration_info(resp)
            else:
                resp = ErrorResponse().deserialize(response.text, "json")
                if resp.verify():
                    logger.error(err_msg.format(sanitize(resp.to_json())))
                    if self.events:
                        self.events.store('protocol response', resp)
                    raise RegistrationError(resp.to_dict())
                else:  # Something else
                    logger.error(unk_msg.format(sanitize(response.text)))
                    raise RegistrationError(response.text)
        else:
            try:
                resp = ErrorResponse().deserialize(response.text, "json")
            except _decode_err:
                logger.error(unk_msg.format(sanitize(response.text)))
                raise RegistrationError(response.text)

            if resp.verify():
                logger.error(err_msg.format(sanitize(resp.to_json())))
                if self.events:
                    self.events.store('protocol response', resp)
                raise RegistrationError(resp.to_dict())
            else:  # Something else
                logger.error(unk_msg.format(sanitize(response.text)))
                raise RegistrationError(response.text)

        return resp

    def federated_client_registration_request(self, **kwargs):
        req = ClientMetadataStatement()

        try:
            pp = kwargs['fo_pattern']
        except KeyError:
            pp = '.'
        req['metadata_statements'] = self.pick_signed_metadata_statements(pp)

        try:
            req['redirect_uris'] = kwargs['redirect_uris']
        except KeyError:
            try:
                req["redirect_uris"] = self.redirect_uris
            except AttributeError:
                raise MissingRequiredAttribute("redirect_uris", kwargs)

        return req

    def register(self, url, **kwargs):
        try:
            reg_type = kwargs['registration_type']
        except KeyError:
            reg_type = 'core'

        if reg_type == 'federation':
            req = self.federated_client_registration_request(**kwargs)
        else:
            req = self.create_registration_request(**kwargs)

        if self.events:
            self.events.store('Protocol request', req)

        headers = {"content-type": "application/json"}

        rsp = self.http_request(url, "POST", data=req.to_json(),
                                headers=headers)

        return self.handle_registration_info(rsp)

    def handle_provider_config(self, pcr, issuer, keys=True, endpoints=True):
        pass
