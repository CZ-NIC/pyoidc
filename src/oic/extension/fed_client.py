import re

import logging

from oic.exception import RegistrationError

from oic.extension.oidc_fed import Operator, ClientMetadataStatement
from oic import oic
from oic.oauth2 import MissingRequiredAttribute, ErrorResponse, sanitize
from oic.oic import RegistrationResponse

try:
    from json import JSONDecodeError
except ImportError:  # Only works for >= 3.5
    _decode_err = ValueError
else:
    _decode_err = JSONDecodeError

logger = logging.getLogger(__name__)

__author__ = 'roland'


class Client(oic.Client):
    def __init__(self, client_id=None, ca_certs=None,
                 client_prefs=None, client_authn_method=None, keyjar=None,
                 verify_ssl=True, config=None, client_cert=None,
                 fo_keyjar=None, signed_metadata_statements=None):
        oic.Client.__init__(
            self, client_id=client_id, ca_certs=ca_certs,
            client_prefs=client_prefs, client_authn_method=client_authn_method,
            keyjar=keyjar, verify_ssl=verify_ssl, config=config,
            client_cert=client_cert)

        self.signed_metadata_statements = {} or signed_metadata_statements
        self.op = Operator(keyjar=keyjar, fo_keyjar=fo_keyjar, httpcli=self,
                           iss=client_id)

    def add_signed_metadata_statement(self, fo, ms):
        try:
            self.signed_metadata_statements[fo].append(ms)
        except KeyError:
            self.signed_metadata_statements[fo] = ms

    def remove_signed_metadata_statement(self, fo, ms):
        self.signed_metadata_statements[fo].remove(ms)

    def pick_signed_metadata_statements(self, pattern):
        comp_pat = re.compile(pattern)
        res = []
        for key, vals in self.signed_metadata_statements.items():
            if comp_pat.search(key):
                res.extend(vals)
        return res

    def register(self, url, **kwargs):
        try:
            reg_type = kwargs['registration_type']
        except KeyError:
            reg_type = 'core'

        if reg_type == 'federation':
            req = ClientMetadataStatement()

            try:
                pp = kwargs['fo_pattern']
            except KeyError:
                pp = '.'
            req['metadata_statements'] = self.pick_signed_metadata_statements(pp)

            if "redirect_uris" not in kwargs:
                try:
                    req["redirect_uris"] = self.redirect_uris
                except AttributeError:
                    raise MissingRequiredAttribute("redirect_uris", kwargs)

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
