import logging

from oic.oic import provider
from oic.extension.oidc_fed import ClientMetadataStatement
from oic.extension.oidc_fed import FederationEntity
from oic.oic.message import OpenIDSchema, RegistrationRequest
from oic.utils.http_util import Created
from oic.utils.http_util import Response
from oic.utils.sanitize import sanitize

logger = logging.getLogger(__name__)


class Provider(provider.Provider, FederationEntity):
    def __init__(self, name, sdb, cdb, authn_broker, userinfo, authz,
                 client_authn, symkey, urlmap=None, ca_certs="", keyjar=None,
                 hostname="", template_lookup=None, template=None,
                 verify_ssl=True, capabilities=None, schema=OpenIDSchema,
                 jwks_uri='', jwks_name='', baseurl=None, client_cert=None,
                 fo_keyjar=None, signed_metadata_statements=None,
                 fo_priority_order=None):
        provider.Provider.__init__(
            self, name, sdb, cdb, authn_broker, userinfo, authz,
            client_authn, symkey, urlmap=urlmap, ca_certs=ca_certs,
            keyjar=keyjar, hostname=hostname, template_lookup=template_lookup,
            template=template, verify_ssl=verify_ssl, capabilities=capabilities,
            schema=schema, jwks_uri=jwks_uri, jwks_name=jwks_name,
            baseurl=baseurl, client_cert=client_cert)

        FederationEntity.__init__(
            self, signed_metadata_statements = signed_metadata_statements,
            fo_keyjar=fo_keyjar, keyjar=keyjar, eid=name,
            fo_priority_order=fo_priority_order, ms_cls=ClientMetadataStatement
        )

    def discovery_endpoint(self, request, handle=None, **kwargs):
        pass

    def registration_endpoint(self, request, authn=None, **kwargs):
        logger.debug("@registration_endpoint: <<%s>>" % sanitize(request))

        try:
            request = ClientMetadataStatement().deserialize(request, "json")
        except ValueError:
            request = ClientMetadataStatement().deserialize(request)

        logger.info("registration_request:%s" % sanitize(request.to_dict()))

        request_args = self.get_metadata_statement(request)
        request = RegistrationRequest(**request_args)

        result = self.client_registration_setup(request)
        if isinstance(result, Response):
            return result

        return Created(result.to_json(), content="application/json",
                       headers=[("Cache-Control", "no-store")])
