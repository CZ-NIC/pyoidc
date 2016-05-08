from oic.oauth2 import SINGLE_REQUIRED_STRING
from oic.oauth2 import SINGLE_OPTIONAL_STRING
from oic.oauth2.message import OPTIONAL_LIST_OF_STRINGS
from oic.oic import message
from oic.oic.message import JasonWebToken, OPTIONAL_MESSAGE

__author__ = 'roland'


class SoftwareStatement(JasonWebToken):
    c_param = JasonWebToken.c_param.copy()
    c_param.update({
        "software_id": SINGLE_OPTIONAL_STRING,
        'client_name': SINGLE_OPTIONAL_STRING,
        'client_uri': SINGLE_OPTIONAL_STRING,
        'signed_key': SINGLE_REQUIRED_STRING
    })


class RegistrationRequest(message.RegistrationRequest):
    c_param = message.RegistrationRequest.c_param.copy()
    c_param.update({
        'software_statements': SINGLE_OPTIONAL_STRING,
        'software_statement_uris': OPTIONAL_MESSAGE,
        'signed_metadata': SINGLE_OPTIONAL_STRING,
        'signed_metadata_uri': SINGLE_OPTIONAL_STRING,
        'signed_jwks_uri': SINGLE_OPTIONAL_STRING,
        'signing_key': SINGLE_REQUIRED_STRING,
        'signing_keys_uri': SINGLE_OPTIONAL_STRING,
        'claims_allowed': OPTIONAL_LIST_OF_STRINGS,
        'scopes_allowed': OPTIONAL_LIST_OF_STRINGS
    })

class ProviderConfigurationResponse(message.ProviderConfigurationResponse):
    c_param = message.ProviderConfigurationResponse.c_param.copy()
    c_param.update({
        'software_statements': SINGLE_OPTIONAL_STRING,
        'software_statement_uris': OPTIONAL_MESSAGE,
        'signed_metadata': SINGLE_OPTIONAL_STRING,
        'signed_metadata_uri': SINGLE_OPTIONAL_STRING,
        'signed_jwks_uri': SINGLE_OPTIONAL_STRING,
        'signing_key': SINGLE_REQUIRED_STRING,
        'signing_keys_uri': SINGLE_OPTIONAL_STRING,
    })
