import json
import logging

from jwkest import as_unicode
from jwkest.jws import factory
from six import PY2
from six import string_types

from oic.utils.keyio import KeyJar

from oic.oauth2 import SINGLE_OPTIONAL_STRING
from oic.oauth2 import VerificationError
from oic.oauth2.message import OPTIONAL_LIST_OF_STRINGS

from oic.oic import message
from oic.oic.message import JasonWebToken
from oic.oic.message import OPTIONAL_MESSAGE
from oic.oic.message import RegistrationRequest

logger = logging.getLogger(__name__)

__author__ = 'roland'


class MetadataStatement(JasonWebToken):
    c_param = JasonWebToken.c_param.copy()
    c_param.update({
        "signing_keys": SINGLE_OPTIONAL_STRING,
        'signing_keys_uri': SINGLE_OPTIONAL_STRING,
        'metadata_statements': OPTIONAL_LIST_OF_STRINGS,
        'metadata_statement_uris': OPTIONAL_MESSAGE,
        'signed_jwks_uri': SINGLE_OPTIONAL_STRING
    })

    def verify(self, **kwargs):
        if "signing_keys" in self:
            if 'signing_keys_uri' in self:
                raise VerificationError(
                    'You can only have one of "signing_keys" and '
                    '"signing_keys_uri" in a metadata statement')
            else:
                # signing_keys MUST be a JWKS
                kj = KeyJar()
                try:
                    kj.import_jwks(self['signing_keys'], '')
                except Exception:
                    raise VerificationError('"signing_keys" not a proper JWKS')
        elif not 'signing_keys_uri' in self:
            raise VerificationError(
                ' You must have one of "signing_keys" or '
                '"signing_keys_uri" in a metadata statement')

        if "metadata_statements" in self and "metadata_statement_uris" in self:
            raise VerificationError(
                'You can only have one of "metadata_statements" and '
                '"metadata_statement_uris" in a metadata statement')

        return True


class ClientMetadataStatement(MetadataStatement):
    c_param = MetadataStatement.c_param.copy()
    c_param.update(RegistrationRequest.c_param.copy())
    c_param.update({
        "scope": OPTIONAL_LIST_OF_STRINGS,
        'claims': OPTIONAL_LIST_OF_STRINGS,
    })


class ProviderConfigurationResponse(message.ProviderConfigurationResponse):
    c_param = MetadataStatement.c_param.copy()
    c_param.update(message.ProviderConfigurationResponse.c_param.copy())


def unfurl(jwt):
    _rp_jwt = factory(jwt)
    return json.loads(_rp_jwt.jwt.part[1].decode('utf8'))


def keyjar_from_metadata_statements(iss, msl):
    keyjar = KeyJar()
    for ms in msl:
        keyjar.import_jwks(ms['signing_keys'], iss)
    return keyjar


def is_lesser(a, b):
    """
    Verify that a in lesser then b
    :param a:
    :param b:
    :return: True or False
    """

    if type(a) != type(b):
        if PY2:  # one might be unicode and the other str
            return as_unicode(a) == as_unicode(b)

        return False

    if isinstance(a, string_types) and isinstance(b, string_types):
        return a == b
    elif isinstance(a, bool) and isinstance(b, bool):
        return a == b
    elif isinstance(a, list) and isinstance(b, list):
        for element in a:
            flag = 0
            for e in b:
                if is_lesser(element, e):
                    flag = 1
                    break
            if not flag:
                return False
        return True
    elif isinstance(a, dict) and isinstance(b, dict):
        if is_lesser(list(a.keys()), list(b.keys())):
            for key, val in a.items():
                if not is_lesser(val, b[key]):
                    return False
            return True
        return False
    elif isinstance(a, int) and isinstance(b, int):
        return a <= b
    elif isinstance(a, float) and isinstance(b, float):
        return a <= b

    return False


#  The resulting metadata must not contain these parameters
IgnoreKeys = list(JasonWebToken.c_param.keys())
IgnoreKeys.extend([
    'signing_keys', 'signing_keys_uri', 'metadata_statement_uris', 'kid',
    'metadata_statements'])

