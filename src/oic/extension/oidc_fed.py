import copy
import json
import logging

from jwkest import BadSignature
from jwkest.jws import factory, alg2keytype
from jwkest.jws import JWSException
from six import string_types

from oic.utils.keyio import KeyJar

from oic.oauth2 import SINGLE_REQUIRED_STRING
from oic.oauth2 import SINGLE_OPTIONAL_STRING
from oic.oauth2.message import OPTIONAL_LIST_OF_STRINGS
from oic.oic import message
from oic.oic.message import JasonWebToken
from oic.oic.message import OPTIONAL_MESSAGE
from oic.oic.message import RegistrationRequest
from oic.utils.jwt import JWT

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


def unpack_metadata_statement(json_ms=None, jwt_ms='', keyjar=None,
                              cls=ClientMetadataStatement, httpcli=None):
    """

    :param json_ms: Metadata statement as a JSON document
    :param jwt_ms: Metadata statement as JWT
    :param keyjar: Keys that should be used to verify the signature of the
        document
    :param cls: What type (Class) of metadata statement this is
    :param httpcli: A oic.oauth2.base.PBase instance
    :return: Unpacked and verified metadata statement
    """

    if keyjar is None:
        _keyjar = KeyJar()
    else:
        _keyjar = keyjar

    if jwt_ms:
        try:
            json_ms = unfurl(jwt_ms)
        except JWSException:
            raise
        else:
            msl = []
            if 'metadata_statements' in json_ms:
                msl = []
                for meta_s in json_ms['metadata_statements']:
                    try:
                        _ms = unpack_metadata_statement(jwt_ms=meta_s,
                                                        keyjar=_keyjar)
                    except (JWSException, BadSignature):
                        pass
                    else:
                        msl.append(_ms)

                for _ms in msl:
                    _keyjar.import_jwks(_ms['signing_keys'], '')

            elif 'metadata_statement_uris' in json_ms:
                pass

            _ms = cls().from_jwt(jwt_ms, keyjar=_keyjar)
            if msl:
                _ms['metadata_statements'] = [x.to_json() for x in msl]
            return _ms

    if json_ms:
        msl = []
        if 'metadata_statements' in json_ms:
            for ms in json_ms['metadata_statements']:
                try:
                    res = unpack_metadata_statement(jwt_ms=ms, keyjar=keyjar)
                except (JWSException, BadSignature):
                    pass
                else:
                    msl.append(res)

        if 'metadata_statement_uris' in json_ms:
            if httpcli:
                for iss, url in json_ms['metadata_statement_uris'].items():
                    if iss not in keyjar:  # FO I don't know about
                        continue
                    else:
                        _jwt = httpcli.http_request(url)
                        try:
                            _inst, _json, _ikj = unpack_metadata_statement(
                                jwt_ms=_jwt, keyjar=keyjar, httpcli=httpcli)
                        except JWSException as err:
                            logger.error(err)
                        else:
                            if _json is None:
                                msl.append((_inst, _inst, _ikj))
                            else:
                                msl.append((_inst, _json, _ikj))

        json_ms['metadata_statements'] = [y for x, y, z in msl]
        _kj = keyjar_from_metadata_statements(json_ms['iss'],
                                              [x for x, y, z in msl])
        for ikj in [z for x, y, z in msl]:
            if ikj:
                _kj.add_keyjar(ikj)
    else:
        raise AttributeError('Need one of json_ms or jwt_ms')

    if jwt_ms and _kj:
        return {'ms': cls().from_jwt(jwt_ms, keyjar=_kj),
                'json_ms':json_ms, 'keyjar':_kj}
    else:
        return {'json_ms':json_ms}


def pack_metadata_statement(metadata, keyjar, iss, alg='', **kwargs):
    """

    :param metas: Original metadata statement as a MetadataStatement instance
    :param keyjar: KeyJar in which the necessary keys should reside
    :param alg: Which signing algorithm to use
    :param kwargs: Additional metadata statement attribute values
    :return: A JWT
    """

    # Own copy
    metadata = copy.deepcopy(metadata)
    metadata.update(kwargs)
    _jwt = JWT(keyjar, iss=iss, msgtype=metadata.__class__)
    if alg:
        _jwt.sign_alg = alg

    return _jwt.pack(cls_instance=metadata)


#  The resulting metadata must not contain these parameters
IgnoreKeys = list(JasonWebToken.c_param.keys())
IgnoreKeys.extend([
    'signing_keys', 'signing_keys_uri', 'metadata_statement_uris', 'kid',
    'metadata_statements'])


def is_lesser(a, b):
    """
    Verify that a in lesser then b
    :param a:
    :param b:
    :return: True or False
    """

    if type(a) != type(b):
        return False

    if isinstance(a, string_types) and isinstance(b, string_types):
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


def evaluate_metadata_statement(metadata):
    """
    Computes the resulting metadata statement from a compounded metadata
    statement.
    If something goes wrong during the evaluation an exception is raised

    :param ms: The compounded metadata statement
    :return: The resulting metadata statement
    """

    # start from the innermost metadata statement and work outwards

    res = dict([(k, v) for k, v in metadata.items() if k not in IgnoreKeys])

    if 'metadata_statements' in metadata:
        cres = {}
        for ms in metadata['metadata_statements']:
            _msd = evaluate_metadata_statement(json.loads(ms))
            for _iss, kw in _msd.items():
                _ci = {}
                for k, v in kw.items():
                    if k in res:
                        if is_lesser(res[k], v):
                            _ci[k] = v
                        else:
                            raise ValueError(
                                'Value of {}: {} not <= {}'.format(k, res[k],
                                                                   v))
                    else:
                        _ci[k] = v
                for k, v in res.items():
                    if k not in _ci:
                        _ci[k] = v
                cres[_iss] = _ci
        return cres
    else:  # this is the innermost
        _iss = metadata['iss']  # The issuer == FO is interesting
        return {_iss: res}
