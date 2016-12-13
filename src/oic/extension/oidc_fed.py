import copy
import json
import logging
import re

from jwkest import BadSignature, as_unicode
from jwkest.jws import factory
from jwkest.jws import JWSException
from six import string_types, PY2

from oic.utils.keyio import KeyJar

from oic.oauth2 import MissingSigningKey
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


class Operator(object):
    def __init__(self, keyjar=None, fo_keyjar=None, httpcli=None, jwks=None,
                 iss=None):
        """

        :param keyjar: Contains the operators signing keys
        :param fo_keyjar: Contains the federation operators signing key
            for all the federations this instance wants to talk to
        :param httpcli: A http client to use when information has to be
            fetched from somewhere else
        :param iss: Issuer ID
        """
        self.keyjar = keyjar
        self.fo_keyjar = fo_keyjar
        self.httpcli = httpcli
        if jwks:
            self.jwks = jwks
        elif keyjar:
            self.jwks = self.keyjar.export_jwks()
        else:
            self.jwks = None
        self.iss = iss
        self.failed = {}

    def unpack_metadata_statement(self, json_ms=None, jwt_ms='', keyjar=None,
                                  cls=ClientMetadataStatement):
        """

        :param json_ms: Metadata statement as a JSON document
        :param jwt_ms: Metadata statement as JWT
        :param keyjar: Keys that should be used to verify the signature of the
            document
        :param cls: What type (Class) of metadata statement this is
        :return: Unpacked and verified metadata statement
        """

        if keyjar is None:
            _keyjar = self.fo_keyjar
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
                            _ms = self.unpack_metadata_statement(
                                jwt_ms=meta_s, keyjar=_keyjar, cls=cls)
                        except (JWSException, BadSignature, MissingSigningKey):
                            pass
                        else:
                            msl.append(_ms)

                    for _ms in msl:
                        _keyjar.import_jwks(_ms['signing_keys'], '')

                elif 'metadata_statement_uris' in json_ms:
                    pass

                try:
                    _ms = cls().from_jwt(jwt_ms, keyjar=_keyjar)
                except MissingSigningKey:
                    raise

                if msl:
                    _ms['metadata_statements'] = [x.to_json() for x in msl]
                return _ms

        if json_ms:
            msl = []
            if 'metadata_statements' in json_ms:
                for ms in json_ms['metadata_statements']:
                    try:
                        res = self.unpack_metadata_statement(
                            jwt_ms=ms, keyjar=keyjar, cls=cls)
                    except (JWSException, BadSignature):
                        pass
                    else:
                        msl.append(res)

            if 'metadata_statement_uris' in json_ms:
                if self.httpcli:
                    for iss, url in json_ms['metadata_statement_uris'].items():
                        if iss not in keyjar:  # FO I don't know about
                            continue
                        else:
                            _jwt = self.httpcli.http_request(url)
                            try:
                                _res = self.unpack_metadata_statement(
                                    jwt_ms=_jwt, keyjar=keyjar, cls=cls)
                            except JWSException as err:
                                logger.error(err)
                            else:
                                msl.append(_res)
            if msl:
                json_ms['metadata_statements'] = [x.to_json() for x in msl]
            return json_ms
        else:
            raise AttributeError('Need one of json_ms or jwt_ms')

    def pack_metadata_statement(self, metadata, keyjar=None, iss=None, alg='',
                                **kwargs):
        """

        :param metas: Original metadata statement as a MetadataStatement
        instance
        :param keyjar: KeyJar in which the necessary keys should reside
        :param alg: Which signing algorithm to use
        :param kwargs: Additional metadata statement attribute values
        :return: A JWT
        """
        if iss is None:
            iss = self.iss
        if keyjar is None:
            keyjar = self.keyjar

        # Own copy
        _metadata = copy.deepcopy(metadata)
        _metadata.update(kwargs)
        _jwt = JWT(keyjar, iss=iss, msgtype=_metadata.__class__)
        if alg:
            _jwt.sign_alg = alg

        return _jwt.pack(cls_instance=_metadata)

    def evaluate_metadata_statement(self, metadata):
        """
        Computes the resulting metadata statement from a compounded metadata
        statement.
        If something goes wrong during the evaluation an exception is raised

        :param metadata: The compounded metadata statement
        :return: The resulting metadata statement
        """

        # start from the innermost metadata statement and work outwards

        res = dict([(k, v) for k, v in metadata.items() if k not in IgnoreKeys])

        if 'metadata_statements' in metadata:
            cres = {}
            for ms in metadata['metadata_statements']:
                _msd = self.evaluate_metadata_statement(json.loads(ms))
                for _iss, kw in _msd.items():
                    _break = False
                    _ci = {}
                    for k, v in kw.items():
                        if k in res:
                            if is_lesser(res[k], v):
                                _ci[k] = v
                            else:
                                self.failed['iss'] = (
                                    'Value of {}: {} not <= {}'.format(k,
                                                                       res[k],
                                                                       v))
                                _break = True
                                break
                        else:
                            _ci[k] = v
                        if _break:
                            break

                    if _break:
                        continue

                    for k, v in res.items():
                        if k not in _ci:
                            _ci[k] = v

                    cres[_iss] = _ci
            return cres
        else:  # this is the innermost
            _iss = metadata['iss']  # The issuer == FO is interesting
            return {_iss: res}


class FederationEntity(object):
    def __init__(self, signed_metadata_statements, fo_keyjar, keyjar, eid,
                 fo_priority_order=None, ms_cls=ClientMetadataStatement):
        self.signed_metadata_statements = {} or signed_metadata_statements
        self.fo_priority_order = {} or fo_priority_order
        self.ms_cls = ms_cls
        self.op = Operator(keyjar=keyjar, fo_keyjar=fo_keyjar, httpcli=self,
                           iss=eid)

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

    def add_fo(self, iss, jwks):
        self.op.fo_keyjar.import_jwks(jwks=jwks, issuer=iss)

    def get_metadata_statement(self, json_ms):
        _cms = self.op.unpack_metadata_statement(json_ms=json_ms,
                                                 cls=self.ms_cls)
        ms_per_fo = self.op.evaluate_metadata_statement(_cms)
        for fo in self.fo_priority_order:
            try:
                return ms_per_fo[fo]
            except KeyError:
                continue

        return None