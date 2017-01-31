import copy
import json
import logging
import os

from jwkest import BadSignature
from jwkest.jws import JWSException
import time
from oic.federation.bundle import JWKSBundle, get_signing_keys
from oic.utils.keyio import build_keyjar, KeyJar

from oic.federation import ClientMetadataStatement
from oic.federation import IgnoreKeys
from oic.federation import is_lesser
from oic.federation import unfurl

from oic.oauth2.message import MissingSigningKey

from oic.utils.jwt import JWT

__author__ = 'roland'

logger = logging.getLogger(__name__)


class Operator(object):
    def __init__(self, keyjar=None, fo_keyjar=None, httpcli=None, iss=None,
                 jwks_file=''):
        """

        :param keyjar: Contains the operators signing keys
        :param fo_keyjar: Contains the federation operators signing key
            for all the federations this instance wants to talk to
        :param httpcli: A http client to use when information has to be
            fetched from somewhere else
        :param iss: Issuer ID
        """
        if keyjar:
            self.keyjar = keyjar
        elif jwks_file:
            try:
                fp = open(jwks_file,'r')
            except Exception:
                self.keyjar = None
            else:
                self.keyjar = KeyJar()
                self.keyjar.import_jwks(json.load(fp), '')
                fp.close()
        else:
            self.keyjar = None

        self.fo_keyjar = fo_keyjar
        self.httpcli = httpcli
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


class FederationOperator(Operator):
    def __init__(self, keyjar=None, fo_keyjar=None, httpcli=None, jwks_file='',
                 iss=None, keyconf=None, bundle_sign_alg='RS256'):

        Operator.__init__(self, keyjar=keyjar, fo_keyjar=fo_keyjar,
                          httpcli=httpcli, iss=iss, jwks_file=jwks_file)

        if self.keyjar is None:
            self.keyjar = build_keyjar(keyconf)[1]
            if jwks_file:
                fp = open(jwks_file, 'w')
                fp.write(json.dumps(self.keyjar.export_jwks(private=True)))
                fp.close()

        self.keyconf = keyconf
        self.bundle_sign_alg = bundle_sign_alg
        self.jb = JWKSBundle(iss, self.keyjar)

    def public_keys(self):
        return self.keyjar.export_jwks()

    def rotate_keys(self, keyconf=None):
        _old = [k.kid for k in self.keyjar.get_issuers_keys('') if k.kid]

        if keyconf:
            self.keyjar = build_keyjar(keyconf, keyjar=self.keyjar)[1]
        else:
            self.keyjar = build_keyjar(self.keyconf, keyjar=self.keyjar)[1]

        for k in self.keyjar.get_issuers_keys(''):
            if k.kid in _old:
                if not k.inactive_since:
                    k.inactive_since = time.time()

    def export_jwks(self):
        return self.keyjar.export_jwks()

    def add_to_bundle(self, fo, jwks):
        self.jb[fo] = jwks

    def remove_from_bundle(self, fo):
        del self.jb[fo]

    def export_bundle(self):
        return self.jb.create_signed_bundle(sign_alg=self.bundle_sign_alg)
