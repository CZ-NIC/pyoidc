import json
import logging
import os
import re
import time

from future.backports.urllib.parse import urlparse, unquote_plus
from oic.oauth2.base import PBase

from oic.federation.bundle import JWKSBundle

from oic.utils.keyio import KeyJar
from oic.federation import ClientMetadataStatement
from oic.federation.operator import Operator

__author__ = 'roland'

logger = logging.getLogger(__name__)


class FederationEntity(Operator):
    def __init__(self, jwks_file=None, httpcli=None, iss='', keyjar=None,
                 signed_metadata_statements_dir='.', fo_jwks_dir=None,
                 fo_priority_order=None, ms_cls=ClientMetadataStatement,
                 fo_bundle_uri=None, fo_bundle_sign_key=None,
                 verify_ssl=True, ca_certs=None, client_cert=None):

        if jwks_file:
            keyjar = self.read_jwks_file(jwks_file)

        if httpcli is None:
            httpcli = PBase(verify_ssl=verify_ssl, ca_certs=ca_certs,
                            keyjar=keyjar, client_cert=client_cert)

        Operator.__init__(self, iss=iss, keyjar=keyjar, httpcli=httpcli)

        # FO keys
        self.fo_keyjar = None
        self.fo_jwks_dir = fo_jwks_dir
        self.jwks_mtime = {}
        if fo_jwks_dir:
            self.get_fo_keyjar_from_dir()

        if fo_bundle_uri:
            self.fo_bundle_uri = fo_bundle_uri
            self.fo_bundle_sign_key = fo_bundle_sign_key
            self.import_from_bundle(fo_bundle_uri, fo_bundle_sign_key)

        # Signed metadata statements
        self.signed_metadata_statements_dir = signed_metadata_statements_dir
        self.sms_mtime = {}
        self.signed_metadata_statements = {}
        self.get_sms_from_dir()

        self.fo_priority_order = {} or fo_priority_order
        self.ms_cls = ms_cls

    def read_jwks_file(self, jwks_file):
        _jwks = open(jwks_file, 'r').read()
        _kj = KeyJar()
        _kj.import_jwks(json.loads(_jwks), '')
        return _kj

    def import_from_bundle(self, uri, sign_key):
        _jb = {}
        p = urlparse(uri)
        if p[0] == 'file':
            jwks_bundle = open(p.path, 'r').read()
            _jb = JWKSBundle('', sign_keys=sign_key)
            _jb.loads(jwks_bundle)
        elif p[0] in ['http', 'https']:
            r = self.httpcli.http_request(uri)
            if r.status == 200:
                _jb = JWKSBundle('', sign_keys=sign_key)
                _jb.loads(r.text)
        else:
            raise ValueError('Unsupported scheme')

        if self.fo_keyjar:
            kj = self.fo_keyjar
        else:
            kj = KeyJar()

        for iss, ikj in _jb.items():
            kj.issuer_keys[iss] = ikj.issuer_keys['']

    def pick_signed_metadata_statements(self, pattern):
        """
        Pick signed metadata statements based on ISS pattern matching
        :param pattern: A regular expression to match the iss against
        :return: list of signed metadata statements
        """
        comp_pat = re.compile(pattern)
        res = []
        for iss, vals in self.signed_metadata_statements.items():
            if comp_pat.search(iss):
                res.extend(vals)
        return res

    def get_metadata_statement(self, json_ms):
        """
        Unpack and evaluate a compound metadata statement
        :param json_ms: The metadata statement as a JSON document
        :return: The resulting metadata that matched highest ranking issuer ID
        """
        _cms = self.unpack_metadata_statement(json_ms=json_ms,
                                              cls=self.ms_cls)
        ms_per_fo = self.evaluate_metadata_statement(_cms)
        for fo in self.fo_priority_order:
            try:
                return ms_per_fo[fo]
            except KeyError:
                continue

        return None

    def _read_info(self, fname):
        if os.path.isfile(fname):
            try:
                return open(fname, 'r').read()
            except Exception as err:
                logger.error(err)
                raise

        return None

    def get_files_from_dir(self, fdir, hist):
        res = {}
        if not os.path.isdir(fdir):
            raise ValueError('No such directory: {}'.format(fdir))
        for f in os.listdir(fdir):
            fname = os.path.join(fdir, f)
            if f in hist:
                try:
                    mtime = os.stat(fname).st_mtime
                except OSError:
                    # The file might be right in the middle of being written
                    # so sleep
                    time.sleep(1)
                    mtime = os.stat(fname).st_mtime

                if mtime > hist[f]:  # has changed
                    res[f] = self._read_info(fname)
                    hist[f] = mtime
            else:
                try:
                    mtime = os.stat(fname).st_mtime
                except OSError:
                    # The file might be right in the middle of being written
                    # so sleep
                    time.sleep(1)
                    mtime = os.stat(fname).st_mtime

                res[f] = self._read_info(fname)
                hist[f] = mtime

        return res, hist

    def get_sms_from_dir(self):
        try:
            fetched_sms, hist = self.get_files_from_dir(
                self.signed_metadata_statements_dir, self.sms_mtime)
        except Exception as err:
            logger.error(err)
        else:
            for qiss, sms in fetched_sms.items():
                self.signed_metadata_statements[unquote_plus(qiss)] = sms
            self.sms_mtime = hist

    def get_fo_keyjar_from_dir(self):
        try:
            fetched_jwks, _mtime = self.get_files_from_dir(self.fo_jwks_dir,
                                                           self.jwks_mtime)
        except Exception as err:
            logger.error(err)
        else:
            _kj = KeyJar()
            for iss, jwks in fetched_jwks.items():
                _kj.import_jwks(json.loads(jwks), unquote_plus(iss))

            self.fo_keyjar = _kj
            self.jwks_mtime = _mtime
