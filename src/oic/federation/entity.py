import json
import logging
import os
import re
from future.backports.urllib.parse import urlparse

from jwkest import jws
import time
from oic.federation.bundle import JWKSBundle

from oic.utils.keyio import KeyJar
from oic.federation import ClientMetadataStatement
from oic.federation.operator import Operator

__author__ = 'roland'

logger = logging.getLogger(__name__)


class FederationEntity(object):
    def __init__(self, eid, keyjar,
                 signed_metadata_statements_dir='.', fo_jwks_dir=None,
                 fo_priority_order=None, ms_cls=ClientMetadataStatement,
                 fo_jwks_uri=None, fo_keys_sign_key=None):
        self.signed_metadata_statements_dir = signed_metadata_statements_dir
        self.fo_jwks_dir = fo_jwks_dir
        self.fo_priority_order = {} or fo_priority_order
        self.ms_cls = ms_cls

        self.keyjar_files = {}
        self.fo_keyjar = self.get_fo_keyjar_from_dir()
        self.op = Operator(keyjar=keyjar, fo_keyjar=self.fo_keyjar,
                           httpcli=self, iss=eid)

        self.mds_mtime = {}
        self.fo_jwks_uri = fo_jwks_uri
        self.fo_keys_sign_key = fo_keys_sign_key
        self.keyjar_files = {}

    def import_fo_bundle(self, uri, sign_key):
        p = urlparse(uri)
        if p.scheme('file'):
            jwks_bundle = open(p.path, 'r').read()
            _jb = JWKSBundle('', sign_keys=sign_key)
            _jb.loads(jwks_bundle)
            kj = KeyJar()
            for iss, ikj in _jb.items():
                kj.issuer_keys[iss] = ikj.issuer_keys['']
            return kj

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

    def _read_info(self, fname):
        if os.path.isfile(fname):
            try:
                return open(fname, 'r').read()
            except Exception as err:
                logger.error(err)
                raise

        return None

    def get_files_from_dir(self, hist):
        res = {}
        for f in os.listdir(self.fo_jwks_dir):
            fname = os.path.join(self.fo_jwks_dir, f)
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

    def get_mds_from_dir(self):
        try:
            fetched_mds, hist = self.get_files_from_dir(self.mds_mtime)
        except Exception as err:
            logger.error(err)
        else:
            self.signed_metadata_statements = fetched_mds
