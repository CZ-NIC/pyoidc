import json
import logging
import os
import re
import time

from future.backports.urllib.parse import urlparse, unquote_plus, quote_plus

from oic.federation.file_system import FileSystem
from oic.oauth2.base import PBase

from oic.federation.bundle import JWKSBundle

from oic.utils.keyio import KeyJar
from oic.federation import ClientMetadataStatement
from oic.federation.operator import Operator

__author__ = 'roland'

logger = logging.getLogger(__name__)


class FederationEntity(Operator):
    def __init__(self, srv, jwks_file=None, iss='', keyjar=None,
                 signed_metadata_statements_dir='.', fo_bundle=None,
                 ms_cls=ClientMetadataStatement):

        if jwks_file:
            keyjar = self.read_jwks_file(jwks_file)

        Operator.__init__(self, iss=iss, keyjar=keyjar, httpcli=srv)

        # FO keys
        self.fo_bundle = fo_bundle

        # Signed metadata statements
        self.signed_metadata_statements = FileSystem(
            signed_metadata_statements_dir,
            key_conv={'in': quote_plus, 'out': unquote_plus})
        self.signed_metadata_statements.sync()

        self.ms_cls = ms_cls

    def read_jwks_file(self, jwks_file):
        _jwks = open(jwks_file, 'r').read()
        _kj = KeyJar()
        _kj.import_jwks(json.loads(_jwks), '')
        return _kj

    def pick_by_priority(self, req, priority=None):
        if not priority:
            return req.values()[0]  # Just return any

        for iss in priority:
            try:
                return req[iss]
            except KeyError:
                pass
        return None

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
        :return: A dictionary with metadata statements per FO
        """
        _cms = self.unpack_metadata_statement(json_ms=json_ms,
                                              cls=self.ms_cls)
        ms_per_fo = self.evaluate_metadata_statement(_cms)

        return ms_per_fo
