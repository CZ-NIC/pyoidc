#!/usr/bin/env python3
import json
import os

import sys

from future.backports.urllib.parse import quote_plus
from jwkest import jws
from jwkest.jws import NoSuitableSigningKeys
from oic.utils.jwt import JWT
from oic.utils.keyio import build_keyjar
from oic.utils.keyio import KeyJar


class JWKSBundle(object):
    def __init__(self, iss, sign_keys=None):
        self.iss = iss
        self.sign_keys = sign_keys  # These are my signing keys as a KeyJar
        self.bundle = {}

    def __setitem__(self, key, value):
        """

        :param key: issuer ID
        :param value: Supposed to be KeyJar or a JWKS (JSON document)
        """
        if not isinstance(value, KeyJar):
            kj = KeyJar()
            kj.import_jwks(value, issuer=key)
            value = kj
        else:
            _iss = list(value.keys())
            if _iss == ['']:
                value.issuer_keys[key] = value.issuer_keys['']
                del value.issuer_keys['']
            elif len(_iss) == 1:
                if _iss[0] != key:
                    value.issuer_keys[key] = value.issuer_keys[_iss[0]]
                    del value.issuer_keys[_iss[0]]
            else:
                raise ValueError('KeyJar contains to many issuers')

        self.bundle[key] = value

    def __getitem__(self, item):
        return self.bundle[item]

    def __delitem__(self, key):
        del self.bundle[key]

    def create_signed_bundle(self, sign_alg='RS256'):
        data = self.__str__()
        _jwt = JWT(self.sign_keys, iss=self.iss, sign_alg=sign_alg)
        return _jwt.pack(bundle=data)

    def loads(self, jstr):
        _info = json.loads(jstr)
        for iss, jwks in _info.items():
            kj = KeyJar()
            kj.import_jwks(jwks, issuer=iss)
            self.bundle[iss] = kj
        return self

    def dumps(self):
        return self.__str__()

    def __str__(self):
        return json.dumps(self.dict())

    def keys(self):
        return self.bundle.keys()

    def items(self):
        return self.bundle.items()

    def dict(self):
        _int = {}
        for iss, kj in self.bundle.items():
            _int[iss] = kj.export_jwks(issuer=iss)
        return _int


def verify_signed_bundle(signed_bundle, ver_keys):
    """

    :param signed_bundle: A signed JWT where the body is a JWKS bundle
    :param ver_keys: Keys that can be used to verify signatures of the
        signed_bundle as a KeyJar.
    :return: The bundle or None
    """
    _jwt = JWT(ver_keys)
    return _jwt.unpack(signed_bundle)


def resign_bundle(iss, signed_bundle, sign_key):
    _jw = jws.factory(signed_bundle)
    _jwt = _jw.jwt.payload()
    _bundle = json.loads(_jwt['bundle'])

    jb = JWKSBundle(iss, sign_key)
    for iss, jwks in _bundle.items():
        jb[iss] = jwks

    return jb


def make_bundle(tool_iss, fo_iss, sign_keyjar, keydefs, base_path=''):
    _operator = {}

    for entity in fo_iss:
        fname = quote_plus(os.path.join(base_path, "{}.key".format(entity)))
        _keydef = keydefs[:]
        _keydef[0]['key'] = fname

        _jwks, _keyjar, _kidd = build_keyjar(_keydef)
        _operator[entity] = _jwks

    jb = JWKSBundle(tool_iss, sign_keyjar)
    for iss, jwks in _operator.items():
        jb[iss] = jwks

    return jb


def get_bundle(iss, fo_iss, sign_key, bundle_file, keydefs, base_path=''):

    try:
        fp = open(bundle_file, 'r')
    except Exception:
        jb = make_bundle(iss, fo_iss, sign_key, keydefs, base_path)
        fp = open(bundle_file, 'w')
        fp.write(jb.create_signed_bundle())
        fp.close()
    else:
        signed_bundle = fp.read()
        fp.close()
        try:
            vb = verify_signed_bundle(signed_bundle, sign_key)
        except (NoSuitableSigningKeys, KeyError):
            jb = resign_bundle(iss, signed_bundle, sign_key)
            fp = open(bundle_file, 'w')
            fp.write(jb.create_signed_bundle())
            fp.close()
        else:
            jb = JWKSBundle(iss, sign_key).loads(vb['bundle'])

    return jb


def get_signing_keys(iss, keydef, key_file):
    if os.path.isfile(key_file):
        kj = KeyJar()
        kj.import_jwks(json.loads(open(key_file, 'r').read()), iss)
    else:
        kj = build_keyjar(keydef)[1]
        # make it know under both names
        fp = open(key_file, 'w')
        fp.write(json.dumps(kj.export_jwks()))
        fp.close()
        kj.issuer_keys[iss] = kj.issuer_keys['']

    return kj


def key_setup(iss, keydefs, sk_file='signing_key.json',
              bundle_file='bundle.jws'):
    sign_key = get_signing_keys(iss, keydefs, sk_file)

    return sign_key, jb


if __name__ == '__main__':
    BASE_PATH = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "static"))

    KEYDEFS = [
        {"type": "RSA", "key": '', "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]}
    ]

    fo_iss = ['https://swamid.se/oidc', 'https://surfnet.nl/oidc',
              'http://aai.grnet.gr/oidc',
              'https://www.heanet.ie/services/oidc']

    tool_iss = sys.argv[1]
    try:
        sk_file = sys.argv[2]
    except IndexError:
        sk_file = 'signing_key.json'
        bundle_file = 'bundle.jws'
    else:
        try:
            bundle_file = sys.argv[3]
        except IndexError:
            bundle_file = 'bundle.jws'

    sign_key = get_signing_keys(tool_iss, KEYDEFS, sk_file)
    jb = get_bundle(tool_iss, fo_iss, sign_key, bundle_file, KEYDEFS, BASE_PATH)

    print(jb.keys())
