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
    """
    A class to keep a number of signing keys from different issuers.
    """

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
            _val = value.copy()
            _iss = list(_val.keys())
            if _iss == ['']:
                _val.issuer_keys[key] = _val.issuer_keys['']
                del _val.issuer_keys['']
            elif len(_iss) == 1:
                if _iss[0] != key:
                    _val.issuer_keys[key] = _val.issuer_keys[_iss[0]]
                    del _val.issuer_keys[_iss[0]]
            else:
                raise ValueError('KeyJar contains to many issuers')

            value = _val

        self.bundle[key] = value

    def __getitem__(self, item):
        """
        Returns a KeyJar instance representing the keys belonging to an
        issuer
        :param item: Issuer ID
        :return: A KeyJar instance
        """
        return self.bundle[item]

    def __delitem__(self, key):
        """
        Remove the KeyJar that belong to a specific issuer
        :param key: Issuer ID
        """
        del self.bundle[key]

    def create_signed_bundle(self, sign_alg='RS256', iss_list=None):
        """
        Create a signed JWT containing a dictionary with Issuer IDs as keys
        and JWKSs as values
        :param sign_alg: Which algorithm to use when signing the JWT
        :return: A signed JWT
        """
        data = json.dumps(self.dict(iss_list))
        _jwt = JWT(self.sign_keys, iss=self.iss, sign_alg=sign_alg)
        return _jwt.pack(bundle=data)

    def loads(self, jstr):
        """
        Upload a bundle from a string
        :param jstr:
        :return:
        """
        _info = json.loads(jstr)
        for iss, jwks in _info.items():
            kj = KeyJar()
            kj.import_jwks(jwks, issuer=iss)
            self.bundle[iss] = kj
        return self

    def dumps(self, iss_list=None):
        return json.dumps(self.dict(iss_list))

    def __str__(self):
        return json.dumps(self.dict())

    def keys(self):
        return self.bundle.keys()

    def items(self):
        return self.bundle.items()

    def dict(self, iss_list=None):
        _int = {}
        for iss, kj in self.bundle.items():
            if iss_list is None or iss in iss_list:
                _int[iss] = kj.export_jwks(issuer=iss)
        return _int

    def upload_signed_bundle(self, sign_bundle, ver_keys):
        jstr = verify_signed_bundle(sign_bundle, ver_keys)
        self.loads(jstr)

    def as_keyjar(self):
        kj = KeyJar()
        for iss, k in self.bundle.items():
            kj.issuer_keys[iss] = k.issuer_keys[iss]
        return kj


def verify_signed_bundle(signed_bundle, ver_keys):
    """

    :param signed_bundle: A signed JWT where the body is a JWKS bundle
    :param ver_keys: Keys that can be used to verify signatures of the
        signed_bundle as a KeyJar.
    :return: The bundle or None
    """
    _jwt = JWT(ver_keys)
    return _jwt.unpack(signed_bundle)


def get_bundle(iss, ver_keys, bundle_file):
    fp = open(bundle_file, 'r')
    signed_bundle = fp.read()
    fp.close()
    return JWKSBundle(iss, None).upload_signed_bundle(signed_bundle, ver_keys)


def get_signing_keys(eid, keydef, key_file):
    """
    If the *key_file* file exists then read the keys from there, otherwise
    create the keys and store them a file with the name *key_file*.

    :param eid: The ID of the entity that the keys belongs to
    :param keydef: What keys to create
    :param key_file: A file name
    :return: A KeyJar instance
    """
    if os.path.isfile(key_file):
        kj = KeyJar()
        kj.import_jwks(json.loads(open(key_file, 'r').read()), eid)
    else:
        kj = build_keyjar(keydef)[1]
        # make it know under both names
        fp = open(key_file, 'w')
        fp.write(json.dumps(kj.export_jwks()))
        fp.close()
        kj.issuer_keys[eid] = kj.issuer_keys['']

    return kj


# def key_setup(iss, keydefs, fo_liss, sk_file='signing_key.json',
#               bundle_file='bundle.jws', base_path='./'):
#     sign_key = get_signing_keys(iss, keydefs, sk_file)
#     jb = get_bundle(iss, fo_liss, sign_key, bundle_file, keydefs,
#                     base_path)
#     return sign_key, jb


if __name__ == '__main__':
    BASE_PATH = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "static"))

    KEYDEFS = [
        {"type": "RSA", "key": '', "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]}
    ]

    fo_liss = ['https://swamid.se/oidc', 'https://surfnet.nl/oidc',
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

    kj = get_signing_keys(tool_iss, KEYDEFS, sk_file)

    sign_key, jb = key_setup(tool_iss, KEYDEFS, fo_liss, sk_file, bundle_file,
                             BASE_PATH)

    print(jb.keys())
