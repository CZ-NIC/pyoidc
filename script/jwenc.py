#!/usr/bin/env python
import sys

__author__ = 'rohe0002'

import argparse
import requests
from oic.jwt import jwe
from oic.jwt import jwk
from oic.utils.keyio import load_jwk
from oic.utils.keyio import load_x509_cert
from oic.utils.keyio import x509_rsa_loads

def assign(lst):
    keys = {}
    for typ, key in lst:
        try:
            keys[typ].append(key)
        except KeyError:
            keys[typ] = [key]
    return keys

def lrequest(url, method="GET", **kwargs):
    return requests.request(method, url, **kwargs)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='debug', action='store_true',
                              help="Print debug information")
    parser.add_argument('-v', dest='verbose', action='store_true',
                              help="Print runtime information")
    parser.add_argument('-x', dest="x509_file",
                              help="File containing a X509 certificate")
    parser.add_argument('-X', dest="x509_url",
                        help="URL pointing to a file containing a X509 certificate")
    parser.add_argument('-j', dest="jwk_file",
                              help="File containing a JWK")
    parser.add_argument('-J', dest="jwk_url",
                        help="URL pointing to a file containing a JWK")
    parser.add_argument('-a', dest="alg",
                              help="The encryption algorithm")
    parser.add_argument("-e", dest="enc", help="The encryption method")
    parser.add_argument("-i", dest="int",
                              help="Integrity method")
    parser.add_argument("message", nargs="?", help="The message to encrypt")


    args = parser.parse_args()

    keys = {}
    if args.jwk_url:
        keys = assign(load_jwk(lrequest, args.jwk_url, {}))
    elif args.jwk_file:
        keys = assign(jwk.loads(open(args.jwk_file).read(), {}))
    elif args.x509_url:
        keys = assign(load_x509_cert(lrequest, args.x509_url, {}))
    elif args.x509_file:
        keys = {"rsa": [x509_rsa_loads(open(args.x509_file).read())]}
    else:
        print >> sys.stderr, "Needs encryption key"
        exit()

    print jwe.encrypt(args.message, keys, args.alg, args.enc, "public")