#!/usr/bin/env python

from oic.oauth2 import PBase
from oic.utils.keystore import KeyStore, x509_rsa_loads

__author__ = 'rohe0002'

def main(x509_file, out="keys.jwk"):
    pb = PBase()
    ks = KeyStore(pb.http_request)

    key = x509_rsa_loads(open(x509_file).read())
    ks.add_key(key, "rsa", "sig")

    f = open(out, "w")
    txt = ks.dumps("sig")
    f.write(txt)
    f.close()

if __name__ == "__main__":
    import sys
    main(*sys.argv[1:2])
