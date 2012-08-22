#!/usr/bin/env python
import json
import os
import M2Crypto
from M2Crypto.util import no_passphrase_callback

__author__ = 'rohe0002'

import sys
from oic.utils import keystore

def main(dir, size, fqdn):
    if not os.path.exists(dir):
        os.mkdir(dir)

    M2Crypto.Rand.rand_seed(os.urandom(size))
    key = M2Crypto.RSA.gen_key(size, 65537, lambda : None)
    key.save_key("%s/%s" % (dir, "key.pem"), None,
                 callback=no_passphrase_callback)

    (cert, _key) = keystore.make_cert(size, rsa=key)
    cert.save("%s/%s" % (dir, "cert.pem"))
    pk = cert.get_pubkey()
    pub_key = pk.get_rsa()
    jwk = {"keys": [keystore.kspec(pub_key, "sig")]}
    f = open("%s/%s" % (dir, "pub.jwk"), "w")
    f.write(json.dumps(jwk))
    f.close()

    # verify
    ks = keystore.KeyStore(None)
    ks.loads(open("%s/%s" % (dir, "pub.jwk")).read(), "sig", ".")
    skey = ks.get_sign_key("rsa")[0]
    assert pub_key.n == skey.n
    assert pub_key.e == skey.e

if __name__ == "__main__":
    size = 2048
    fqdn = "example.com"

    try:
        dir = sys.argv[1]
        try:
            bits = sys.argv[1]
            try:
                fqdn = sys.argv[2]
            except IndexError:
                fqdn = None
        except IndexError:
            bits=2048
    except IndexError:
        dir = "."

    main(dir, size, fqdn)
