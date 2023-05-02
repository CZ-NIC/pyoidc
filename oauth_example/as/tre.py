from oic.utils.keyio import build_keyjar
from oic.utils.keyio import dump_jwks

__author__ = "roland"

key_conf = [{"type": "RSA", "use": ["enc", "sig"]}]

pub_jwks, keyjar, kdd = build_keyjar(key_conf, "tre%d", None, None)

dump_jwks(keyjar.issuer_keys[""], "tre.jwks")
