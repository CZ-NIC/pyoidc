from jwkest.jws import alg2keytype
from oic.oic.message import IdToken
from oic.utils.keyio import KeyJar, keybundle_from_local_file

__author__ = 'rohe0002'

kc = keybundle_from_local_file("../oc3/certs/mycert.key", "rsa", ["ver",
                                                                  "sig"])

kj = KeyJar()

kj["foobar"] = [kc]

idt = IdToken().from_dict({"user_id": "diana", "aud": "uo5nowsdL3ck",
                           "iss": "https://localhost:8092", "acr": "2",
                           "exp": 1354442188, "iat": 1354359388})

ckey = kj.get_signing_key(alg2keytype("RS256"), "foobar")
_signed_jwt = idt.to_jwt(key=ckey, algorithm="RS256")