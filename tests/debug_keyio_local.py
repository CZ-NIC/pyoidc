from jwkest.jws import alg2keytype
from oic.oic.message import IdToken
from oic.utils.keyio import KeyBundle, KeyJar

__author__ = 'rohe0002'

b0 = KeyBundle(source="http://localhost:8090/exports/jwk.json", src_type="jwk",
               usage=["ver", "dec", "sig"])

b1 = KeyBundle(source="http://localhost:8090/exports/cert.pem", src_type="x509",
               usage=["ver", "dec", "sig"])

print b0
print b1

kj = KeyJar()

kj["foobar"] = [b0, b1]

idt = IdToken().from_dict({"user_id": "diana", "aud": "uo5nowsdL3ck",
                           "iss": "https://localhost:8092", "acr": "2",
                           "exp": 1354442188, "iat": 1354359388})

ckey = kj.get_signing_key(alg2keytype("RS256"), "foobar")
_signed_jwt = idt.to_jwt(key=ckey, algorithm="RS256")