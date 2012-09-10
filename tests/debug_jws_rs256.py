from oic.utils.keystore import rsa_load
from oic.utils import jwt

__author__ = 'rohe0002'

rsapub = rsa_load("../oc3/certs/mycert.key")

payload = "Please take a moment to register today"
keycol = {"rsa": [rsapub]}

_jwt = jwt.sign(payload, keycol, "RS256")

info = jwt.verify(_jwt, keycol)

assert info == payload
