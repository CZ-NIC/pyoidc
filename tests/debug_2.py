from oic.oic.consumer import Consumer
from oic.utils.keyio import KeyChain, KeyJar

__author__ = 'rohe0002'
from fakeoicsrv import MyFakeOICServer

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

RSAPUB = "../oc3/certs/mycert.key"

KC_HMAC_VS = KeyChain({"hmac": CLIENT_SECRET}, usage=["ver", "sig"])
KC_RSA = KeyChain(source="file://%s" % RSAPUB, type="rsa", usage=["ver", "sig"])
KC_HMAC_S = KeyChain({"hmac": CLIENT_SECRET}, usage=["sig"])

SRVKEYS = KeyJar()
SRVKEYS[""] = [KC_RSA]
SRVKEYS["client_1"] = [KC_HMAC_VS, KC_RSA]

c = Consumer(None, None)
mfos = MyFakeOICServer("http://example.com")
mfos.keyjar = SRVKEYS
c.http_request = mfos.http_request

principal = "foo@example.com"

res = c.discover(principal)
info = c.provider_config(res)
assert info.type() == "ProviderConfigurationResponse"
