import json
from oic.oauth2 import PBase
from oic.utils.keystore import KeyStore
from oic.utils import keystore
import numbers

__author__ = 'rohe0002'

jwk_url = "https://connect.openid4.us/connect4us.jwk"
x509_url = "https://connect.openid4.us/connect4us.pem"

pb = PBase()
ks = KeyStore(pb.http_request)
#ks.load_jwk(jwk_url, "ver", "a")
#jkey = ks.get_verify_key("rsa", "a")[0]

r = ks.http_request(jwk_url, allow_redirects=True)
spec = json.loads(r.text)

xkey = ks.load_x509_cert(x509_url, "dec", "b")

xn = keystore.my_b64encode(keystore.mpi_to_long(xkey.n))
xe = keystore.my_b64encode(keystore.mpi_to_long(xkey.e))

xnn = keystore.my_b64encode(numbers.mpi_to_long(xkey.n))

kexp = spec["keys"][0]["exp"]
kmod = spec["keys"][0]["mod"]

print kmod
print xnn
#assert kexp == xe
#assert xn == kmod

e = keystore.my_b64decode(kexp)
n = keystore.my_b64decode(kmod)

print e
print n
print numbers.mpi_to_long(xkey.n)
print n - numbers.mpi_to_long(xkey.n)