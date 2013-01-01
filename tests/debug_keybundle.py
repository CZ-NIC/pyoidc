from oic.utils.keyio import KeyBundle, key_eq

__author__ = 'rolandh'

jwk_url = ["https://connect.openid4.us/connect4us.jwk", # edmund
       "https://connect-op.heroku.com/jwk.json"]    # nov

x509_url = ["https://connect-op.heroku.com/cert.pem"]

kc0 = KeyBundle(source=jwk_url[1], src_type="jwk", type="rsa", usage=["sig", "enc"])

kc1 = KeyBundle(source=x509_url[0], src_type="x509", type="rsa", usage=["sig", "enc"])

kc0.update()

print kc0

kc1.update()

print kc1

print key_eq(kc0.get("rsa")[0], kc1.get("rsa")[0])