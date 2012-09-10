import os
import M2Crypto
from oic.utils.keystore import KeyStore, x509_rsa_loads

__author__ = 'rohe0002'

keystore = KeyStore(None)

keystore.loads(open("jwk.json").read(), "sig", "http://example.com")

print len(keystore._store)

key = keystore.get_sign_key(type="rsa", owner="http://example.com")

print len(key[0])

size = 2048
M2Crypto.Rand.rand_seed(os.urandom(size))
newkey = M2Crypto.RSA.gen_key(size, 65537)

print len(newkey)

keystore.add_key(newkey, "rsa", "sig")

_jwk = keystore.dumps("sig")
print _jwk
keystore.loads(_jwk, "sig", "http://example.org")

print len(keystore._store)

key = keystore.get_sign_key(type="rsa", owner="http://example.org")

print len(key[0])

cert = """-----BEGIN CERTIFICATE-----
MIIE1zCCA7+gAwIBAgIDAxPgMA0GCSqGSIb3DQEBBQUAMDwxCzAJBgNVBAYTAlVT
MRcwFQYDVQQKEw5HZW9UcnVzdCwgSW5jLjEUMBIGA1UEAxMLUmFwaWRTU0wgQ0Ew
HhcNMTEwOTA3MTkzOTI2WhcNMTIwOTA5MDkzMzI5WjCB6zEpMCcGA1UEBRMgRi82
MEZLdjRkZGttVG1rZlkzVExVS0h1dTBTRVJybUQxCzAJBgNVBAYTAlVTMRswGQYD
VQQKExJjb25uZWN0Lm9wZW5pZDQudXMxEzARBgNVBAsTCkdUMTM2MTcyNTcxMTAv
BgNVBAsTKFNlZSB3d3cucmFwaWRzc2wuY29tL3Jlc291cmNlcy9jcHMgKGMpMTEx
LzAtBgNVBAsTJkRvbWFpbiBDb250cm9sIFZhbGlkYXRlZCAtIFJhcGlkU1NMKFIp
MRswGQYDVQQDExJjb25uZWN0Lm9wZW5pZDQudXMwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQC1/+wHgzSwd5qtEvPPWrUlGBF1GfCTSXP4hxUMWWmnZ20N
XID5kzxO7WzCnu6lpM3KR/tync17/q5bcmIq9EwN0128dYLMMeZuZlYZ2cUX1V74
PVxTGPgRNWlQzsAhdZsazfh9Q1iXdfNzhtpLK9htzeHqLPwAh1v/VtAvEmwcGL7J
2Dc0wki2BAmoGLAKZBgI6cmV6RH4ZrZrleUjHjpayPc/PS3R3MzyBVJT19TdCsor
MMUKgUdOCKDVhk01blbYfpDAA0vmH6duCt7mxaYOZ2d+JTo+PkY5AOan/+vB6Kem
Hw4AU0XqNWqtFndAkSYyc7jadpY6zFXYUBRdp+SxAgMBAAGjggEwMIIBLDAfBgNV
HSMEGDAWgBRraT1qGEJK3Y8CZTn9NSSGeJEWMDAOBgNVHQ8BAf8EBAMCBaAwHQYD
VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdEQQWMBSCEmNvbm5lY3Qu
b3BlbmlkNC51czBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vcmFwaWRzc2wtY3Js
Lmdlb3RydXN0LmNvbS9jcmxzL3JhcGlkc3NsLmNybDAdBgNVHQ4EFgQUgaqWav9/
ECejN+in7Z8HpjDPJnAwDAYDVR0TAQH/BAIwADBJBggrBgEFBQcBAQQ9MDswOQYI
KwYBBQUHMAKGLWh0dHA6Ly9yYXBpZHNzbC1haWEuZ2VvdHJ1c3QuY29tL3JhcGlk
c3NsLmNydDANBgkqhkiG9w0BAQUFAAOCAQEARHKcvIHCHhqYlKUDzgTGIG6TqSIp
lkPkeUImcDFaVdiR96SVGK2EWK5qa+ptWqJbYNyDHiwzAXBrXnNZfBpXl+V0XTSC
PowH3aV+Pb1g3NMPL4Wz0RduZt6kQfMrfqSYbFmeJ3Iv0qQP8jZZ8/q7N6mTMrLl
9e8kzuCGCIl1VNmDkWOhPQa0d9LBAjk0y9e0Bw04k20tmNoObIhlEo0WmNMfauw/
ie4Pxhr1sUlXB6Lfbt5N6bQJIOnqADQbH9NScIDnr1QPhHjyiZKPVLrLr7vLVMwG
rmBLACZlz+wWXu+/uYFlRICOb5nRU+FJrT3B8KEsa8p4KDXOsEVo3FofmA==
-----END CERTIFICATE-----"""

_k = x509_rsa_loads(cert)

print _k.n
