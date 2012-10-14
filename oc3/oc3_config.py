baseurl = "https://localhost"
#issuer= "https://www.kodtest.se/rolandsOP"
issuer="https://localhost:8092"
keys= {
    "rsa": {
        "key":"oc3_keys/key.pem",
        "jwk": "oc3_keys/pub.jwk",
        "cert": "oc3_keys/cert.pem"
        }}
COOKIENAME= 'pyoic'
COOKIETTL = 4*60 # 4 hours
SEED = "SoLittleTime,GotToHurry"
SERVER_CERT="certs/server.crt"
SERVER_KEY="certs/server.key"
#CERT_CHAIN="certs/chain.pem"
CERT_CHAIN=None