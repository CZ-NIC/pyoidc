baseurl = "https://localhost"
#issuer= "https://www.kodtest.se/rolandsOP"
issuer="https://localhost:8088"
keys= {
    "rsa": {
        "key":"oc3_keys/key.pem",
        "jwk": "oc3_keys/pub.jwk",
        "cert": "oc3_keys/cert.pem"}}
COOKIENAME= 'pyoic'
COOKIETTL = 4*60 # 4 hours
SEED = "SoLittleTime,GotToHurry"
