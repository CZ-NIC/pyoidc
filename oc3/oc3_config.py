# -*- coding: utf-8 -*-

#issuer= "https://www.kodtest.se/rolandsOP"
baseurl = "https://localhost"
#baseurl = "https://lingon.ladok.umu.se"
issuer = "%s:8092" % baseurl
keys = {
    "rsa": {
        "key": "oc3_keys/key.pem",
        "jwk": "oc3_keys/pub.jwk",
        "cert": "oc3_keys/cert.pem"
    }
}

COOKIENAME= 'pyoic'
COOKIETTL = 4*60 # 4 hours
SYM_KEY = "SoLittleTime,GotToHurry"
SERVER_CERT = "certs/server.crt"
SERVER_KEY = "certs/server.key"
#CERT_CHAIN="certs/chain.pem"
CERT_CHAIN = None

CLAIMS_PROVIDER = "https://localhost:8093/"

USERDB = {
    "diana": {
        "user_id": "dikr0001",
        "name": "Diana Krall",
        "given_name": "Diana",
        "family_name": "Krall",
        "nickname": "Dina",
        "email": "diana@example.org",
        "email_verified": False,
        "phone_number": "+46 90 7865000",
        "address": {
            "street_address": "Umeå Universitet",
            "locality": "Umeå",
            "postal_code": "SE-90187",
            "country": "Sweden"
        },
        },
    "babs": {
        "user_id": "babs0001",
        "name": "Barbara J Jensen",
        "given_name": "Barbara",
        "family_name": "Jensen",
        "nickname": "babs",
        "email": "babs@example.com",
        "email_verified": True,
        "address": {
            "street_address": "100 Universal City Plaza",
            "locality": "Hollywood",
            "region": "CA",
            "postal_code": "91608",
            "country": "USA",
            },
        "_external_": {
            CLAIMS_PROVIDER: ["geolocation"]
        }
    },
    "upper": {
        "user_id": "uppe0001",
        "name": "Upper Crust",
        "given_name": "Upper",
        "family_name": "Crust",
        "email": "uc@example.com",
        "email_verified": True,
        "_external_": {
            CLAIMS_PROVIDER: ["geolocation"]
        }
    }
}

CLIENT_INFO = { }
#    CLAIMS_PROVIDER: {
#        "userclaims_endpoint":"%suserclaims" % CLAIMS_PROVIDER,
#        "client_id": "client_1",
#        "client_secret": "hemlig",
#        "x509_url": "%scp_keys/cert.pem" % CLAIMS_PROVIDER,
#        "jwk_url": "%scp_keys/pub.jwk" % CLAIMS_PROVIDER,
#        }
#}
