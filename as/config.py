# -*- coding: utf-8 -*-
__author__ = 'rolandh'

baseurl = "https://localhost"
issuer = "%s:8092" % baseurl

COOKIENAME = 'pyoic'
COOKIETTL = 4 * 60  # 4 hours
SEED = "SoLittleTime,GotToHurry"
SERVER_CERT = "certs/server.crt"
SERVER_KEY = "certs/server.key"
#CERT_CHAIN="certs/chain.pem"
CERT_CHAIN = None


USERDB = {
    "haho0032": {
        "user_id": "haho0032",
        "name": "Hans Hörberg",
        "given_name": "Hans",
        "family_name": "Hörberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "email_verified": False,
        "phone_number": "+46 90 7865000",
        "address": {
            "street_address": "Umeå Universitet",
            "locality": "Umeå",
            "postal_code": "SE-90187",
            "country": "Sweden"
        },
    },
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
    },
    "upper": {
        "user_id": "uppe0001",
        "name": "Upper Crust",
        "given_name": "Upper",
        "family_name": "Crust",
        "email": "uc@example.com",
        "email_verified": True,
    }
}

CLIENT = {
    "1234567890" :{
        "client_secret": "SoonerOrLater",
        "return_uris": ["https://localhost:8091"]
    }
}