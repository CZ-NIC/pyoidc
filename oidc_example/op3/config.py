PORT = 8040
ISSUER = 'https://localhost'  # do not include the port, it will be added in the code.
SERVICEURL = "{issuer}verify"  # do not manually add issuer or port number, these will be added in the code.
SERVER_CERT = "certification/server.crt"
SERVER_KEY = "certification/server.key"
CERT_CHAIN = None

AUTHENTICATION = {
    "UserPassword":
        {
            "ACR": "PASSWORD",
            "WEIGHT": 1,
            "URL": SERVICEURL,
            "EndPoints": ["verify"],
        }
}

CLIENTDB = 'ClientDB'
SYM_KEY = "SoLittleTime,Got" # used for Symmetric key authentication only.
COOKIENAME = 'pyoic'
COOKIETTL = 4 * 60  # 4 hours

USERINFO = "SIMPLE"

USERDB = {
    "user1": {
        "sub": "sub1",
        "name": "name1",
        "given_name": "givenName1",
        "family_name": "familyName1",
        "nickname": "nickname1",
        "email": "email1@example.org",
        "email_verified": False,
        "phone_number": "+984400000000",
        "address": {
            "street_address": "address1",
            "locality": "locality1",
            "postal_code": "5719800000",
            "country": "Iran"
        },
    },
    "user2": {
        "sub": "sub2",
        "name": "name2",
        "given_name": "givenName2",
        "family_name": "familyName2",
        "nickname": "nickname2",
        "email": "email2@example.com",
        "email_verified": True,
        "address": {
            "street_address": "address2",
            "locality": "locality2",
            "region": "region2",
            "postal_code": "5719899999",
            "country": "Iran",
        },
    }
}

# This is a JSON Web Key (JWK) object, and its members represent
# properties of the key and its values.
keys = [
    {"type": "RSA", "key": "cryptography_keys/key.pem", "use": ["enc", "sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]}

    # "type" or "kty" identifies the cryptographic algorithm family used with the key.
    # The kty values are case sensitive. The kty values should either be registered
    # in the IANA "JSON Web Key Types" registery or be a value that contains a
    # Collision-Resistant Name. For more info on kty values refer to:
    # https://tools.ietf.org/html/rfc7518
    #
    # Cryptography keys are: private and public keys.
    # Keys are encrypted with RSA algorithm, and are stored in separate files in RSA.
    #
    # use (Public Key Use) parameter identifies the intended use of the public key.
    # This parameter is employed to indicate whether a public key is used for encryption
    # data or verifying the signature on data. Values defined by this specification are:
    # enc (encryption), sig (signature)
    #
    #
    # "RSA" (a public key cryptography), see:
    # http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    #
    # "EC": Elliptic Curve, see:
    # http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
]
