__author__ = 'rohe0002'

from oic.oic.message import *

def _eq(l1, l2):
    return set(l1) == set(l2)

def test_iss():
    swd = SWDServiceRedirect(location="https://example.net")
    ir = IssuerResponse(SWD_service_redirect=swd)
    res = ir.get_json()
    assert res == '{"SWD_service_redirect": {"location": "https://example.net"}}'

def test_JWKEllipticKeyObject():
    jeko = JWKEllipticKeyObject(algorithm="EC", curve="P-256",
                                x="MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                                y="4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                                use="encryption", keyid="1")

    assert jeko.keyid == "1"
    assert jeko.use == "encryption"
    assert jeko.curve == "P-256"

def test_JWKRSAKeyObject():
    jrsa = JWKRSAKeyObject(algorithm="RSA", exponent="AQAB",
                           keyid="2011-04-29",
                           modulus="0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    )

    assert jrsa.algorithm == "RSA"
    assert jrsa.exponent == "AQAB"

def test_JWKKeyObject():
    jwk = JWKKeyObject(algorithm="RSA", exponent="AQAB",
                           keyid="2011-04-29",
                           modulus="0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")

    assert _eq(jwk.keys(), ['keyid', 'algorithm', 'modulus', 'exponent'])