#!/usr/bin/env python

import json
from jwkest.jws import JWS
from jwkest.jws import factory
from oic.extension.client import make_software_statement
from oic.extension.client import RegistrationRequest
from oic.extension.client import unpack_software_statement
from oic.extension.oidc_fed import SoftwareStatement
from oic.utils.keyio import build_keyjar
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar

__author__ = 'roland'


def print_lines(lines, maxlen=70):
    for line in lines.split('\n'):
        if len(line) <= maxlen:
            print(line)
        else:
            n = maxlen
            for l in [line[i:i + n] for i in range(0, len(line), n)]:
                print(l)


def print_private_key(keyjar, headline):
    _jwks = keyjar.issuer_keys[''][0].jwks(private=True)  # Only one bundle

    print(70 * "-")
    print(headline)
    print(70 * "-")
    print_lines(json.dumps(json.loads(_jwks), sort_keys=True, indent=2,
                           separators=(',', ': ')))

key_conf = [
    {"type": "RSA", "use": ["sig"]},
]

# -----------------------------------------------------------------------------
# FO get's its key pair
# -----------------------------------------------------------------------------

fo_jwks, fo_keyjar = build_keyjar(key_conf)[:-1]

print_private_key(fo_keyjar, "FO's key pair")


# -----------------------------------------------------------------------------
# Create initial RP key pair (A)
# -----------------------------------------------------------------------------

pub_jwks, a_keyjar, kdd = build_keyjar(key_conf)

print_private_key(a_keyjar, "Primary signing key")

# -----------------------------------------------------------------------------
# -- construct JSON document to be signed by FO
# -----------------------------------------------------------------------------

ssreq = SoftwareStatement(
    redirect_uris=['https://example.com/rp/cb'],
    signing_key=pub_jwks['keys'][0]
)

print(70 * "-")
print('Software statement request')
print(70 * "-")
print_lines(json.dumps(ssreq.to_dict(), sort_keys=True, indent=2,
                       separators=(',', ': ')))

# -----------------------------------------------------------------------------
# The FO constructs Software statement
# -----------------------------------------------------------------------------

ssreq.update({
    "response_types": ["code", "token"],
    "token_endpoint_auth_method": "private_key_jwt",
    "scopes_allowed": ['openid', 'email', 'phone']
})

sost = make_software_statement(fo_keyjar, 'https://fo.example.com/',
                               **ssreq.to_dict())
_jwt = factory(sost)
_sos = json.loads(_jwt.jwt.part[1].decode('utf8'))

print(70 * "-")
print('FO extended software statement')
print(70 * "-")
print_lines(json.dumps(_sos, sort_keys=True, indent=2, separators=(',', ': ')))
print()
print_lines(sost)

# -----------------------------------------------------------------------------
# Create intermediate key pair
# -----------------------------------------------------------------------------

im_jwks, im_keyjar = build_keyjar(key_conf)[:-1]

print_private_key(im_keyjar, 'RP intermediate key')

# -----------------------------------------------------------------------------
# make a signed JWT with im_jwks as message body
# -----------------------------------------------------------------------------

_jws = JWS(im_jwks, alg="RS384")
keys = a_keyjar.keys_by_alg_and_usage('', 'RS384', 'sig')
signed_intermediate = _jws.sign_compact(keys)

print(70 * "-")
print("Signed intermediate key")
print(70 * "-")
print_lines(signed_intermediate)

# -----------------------------------------------------------------------------
# Create RP public keys, sign_jwks is what's support to be found at jwks_uri
# -----------------------------------------------------------------------------

rp_session_key_conf = [
    {"type": "RSA", "use": ["sig", 'enc']},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]}
]

sign_jwks, sign_keyjar = build_keyjar(rp_session_key_conf)[:-1]

print(70 * "-")
print("Keys at jwks_uri")
print(70 * "-")
print_lines(
    json.dumps(sign_jwks, sort_keys=True, indent=2, separators=(',', ': ')))

# -----------------------------------------------------------------------------
# Create signed_jwks_uri
# -----------------------------------------------------------------------------

_jws = JWS(sign_jwks, alg="RS256")
keys = im_keyjar.keys_by_alg_and_usage('', 'RS256', 'sig')
signed_jwks = _jws.sign_compact(keys)

print(70 * "-")
print('signed_jwks_uri content')
print(70 * "-")
print_lines(signed_jwks)

# -----------------------------------------------------------------------------
# Create client registration request
# -----------------------------------------------------------------------------

rr = RegistrationRequest(
    jwks_uri='https://example.com/rp/jwks',
    software_statements=[sost],
    signed_jwks_uri='https://example.com/rp/signed_jwks',
    response_types=['code'],
    id_token_signed_response_alg='SHA-256',
    signing_key=signed_intermediate
)

_jws = JWS(rr.to_json(), alg='RS256')
keys = a_keyjar.keys_by_alg_and_usage('', 'RS384', 'sig')
signed_reg_req = _jws.sign_compact(keys)

rr['signed_metadata'] = signed_reg_req

print(70 * "-")
print('Client registration request')
print(70 * "-")
print_lines(
    json.dumps(rr.to_dict(), sort_keys=True, indent=2, separators=(',', ': ')))

#### ======================================================================
##   On the OP
#### ======================================================================

op_keyjar = KeyJar()
op_keyjar.add_kb('https://fo.example.com/', KeyBundle(fo_jwks['keys']))

# -----------------------------------------------------------------------------
# Unpack software_statements
# -----------------------------------------------------------------------------

msgs = []

# Only one software statement
sost = rr['software_statements'][0]

_sost = unpack_software_statement(sost, '', op_keyjar)
fo_id = _sost['iss']

# ------------------------------
# get the long lived RP key (A)
# ------------------------------
A_keyjar = KeyJar()
A_keyjar.add_kb('', KeyBundle(_sost['signing_key']))

print(70 * "-")
print('Received primary key')
print(70 * "-")
print_lines(
    json.dumps(_sost['signing_key'], sort_keys=True, indent=2,
               separators=(',', ': ')))


# ------------------------------
#  get the intermediate key
# ------------------------------

_jws = factory(rr['signing_key'])
_keys = A_keyjar.get_issuer_keys('')
intermediate_keys = _jws.verify_compact(rr['signing_key'], _keys)
intermediate_keyjar = KeyJar()
intermediate_keyjar.add_kb('', KeyBundle(intermediate_keys['keys']))

print(70 * "-")
print('Received intermediate keys')
print(70 * "-")
print_lines(
    json.dumps(intermediate_keys, sort_keys=True, indent=2,
               separators=(',', ': ')))

# ------------------------------
#  Verify metadata signature
# ------------------------------

_jws = factory(rr['signed_metadata'])
_keys = A_keyjar.get_issuer_keys('')
metadata = _jws.verify_compact(rr['signed_metadata'], _keys)
print(70 * "-")
print('Verified metadata')
print(70 * "-")
print_lines(json.dumps(metadata, sort_keys=True, indent=2,
                       separators=(',', ': ')))

# ----------------------------------------------
#  Verify the info fetched from signed_jwks_uri
# ----------------------------------------------
_jws = factory(signed_jwks)
_keys = intermediate_keyjar.get_issuer_keys('')
rp_keys = _jws.verify_compact(signed_jwks, _keys)
print(70 * "-")
print('Verified RP public keys')
print(70 * "-")
print_lines(json.dumps(rp_keys, sort_keys=True, indent=2,
                       separators=(',', ': ')))
