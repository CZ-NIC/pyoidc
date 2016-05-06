#!/usr/bin/env python3

import json
from jwkest.jws import factory

from oic.oauth2 import Message
from oic.oic.message import RegistrationRequest

from oic.extension.message import make_software_statement
from oic.extension.message import unpack_software_statement
from oic.extension.message import SoftwareStatement
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

swamid_issuer = 'https://swamid.sunet.se/'
swamid_jwks, swamid_keyjar = build_keyjar(key_conf)[:-1]

print_private_key(swamid_keyjar, "SWAMID's key pair")

incommon_issuer = 'https://www.incommon.org'
incommon_jwks, incommon_keyjar = build_keyjar(key_conf)[:-1]

print_private_key(incommon_keyjar, "InCommon's key pair")

# -----------------------------------------------------------------------------
# Create initial Developer key pair (A)
# -----------------------------------------------------------------------------

dev_swamid_jwks, dev_swamid_keyjar, _ = build_keyjar(key_conf)
print_private_key(dev_swamid_keyjar, "Developers SWAMID signing key")

dev_incommon_jwks, dev_incommon_keyjar, _ = build_keyjar(key_conf)
print_private_key(dev_incommon_keyjar, "Developers InCommon signing key")

# -----------------------------------------------------------------------------
# -- construct JSON document to be signed by SWAMID
# -----------------------------------------------------------------------------

ssreq = SoftwareStatement(
    contacts=['dev_admin@example.com'],
    policy_uri='https://example.com/policy.html',
    tos_uri='https://example.com/tos.html',
    logo_uri='https://example.com/logo.jpg',
    signing_key=dev_swamid_jwks['keys'][0]
)

print(70 * "-")
print('Software statement request')
print(70 * "-")
print_lines(json.dumps(ssreq.to_dict(), sort_keys=True, indent=2,
                       separators=(',', ': ')))

# -----------------------------------------------------------------------------
# The SWAMID FO constructs Software statement
# -----------------------------------------------------------------------------

ssreq.update({
    "response_types": ["code", "code id_token", "token"],
    "token_endpoint_auth_method": "private_key_jwt",
    "scopes": ['openid', 'email', 'phone']
})

dev_swamid_sost = make_software_statement(swamid_keyjar, swamid_issuer,
                                          **ssreq.to_dict())
_jwt = factory(dev_swamid_sost)
_sos = json.loads(_jwt.jwt.part[1].decode('utf8'))

print(70 * "-")
print('SWAMID extended software statement')
print(70 * "-")
print_lines(json.dumps(_sos, sort_keys=True, indent=2, separators=(',', ': ')))

# -----------------------------------------------------------------------------
# -- construct JSON document to be signed by InCommon
# -----------------------------------------------------------------------------

ssreq = SoftwareStatement(
    contacts=['dev_admin@example.com'],
    policy_uri='https://example.com/policy.html',
    tos_uri='https://example.com/tos.html',
    logo_uri='https://example.com/logo.jpg',
    signing_key=dev_incommon_jwks['keys'][0]
)

print(70 * "-")
print('Software statement request')
print(70 * "-")
print_lines(json.dumps(ssreq.to_dict(), sort_keys=True, indent=2,
                       separators=(',', ': ')))

# -----------------------------------------------------------------------------
# The InCommon FO constructs Software statement
# -----------------------------------------------------------------------------

ssreq.update({
    "response_types": ["code", "token"],
    "token_endpoint_auth_method": "private_key_jwt",
    "scopes": ['openid', 'email']
})

dev_incommon_sost = make_software_statement(incommon_keyjar, incommon_issuer,
                                            **ssreq.to_dict())
_jwt = factory(dev_incommon_sost)
_sos = json.loads(_jwt.jwt.part[1].decode('utf8'))

print(70 * "-")
print('InCommon extended software statement')
print(70 * "-")
print_lines(json.dumps(_sos, sort_keys=True, indent=2, separators=(',', ': ')))

# -----------------------------------------------------------------------------
# The RPs signing key
# -----------------------------------------------------------------------------

rp_jwks, rp_keyjar, _ = build_keyjar(key_conf)

print_private_key(rp_keyjar, "RPs signing key")

# -----------------------------------------------------------------------------
# -- construct Registration Request to be signed by Developer
# -----------------------------------------------------------------------------

rreq = RegistrationRequest(
    redirect_uris=['https://example.com/rp1/callback'],
    application_type='web',
    response_types=['code'],
    signing_key=rp_jwks['keys'][0],
    jwks_uri_signed='https://example.com/rp1/jwks.jws'
)

print(70 * "-")
print('Client Registration request')
print(70 * "-")
print_lines(json.dumps(rreq.to_dict(), sort_keys=True, indent=2,
                       separators=(',', ': ')))

# -----------------------------------------------------------------------------
# Developer signs Registration Request once per federation
# -----------------------------------------------------------------------------

# adds the developers software statement
rreq.update({
    "software_statements": [dev_swamid_sost],
})

print(70 * "-")
print('Developer adds software_statement to the Client Registration request')
print(70 * "-")

print_lines(json.dumps(rreq.to_dict(), sort_keys=True, indent=2,
                       separators=(',', ': ')))

rp_swamid_sost = make_software_statement(dev_swamid_keyjar,
                                         'https://dev.example.com/',
                                         **rreq.to_dict())

print(70 * "-")
print('.. and signs it producing a JWS')
print(70 * "-")
print_lines(rp_swamid_sost)

rreq.update({
    "software_statements": [dev_incommon_sost],
})

rp_incommon_sost = make_software_statement(dev_swamid_keyjar,
                                           'https://dev.example.com/',
                                           **rreq.to_dict())

# ----------------------------------------------------------------------------
# The RP publishes Registration Request
# ----------------------------------------------------------------------------

rere = Message(
    software_statement_uris={
        swamid_issuer: "https://dev.example.com/rp1/idfed/swamid.jws",
        incommon_issuer: "https://dev.example.com/rp1/idfed/incommon.jws"
    }
)

print('Registration Request published by RP')
print(70 * "-")
print_lines(json.dumps(rere.to_dict(), sort_keys=True, indent=2,
                       separators=(',', ': ')))

# ### ======================================================================
# #   On the OP
# ### ======================================================================

print('The OP chooses which federation it will work under - SWAMID of course')

op_keyjar = KeyJar()
op_keyjar.add_kb(swamid_issuer, KeyBundle(swamid_jwks['keys']))

# -----------------------------------------------------------------------------
# Unpacking the russian doll (= the software_statement)
# -----------------------------------------------------------------------------

msgs = []

# Only one software statement
_rp_jwt = factory(rp_swamid_sost)
_rp_sost = json.loads(_rp_jwt.jwt.part[1].decode('utf8'))

# Only one Software Statement within the signed
sost = _rp_sost['software_statements'][0]

_sost_dev = unpack_software_statement(sost, '', op_keyjar)
assert _sost_dev['iss'] == swamid_issuer

# ----------------------------------------
# get the Developers key and issuer ID
# ----------------------------------------

DEV_keyjar = KeyJar()
DEV_keyjar.add_kb('', KeyBundle(_sost_dev['signing_key']))

dev_iss = _rp_sost['iss']

# -----------------------------------------------------------------------------

_sost_rp = unpack_software_statement(rp_swamid_sost, dev_iss, DEV_keyjar)

assert _sost_rp

regreq_rp = RegistrationRequest(**_sost_rp)
regreq_rp.weed()

regreq_dev = RegistrationRequest(**_sost_dev)
regreq_dev.weed()

for key, val in regreq_rp.items():
    if key not in regreq_dev:
        regreq_dev[key] = val
    elif isinstance(val, list):
        regreq_dev[key] = list(set(regreq_dev[key]).intersection(val))

print(70 * "-")
print_lines(json.dumps(regreq_dev.to_dict(), sort_keys=True, indent=2,
                       separators=(',', ': ')))
