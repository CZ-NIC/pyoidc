#!/usr/bin/env python3

import json
from jwkest.jws import factory

from oic.federation import MetadataStatement
from oic.federation.bundle import JWKSBundle
from oic.federation.operator import Operator
from oic.oauth2 import Message
from oic.oic.message import RegistrationRequest

from oic.utils.keyio import build_keyjar

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

    print(70 * ".")
    print(headline)
    print(70 * ".")
    print_lines(json.dumps(json.loads(_jwks), sort_keys=True, indent=2,
                           separators=(',', ': ')))


def print_metadata_statement(txt, sms):
    _jwt = factory(sms)
    _sos = json.loads(_jwt.jwt.part[1].decode('utf8'))

    print(70 * "=")
    print(txt)
    print(70 * "=")
    print_lines(
        json.dumps(_sos, sort_keys=True, indent=2, separators=(',', ': ')))


def print_request(txt, req):
    print(70 * "-")
    print(txt)
    print(70 * "-")
    print_lines(json.dumps(req.to_dict(), sort_keys=True, indent=2,
                           separators=(',', ': ')))


key_conf = [
    {"type": "RSA", "use": ["sig"]},
]

# -----------------------------------------------------------------------------
# FO get's its key pair
# -----------------------------------------------------------------------------

swamid = Operator(iss='https://swamid.sunet.se/',
                  keyjar=build_keyjar(key_conf)[1])

print_private_key(swamid.keyjar, "SWAMID's key pair")

incommon = Operator(iss='https://www.incommon.org',
                    keyjar=build_keyjar(key_conf)[1])

print_private_key(incommon.keyjar, "InCommon's key pair")

# -----------------------------------------------------------------------------
# Create initial Organisation key pair (OA)
# -----------------------------------------------------------------------------

sunet = Operator(iss='https://www.sunet.se', keyjar=build_keyjar(key_conf)[1])

# -----------------------------------------------------------------------------
# -- construct JSON document to be signed by SWAMID
# -----------------------------------------------------------------------------

sunet_msreq = MetadataStatement(
    contacts=['dev_admin@sunet.se'],
    policy_uri='https://sunet.se/policy.html',
    tos_uri='https://sunet.se/tos.html',
    logo_uri='https://sunet.se/logo.jpg',
    signing_keys=sunet.signing_keys_as_jwks()
)

print_request('SUNET Metadata Statement request', sunet_msreq)

# -----------------------------------------------------------------------------
# The SWAMID FO constructs Metadata statement
# -----------------------------------------------------------------------------

sunet_msreq.update({
    "response_types": ["code", "code id_token", "token"],
    "token_endpoint_auth_method": "private_key_jwt",
    "scopes": ['openid', 'email', 'phone']
})

jwt_args = {'aud': [sunet.iss]}
sunet_swamid = swamid.pack_metadata_statement(sunet_msreq, jwt_args=jwt_args)

print_metadata_statement('SUNETs by SWAMID extended metadata statement',
                         sunet_swamid)

# -----------------------------------------------------------------------------
# -- JSON document to be signed by InCommon, same as for SWAMID
# -----------------------------------------------------------------------------

sunet_msreq = MetadataStatement(
    contacts=['dev_admin@sunet.se'],
    policy_uri='https://sunet.se/policy.html',
    tos_uri='https://sunet.se/tos.html',
    logo_uri='https://sunet.se/logo.jpg',
    signing_keys=sunet.signing_keys_as_jwks()
)

# -----------------------------------------------------------------------------
# The InCommon FO constructs Software statement
# -----------------------------------------------------------------------------

sunet_msreq.update({
    "response_types": ["code", "token"],
    "token_endpoint_auth_method": "private_key_jwt",
    "scopes": ['openid', 'email']
})

jwt_args = {'aud': [sunet.iss]}
sunet_incommon = incommon.pack_metadata_statement(sunet_msreq,
                                                  jwt_args=jwt_args)

print_metadata_statement('SUNEts by InCommon extended metadata statement',
                         sunet_incommon)

# -----------------------------------------------------------------------------
# The RP as federation entity
# -----------------------------------------------------------------------------

sunet_rp = Operator(iss='https://sunet.se/sysadm',
                    keyjar=build_keyjar(key_conf)[1])

# -----------------------------------------------------------------------------
# -- construct Registration Request to be signed by organisation
# -----------------------------------------------------------------------------

rreq = RegistrationRequest(
    redirect_uris=['https://sunet.se/rp1/callback'],
    application_type='web',
    response_types=['code'],
    signing_keys=sunet_rp.signing_keys_as_jwks(),
    jwks_uri_signed='https://sunet.se/rp1/jwks.jws'
)

print_request('Client Registration request', rreq)

# -----------------------------------------------------------------------------
# SUNET signs Registration Request once per federation
# -----------------------------------------------------------------------------

# adds the developers software statement
rreq.update({
    "metadata_statements": [sunet_swamid],
})

jwt_args = {"aud": sunet_rp.iss, "sub": sunet_rp.iss}
rp_sunet_swamid = sunet.pack_metadata_statement(rreq, jwt_args=jwt_args)

print_metadata_statement(
    'Registration request extended by SUNET@SWAMID', rp_sunet_swamid)

rreq.update({
    "metadata_statements": [sunet_incommon],
})

rp_sunet_incommon = incommon.pack_metadata_statement(rreq, jwt_args=jwt_args)

print_metadata_statement('Registration request extended by SUNET@InCommon',
                         rp_sunet_incommon)

# ----------------------------------------------------------------------------
# The RP publishes Registration Request
# ----------------------------------------------------------------------------

rere = Message(
    redirect_uris=['https://sunet.se/rp1/callback'],
    metadata_statements=[rp_sunet_swamid, rp_sunet_incommon]
)

print_request('Registration Request published by RP', rere)

# ### ======================================================================
# #   On the OP
# ### ======================================================================

_jb = JWKSBundle('https://sunet.se/op')
_jb[swamid.iss] = swamid.signing_keys_as_jwks()
_jb[incommon.iss] = incommon.signing_keys_as_jwks()

op = Operator(iss='https://sunet.se/op', jwks_bundle=_jb)

print('Unpack the request')

# -----------------------------------------------------------------------------
# Unpacking the russian doll (= the metadata_statements)
# -----------------------------------------------------------------------------

_cms = op.unpack_metadata_statement(json_ms=rere)
res = op.evaluate_metadata_statement(_cms)

print(70 * ":")
print('Unpacked and flattened metadata statement per FO')
print(70 * ":")
print_lines(json.dumps(res, sort_keys=True, indent=2,
                       separators=(',', ': ')))
