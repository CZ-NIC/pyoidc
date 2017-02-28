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


def paragraph(*lines):
    print("\n".join(lines))
    print("")


key_conf = [
    {"type": "RSA", "use": ["sig"]},
]

paragraph(
    "The story is that UNINETT has applied and been accepted as a member",
    "of two federations: Feide and SWAMID.",
    "Now UNINETT is running a service (Foodle) that needs signed metadata",
    "statements to prove that it belongs to the federation",
    "that the OP belongs to when a user of the Foodle service wants to log",
    "in using an OP that belongs to either or both of the federations.")

paragraph("X.1.0 At the beginning of times this happens:")

# -----------------------------------------------------------------------------
# FO get's its key pair
# -----------------------------------------------------------------------------

swamid = Operator(iss='https://swamid.sunet.se/',
                  keyjar=build_keyjar(key_conf)[1])

print_private_key(swamid.keyjar,
                  "SWAMID gets a  key pair for signing Metadata Statements")

feide = Operator(iss='https://www.feide.no',
                 keyjar=build_keyjar(key_conf)[1])

print_private_key(feide.keyjar,
                  "Feide gets a key pair for signing Metadata Statements")

# -----------------------------------------------------------------------------
# Create initial Organisation key pair (OA)
# -----------------------------------------------------------------------------

paragraph("", "X.2.0", "@ UNINETT")
uninett = Operator(iss='https://www.uninett.no',
                   keyjar=build_keyjar(key_conf)[1])

print_private_key(feide.keyjar,
                  "UNINETT gets a key pair for signing Metadata Statements")

# -----------------------------------------------------------------------------
# -- construct JSON document to be signed by SWAMID
# -----------------------------------------------------------------------------
paragraph("", "Now is the time to construct the signed metadata statements",
          "and get them signed by the federations.",
          "We'll start with Feide and UNINETT")
paragraph("X.2.1", "UNINETT constructs a signing request containing only the",
          "public parts of the UNINETT signing keys")

uninett_feide_msreq = MetadataStatement(
    signing_keys=uninett.signing_keys_as_jwks()
)

print_request('UNINETT Metadata Statement request', uninett_feide_msreq)

# -----------------------------------------------------------------------------
# The SWAMID FO constructs Metadata statement
# -----------------------------------------------------------------------------

paragraph(
    "UNINETT sends the Metadata statement signing request to Feide and ",
    "Feide adds claims representing the Feide federation policiy.")

uninett_feide_msreq.update({
    'id_token_signing_alg_values_supported': ['RS256', 'RS512'],
    'claims': ['sub', 'name', 'email', 'picture']
})

uninett_feide_ms = feide.pack_metadata_statement(uninett_feide_msreq)

print_metadata_statement('X.2.2 Signed Metadata statement created by Feide',
                         uninett_feide_ms)

# -----------------------------------------------------------------------------
# -- JSON document to be signed by InCommon, same as for SWAMID
# -----------------------------------------------------------------------------

paragraph("", "The same process is repeated for UNINETT/SWAMID")

uninett_sunet_msreq = MetadataStatement(
    signing_keys=uninett.signing_keys_as_jwks()
)

# -----------------------------------------------------------------------------
# The InCommon FO constructs Software statement
# -----------------------------------------------------------------------------

paragraph("X.3.1", "SUNET gets the same signing request as Feide got but adds",
          "a different set of policy claims")

uninett_sunet_msreq.update({
    "response_types": ["code", "token"],
    "token_endpoint_auth_method": "private_key_jwt",
    "scopes": ['openid', 'email']
})

uninett_swamid_ms = swamid.pack_metadata_statement(uninett_sunet_msreq)

print_metadata_statement("X.3.2 The by SWAMID signed metadata statement",
                         uninett_swamid_ms)

paragraph("",
          "Now UNINETT sits with two signed metadata statements one for each of",
          "the federations it belongs to")

paragraph("X.4.0","Time to create the Foodle (RP) metadata statement",
          "We take a road similar to the request/request_uri path. That is we",
          "include all the information about the client that needs to be",
          "protect from tampering by a MITM and places it in the ",
          "metadata statement signing request.")

# -----------------------------------------------------------------------------
# The RP as federation entity
# -----------------------------------------------------------------------------

paragraph("But first Foodle needs it's own signing keys. Not for signing",
          "Metadata Statements but for signing the JWKS document found at",
          "the URI pointed to by jwks_uri.",
          "It is vital to protect this key information from tampering since",
          "a lot of the security of the future OIDC communication will",
          "depend on the correctness of the keys found at the jwks_uri.")

foodle_rp = Operator(iss='https://foodle.uninett.no',
                     keyjar=build_keyjar(key_conf)[1])

print_private_key(foodle_rp.keyjar,
                  "Foodle gets a key pair for signing the JWKS documents")

# -----------------------------------------------------------------------------
# -- construct Registration Request to be signed by organisation
# -----------------------------------------------------------------------------

paragraph("", "X.4.1", "And now for the registration request")

rreq = RegistrationRequest(
    redirect_uris=['https://foodle.uninett.no/callback'],
    application_type='web',
    response_types=['code'],
    signing_keys=foodle_rp.signing_keys_as_jwks(),
    signed_jwks_uri='https://foodle.uninett.no/jwks.jws'
)

print_request('Client Registration request', rreq)

# -----------------------------------------------------------------------------
# SUNET signs Registration Request once per federation
# -----------------------------------------------------------------------------

paragraph("The Client Registration Request is sent to UNINETT",
          "who adds the two signed metadata staments it has.",
          "One for each of SWAMID and Feide."
          "Since it knows that it is the Foodle RP which is the subject",
          "of the JWT it adds Foodle's identifier as 'sub'")

rreq.update({
    "metadata_statements": [uninett_swamid_ms, uninett_feide_ms],
})

jwt_args = {"sub": foodle_rp.iss}

foodle_uninett = uninett.pack_metadata_statement(rreq, jwt_args=jwt_args)

print_metadata_statement(
    'X.4.2 Metadata statement about Foodle signed by UNINETT', foodle_uninett)

# ----------------------------------------------------------------------------
# The RP publishes Registration Request
# ----------------------------------------------------------------------------

paragraph("",'X.5.0',
          'Now, when Foodle wants to register as a client with an OP it adds',
          "the signed Metadata statement it received from UNINETT to",
          "the client registration request.",
          "Note that 'redirect_uri' MUST be in the registration request as",
          "this is requied by the OIDC standard."
          "If the 'redirect_uris' values that are transfered unprotected ",
          "where to differ from what's in the signed metadata",
          "statement the OP MUST refuse the registration.")

rere = Message(
    redirect_uris=['https://foodle.uninett.no/callback'],
    metadata_statements=[foodle_uninett]
)

print_request('Registration Request published by RP', rere)

# ### ======================================================================
# #   On the OP
# ### ======================================================================

paragraph(
    "", "X.6.0",
    "The OP that has the public part of the signing keys for both",
    "SWAMID and Feide can now verify the signature chains all the",
    "way from the Metadata statement signed by UNINETT up to the FOs.",
    "If that works it can then flatten the compounded metadata statements.")

_jb = JWKSBundle('https://foodle.uninett.no')
_jb[swamid.iss] = swamid.signing_keys_as_jwks()
_jb[feide.iss] = feide.signing_keys_as_jwks()

op = Operator(iss='https://foodle.uninett.no', jwks_bundle=_jb)

print('Unpack the client registration request')

# -----------------------------------------------------------------------------
# Unpacking the russian doll (= the metadata_statements)
# -----------------------------------------------------------------------------

_cms = op.unpack_metadata_statement(json_ms=rere)
res = op.evaluate_metadata_statement(_cms)

print(70 * ":")
print('Unpacked and flattened metadata statement per FO')
print(70 * ":")
for fo, ms in res.items():
    print("*** {} ***".format(fo))
    print_lines(json.dumps(ms, sort_keys=True, indent=2,
                           separators=(',', ': ')))
