import json
import os

from jwkest.jws import JWSException, NoSuitableSigningKeys

from oic.utils.keyio import build_keyjar, KeyJar

from oic.extension.oidc_fed import ClientMetadataStatement
from oic.extension.oidc_fed import is_lesser
from oic.extension.oidc_fed import Operator
from oic.extension.oidc_fed import unfurl

from oic.extension.oidc_fed import MetadataStatement

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

KEYS = {}
ISSUER = {}
OPERATOR = {}

for entity in ['fo', 'fo1', 'org', 'inter', 'admin', 'ligo']:
    fname = os.path.join(BASE_PATH, "{}.key".format(entity))
    _keydef = KEYDEFS[:]
    _keydef[0]['key'] = fname

    _jwks, _keyjar, _kidd = build_keyjar(_keydef)
    KEYS[entity] = {'jwks': _jwks, 'keyjar': _keyjar, 'kidd': _kidd}
    ISSUER[entity] = 'https:{}.example.org'.format(entity)
    OPERATOR[entity] = Operator(keyjar=_keyjar, iss=ISSUER[entity], jwks=_jwks)

FOP = OPERATOR['fo']
FOP.fo_keyjar = FOP.keyjar
FO1P = OPERATOR['fo1']
FO1P.fo_keyjar = FO1P.keyjar
ORGOP = OPERATOR['org']
ADMINOP = OPERATOR['admin']
INTEROP = OPERATOR['inter']
LIGOOP = OPERATOR['ligo']


def fo_member(*args):
    _kj = KeyJar()
    for fo in args:
        _kj.import_jwks(fo.jwks, '')

    return Operator(fo_keyjar=_kj)


def test_create_metadata_statement_simple():
    ms = MetadataStatement(signing_keys=KEYS['org']['jwks'])

    assert ms
    assert len(ms['signing_keys']['keys']) == 2


def test_create_client_metadata_statement():
    ms = MetadataStatement(signing_keys=KEYS['org']['jwks'])
    ms_jwt = ms.to_jwt(KEYS['fo']['keyjar'].get_signing_key('rsa'))

    cms = ClientMetadataStatement(
        metadata_statements=[ms_jwt],
        contacts=['info@example.com']
    )

    assert cms


def test_pack_and_unpack_ms_lev0():
    cms = ClientMetadataStatement(signing_keys=FOP.jwks,
                                  contacts=['info@example.com'])

    _jwt = FOP.pack_metadata_statement(cms, alg='RS256', scope=['openid'])

    assert _jwt
    json_ms = unfurl(_jwt)
    #  print(json_ms.keys())
    assert set(json_ms.keys()) == {'signing_keys', 'iss', 'iat', 'exp',
                                   'kid', 'scope', 'contacts', 'jti'}

    # Unpack what you have packed
    _cms = FOP.unpack_metadata_statement(jwt_ms=_jwt)

    assert _cms


def test_pack_ms_wrong_fo():
    cms = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    _jwt = FOP.pack_metadata_statement(cms, alg='RS256', scope=['openid'])

    try:
        member = fo_member(FO1P)
        _ = member.unpack_metadata_statement(jwt_ms=_jwt)
    except JWSException as err:
        assert isinstance(err, NoSuitableSigningKeys)
    else:
        assert False


def test_pack_and_unpack_ms_lev1():
    # metadata statement created by the organization
    cms_org = ClientMetadataStatement(
        signing_keys=ORGOP.jwks,
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org = FOP.pack_metadata_statement(cms_org, alg='RS256', scope=['openid'])

    # metadata statement created by the admin
    cms_rp = ClientMetadataStatement(
        signing_keys=ADMINOP.jwks,
        redirect_uris=['https://rp.example.com/auth_cb']
    )

    # signed by the org
    ms_rp = ORGOP.pack_metadata_statement(cms_rp, alg='RS256',
                                          metadata_statements=[ms_org])

    receiver = fo_member(FOP)
    _cms = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    assert _cms


def test_pack_and_unpack_ms_lev2():
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org = FOP.pack_metadata_statement(cms_org, alg='RS256', scope=['openid'])

    cms_inter = ClientMetadataStatement(
        signing_keys=KEYS['inter']['jwks'],
        tos_uri=['https://inter.example.com/tos.html']
    )

    #  signed by org
    ms_inter = ORGOP.pack_metadata_statement(cms_inter, alg='RS256',
                                             metadata_statements=[ms_org])

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb']
    )

    #  signed by intermediate
    ms_rp = INTEROP.pack_metadata_statement(cms_rp, alg='RS256',
                                            metadata_statements=[ms_inter])

    receiver = fo_member(FOP)
    _cms = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    assert _cms


def test_multiple_fo_one_working():
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org1 = FOP.pack_metadata_statement(cms_org, alg='RS256',
                                          scope=['openid'])

    #  signed by FO1
    ms_org2 = FO1P.pack_metadata_statement(cms_org, alg='RS256',
                                           scope=['openid', 'address'])

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb']
    )

    ms_rp = ORGOP.pack_metadata_statement(cms_rp, alg='RS256',
                                          metadata_statements=[ms_org1,
                                                               ms_org2])

    # only knows about one FO
    receiver = fo_member(FOP)
    _cms = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    assert len(_cms['metadata_statements']) == 1
    _ms = json.loads(_cms['metadata_statements'][0])
    assert _ms['iss'] == ISSUER['fo']


def test_multiple_fo_all_working():
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org1 = FOP.pack_metadata_statement(cms_org, alg='RS256',
                                          scope=['openid'])

    #  signed by FO1
    ms_org2 = FO1P.pack_metadata_statement(cms_org, alg='RS256',
                                           scope=['openid', 'address'])

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb']
    )

    ms_rp = ORGOP.pack_metadata_statement(cms_rp, alg='RS256',
                                          metadata_statements=[ms_org1,
                                                               ms_org2])

    # knows all FO's
    receiver = fo_member(FOP, FO1P)
    _cms = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    assert len(_cms['metadata_statements']) == 2
    _iss = [json.loads(x)['iss'] for x in _cms['metadata_statements']]
    assert set(_iss) == {ISSUER['fo'], ISSUER['fo1']}


def test_is_lesser_strings():
    assert is_lesser('foo', 'foo')
    assert is_lesser('foo', 'fox') is False
    assert is_lesser('foo', 'FOO') is False


def test_is_lesser_list():
    assert is_lesser(['foo'], ['foo'])
    assert is_lesser(['foo', 'fox'], ['fox', 'foo'])
    assert is_lesser(['fee', 'foo'], ['foo', 'fee', 'fum'])
    assert is_lesser(['fee', 'fum', 'foo'], ['foo', 'fee', 'fum'])

    assert is_lesser(['fee', 'foo', 'fum'], ['foo', 'fee']) is False
    assert is_lesser(['fee', 'fum'], ['fee']) is False


def test_evaluate_metadata_statement_1():
    cms_org = ClientMetadataStatement(
        signing_keys=ORGOP.jwks, contacts=['info@example.com'])

    #  signed by FO
    ms_org = FOP.pack_metadata_statement(cms_org, alg='RS256', scope=['openid'])

    cms_inter = ClientMetadataStatement(
        signing_keys=KEYS['inter']['jwks'],
        tos_uri=['https://inter.example.com/tos.html']
    )

    #  signed by org
    ms_inter = ORGOP.pack_metadata_statement(cms_inter, alg='RS256',
                                             metadata_statements=[ms_org])

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb']
    )

    #  signed by intermediate
    ms_rp = INTEROP.pack_metadata_statement(cms_rp, alg='RS256',
                                            metadata_statements=[ms_inter])

    receiver = fo_member(FOP)
    _cms = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    res = receiver.evaluate_metadata_statement(_cms)
    assert list(res.keys()) == [ISSUER['fo']]
    assert sorted(list(res[ISSUER['fo']].keys())) == sorted(
        ['contacts', 'tos_uri', 'redirect_uris', 'scope'])


def test_evaluate_metadata_statement_2():
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org = FOP.pack_metadata_statement(cms_org, alg='RS256',
                                         scope=['openid', 'email', 'address'])

    cms_inter = ClientMetadataStatement(
        signing_keys=KEYS['inter']['jwks'],
        tos_uri=['https://inter.example.com/tos.html']
    )

    #  signed by org
    ms_inter = ORGOP.pack_metadata_statement(cms_inter, alg='RS256',
                                             metadata_statements=[ms_org])

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb'],
        scope=['openid', 'email']
    )

    #  signed by intermediate
    ms_rp = INTEROP.pack_metadata_statement(cms_rp, alg='RS256',
                                            metadata_statements=[ms_inter])

    receiver = fo_member(FOP)
    _cms = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    res = receiver.evaluate_metadata_statement(_cms)
    assert list(res.keys()) == [ISSUER['fo']]
    assert sorted(list(res[ISSUER['fo']].keys())) == sorted(
        ['contacts', 'tos_uri', 'redirect_uris', 'scope'])

    assert res[ISSUER['fo']]['scope'] == ['openid', 'email', 'address']


def test_evaluate_metadata_statement_3():
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org1 = FOP.pack_metadata_statement(cms_org, alg='RS256',
                                          claims=['email', 'email_verified',
                                                  'phone', 'phone_verified'],
                                          scope=['openid', 'email', 'phone'])

    #  signed by FO1
    ms_org2 = FO1P.pack_metadata_statement(cms_org, alg='RS256',
                                           scope=['openid', 'email', 'address'])

    cms_inter = ClientMetadataStatement(
        signing_keys=KEYS['inter']['jwks'],
        tos_uri=['https://inter.example.com/tos.html']
    )

    #  signed by org
    ms_inter = ORGOP.pack_metadata_statement(cms_inter, alg='RS256',
                                             metadata_statements=[ms_org1,
                                                                  ms_org2])

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb'],
        scope=['openid', 'email']
    )

    #  signed by intermediate
    ms_rp = INTEROP.pack_metadata_statement(cms_rp, alg='RS256',
                                            metadata_statements=[ms_inter])

    # knows all FO's
    receiver = fo_member(FOP, FO1P)
    _cms = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    res = receiver.evaluate_metadata_statement(_cms)
    assert set(res.keys()) == {ISSUER['fo'], ISSUER['fo1']}
    assert sorted(list(res[ISSUER['fo']].keys())) == sorted(
        ['claims', 'contacts', 'tos_uri', 'redirect_uris', 'scope'])

    assert res[ISSUER['fo']]['scope'] == ['openid', 'email', 'phone']
    assert res[ISSUER['fo1']]['scope'] == ['openid', 'email', 'address']
    assert 'claims' in res[ISSUER['fo']]
    assert 'claims' not in res[ISSUER['fo1']]


def test_evaluate_metadata_statement_4():
    """
    One 4-level (FO, Org, Inter, admin) and one 2-level (FO1, Inter, admin)
    """
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org = FOP.pack_metadata_statement(cms_org, alg='RS256',
                                         claims=['email', 'email_verified',
                                                 'phone', 'phone_verified'],
                                         scope=['openid', 'email', 'phone'])

    cms_inter = ClientMetadataStatement(
        signing_keys=KEYS['inter']['jwks'],
        tos_uri=['https://inter.example.com/tos.html']
    )

    #  signed by org
    ms_inter0 = ORGOP.pack_metadata_statement(cms_inter, alg='RS256',
                                              metadata_statements=[ms_org])

    ms_inter1 = LIGOOP.pack_metadata_statement(cms_inter, alg='ES256')

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb'],
        scope=['openid', 'email']
    )

    #  signed by intermediate
    ms_rp = INTEROP.pack_metadata_statement(cms_rp, alg='RS256',
                                            metadata_statements=[ms_inter0,
                                                                 ms_inter1])

    # knows both FO's
    receiver = fo_member(FOP, LIGOOP)
    _cms = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    res = receiver.evaluate_metadata_statement(_cms)
    assert set(res.keys()) == {ISSUER['fo'], ISSUER['ligo']}
    assert sorted(list(res[ISSUER['fo']].keys())) == sorted(
        ['claims', 'contacts', 'redirect_uris', 'scope', 'tos_uri'])

    assert res[ISSUER['fo']]['scope'] == ['openid', 'email', 'phone']
