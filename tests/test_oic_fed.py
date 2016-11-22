import os

from jwkest.jws import JWSException, NoSuitableSigningKeys

from oic.utils.keyio import build_keyjar

from oic.extension.oidc_fed import ClientMetadataStatement
from oic.extension.oidc_fed import evaluate_metadata_statement
from oic.extension.oidc_fed import is_lesser
from oic.extension.oidc_fed import pack_metadata_statement
from oic.extension.oidc_fed import unfurl
from oic.extension.oidc_fed import unpack_metadata_statement

from oic.extension.oidc_fed import MetadataStatement

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

KEYS = {}
ISSUER = {}

for entity in ['fo', 'fo1', 'org', 'inter', 'admin']:
    fname = os.path.join(BASE_PATH, "{}.key".format(entity))
    _keydef = KEYDEFS[:]
    _keydef[0]['key'] = fname

    _jwks, _keyjar, _kidd = build_keyjar(_keydef)
    KEYS[entity] = {'jwks': _jwks, 'keyjar': _keyjar, 'kidd': _kidd}
    ISSUER[entity] = 'https:{}.example.org'.format(entity)


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
    cms = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    _jwt = pack_metadata_statement(cms, KEYS['fo']['keyjar'], ISSUER['fo'],
                                   'RS256',
                                   scope=['openid'])

    assert _jwt
    json_ms = unfurl(_jwt)
    #  print(json_ms.keys())
    assert json_ms.keys() == {'signing_keys': 0, 'iss': 0, 'iat': 0, 'exp': 0,
                              'kid': 0, 'scope': 0, 'contacts': 0,
                              'jti': 0}.keys()

    _cms = unpack_metadata_statement(jwt_ms=_jwt, keyjar=KEYS['fo']['keyjar'])

    assert _cms


def test_pack_ms_wrong_fo():
    cms = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    _jwt = pack_metadata_statement(cms, KEYS['fo']['keyjar'], ISSUER['fo'],
                                   'RS256',
                                   scope=['openid'])

    try:
        _ = unpack_metadata_statement(jwt_ms=_jwt, keyjar=KEYS['fo1']['keyjar'])
    except JWSException as err:
        assert isinstance(err, NoSuitableSigningKeys)
    else:
        assert False


def test_pack_and_unpack_ms_lev1():
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org = pack_metadata_statement(cms_org, KEYS['fo']['keyjar'],
                                     ISSUER['fo'], 'RS256',
                                     scope=['openid'])

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb']
    )

    ms_rp = pack_metadata_statement(cms_rp, KEYS['org']['keyjar'],
                                    iss=ISSUER['org'], alg='RS256',
                                    metadata_statements=[ms_org])

    _cms = unpack_metadata_statement(jwt_ms=ms_rp, keyjar=KEYS['fo']['keyjar'])

    assert _cms


def test_pack_and_unpack_ms_lev2():
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org = pack_metadata_statement(cms_org, KEYS['fo']['keyjar'],
                                     ISSUER['fo'], 'RS256',
                                     scope=['openid'])

    cms_inter = ClientMetadataStatement(
        signing_keys=KEYS['inter']['jwks'],
        tos_uri=['https://inter.example.com/tos.html']
    )

    #  signed by org
    ms_inter = pack_metadata_statement(cms_inter, KEYS['org']['keyjar'],
                                       iss=ISSUER['org'], alg='RS256',
                                       metadata_statements=[ms_org])

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb']
    )

    #  signed by intermediate
    ms_rp = pack_metadata_statement(cms_rp, KEYS['inter']['keyjar'],
                                    iss=ISSUER['inter'], alg='RS256',
                                    metadata_statements=[ms_inter])

    _cms = unpack_metadata_statement(jwt_ms=ms_rp, keyjar=KEYS['fo']['keyjar'])

    assert _cms


def test_multiple_fo():
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org1 = pack_metadata_statement(cms_org, KEYS['fo']['keyjar'],
                                      ISSUER['fo'], 'RS256',
                                      scope=['openid'])

    #  signed by FO1
    ms_org2 = pack_metadata_statement(cms_org, KEYS['fo1']['keyjar'],
                                      ISSUER['fo1'], 'RS256',
                                      scope=['openid'])

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb']
    )

    ms_rp = pack_metadata_statement(cms_rp, KEYS['org']['keyjar'],
                                    iss=ISSUER['org'], alg='RS256',
                                    metadata_statements=[ms_org1, ms_org2])

    # only knows about one FO
    _cms = unpack_metadata_statement(jwt_ms=ms_rp, keyjar=KEYS['fo']['keyjar'])

    assert _cms


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
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org = pack_metadata_statement(cms_org, KEYS['fo']['keyjar'],
                                     ISSUER['fo'], 'RS256',
                                     scope=['openid'])

    cms_inter = ClientMetadataStatement(
        signing_keys=KEYS['inter']['jwks'],
        tos_uri=['https://inter.example.com/tos.html']
    )

    #  signed by org
    ms_inter = pack_metadata_statement(cms_inter, KEYS['org']['keyjar'],
                                       iss=ISSUER['org'], alg='RS256',
                                       metadata_statements=[ms_org])

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb']
    )

    #  signed by intermediate
    ms_rp = pack_metadata_statement(cms_rp, KEYS['inter']['keyjar'],
                                    iss=ISSUER['inter'], alg='RS256',
                                    metadata_statements=[ms_inter])

    _cms = unpack_metadata_statement(jwt_ms=ms_rp, keyjar=KEYS['fo']['keyjar'])

    res = evaluate_metadata_statement(_cms)
    assert list(res.keys()) == [ISSUER['fo']]
    assert sorted(list(res[ISSUER['fo']].keys())) == sorted(
        ['contacts', 'tos_uri', 'redirect_uris', 'scope'])


def test_evaluate_metadata_statement_2():
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org = pack_metadata_statement(cms_org, KEYS['fo']['keyjar'],
                                     ISSUER['fo'], 'RS256',
                                     scope=['openid', 'email', 'address'])

    cms_inter = ClientMetadataStatement(
        signing_keys=KEYS['inter']['jwks'],
        tos_uri=['https://inter.example.com/tos.html']
    )

    #  signed by org
    ms_inter = pack_metadata_statement(cms_inter, KEYS['org']['keyjar'],
                                       iss=ISSUER['org'], alg='RS256',
                                       metadata_statements=[ms_org])

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb'],
        scope=['openid', 'email']
    )

    #  signed by intermediate
    ms_rp = pack_metadata_statement(cms_rp, KEYS['inter']['keyjar'],
                                    iss=ISSUER['inter'], alg='RS256',
                                    metadata_statements=[ms_inter])

    _cms = unpack_metadata_statement(jwt_ms=ms_rp, keyjar=KEYS['fo']['keyjar'])

    res = evaluate_metadata_statement(_cms)
    assert list(res.keys()) == [ISSUER['fo']]
    assert sorted(list(res[ISSUER['fo']].keys())) == sorted(
        ['contacts', 'tos_uri', 'redirect_uris', 'scope'])

    assert res[ISSUER['fo']]['scope'] == ['openid', 'email', 'address']
