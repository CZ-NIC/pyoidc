from oic.utils.stateless import StateLess

__author__ = "roland"


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_access_code():
    keys = {"oct": ["symmetric key123"]}  # keylength 16 bytes=128 bits
    st = StateLess(keys, enc_alg="A128KW", enc_method="A128CBC-HS256")
    con = st.create_authz_session("subject", {"redirect_uri": "https://example.com"})
    tok = st.get_token(con)

    _info = st[tok]
    assert _eq(_info.keys(), ["typ", "aud", "val", "sub"])
    assert _info["sub"] == "subject"
    assert _info["typ"] == "code"
    assert _info["aud"] == "https://example.com"


def test_update_to_access_token():
    keys = {"oct": ["symmetric key123"]}
    st = StateLess(keys, enc_alg="A128KW", enc_method="A128CBC-HS256")
    tok = st.create_authz_session("subject", {"redirect_uri": "https://example.com"})
    assert tok["aud"] == "https://example.com"
    assert tok["sub"] == "subject"
