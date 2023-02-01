import pytest

from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from oic.utils.token_handler import NotAllowed
from oic.utils.token_handler import TokenHandler


def _eq(l1, l2):
    return set(l1) == set(l2)


__author__ = "roland"

JWKS = {
    "keys": [
        {
            "d": "vT9bnSZ63uIdaVsmZjrbmcvrDZG-_qzVQ1KmrSSC398sLJiyaQKRPkmBRvV"
            "-MGxW1MVPeCkhnSULCRgtqHq"
            "-zQxMeCviSScHTKOuDYJfwMB5qdOE3FkuqPMsEVf6EXYaSd90"
            "-O6GOA88LBCPNR4iKxsrQ6LNkawwiJoPw7muK3TbQk9HzuznF8WDkt72CQFxd4eT"
            "6wJ97xpaIgxZce0oRmFcLYkQ4A0pgVhF42zxJjJDIBj_ZrSl5_qZIgiE76PV4hjH"
            "t9Nv4ZveabObnNbyz9YOiWHiOLdYZGmixHuauM98NK8udMxI6IuOkRypFhJzaQZF"
            "wMroa7ZNZF-mm78VYQ",
            "dp": "wLqivLfMc0FBhGFFRTb6WWzDpVZukcgOEQGb8wW3knmNEpgch699WQ4ZY_ws1xSbv"
            "QZtbx7MaIBXpn3qT1LYZosoP5oHVTAvdg6G8I7zgWyqj-nG4evciuoeAa1Ff52h4-"
            "J1moZ6FF2GelLdjXHoCbjIBjz_VljelSqOk5Sh5HU",
            "dq": "KXIUYNfDxwxv3A_w1t9Ohm92gOs-UJdI3_IVpe4FauCDrJ4mqgsnTisA15KY"
            "-9fCEvKfqG571WK6EKpBcxaRrqSU0ekpBvgJx8o3MGlqXWj-Lw0co8N9_"
            "-fo1rYx_8g-wCRrm5zeA5pYJdwdhOBnmKOqw_GsXJEcYeUod1xkcfU",
            "e": "AQAB",
            "ext": "true",
            "key_ops": "sign",
            "kty": "RSA",
            "n": "wl0DPln-EFLqr_Ftn6A87wEQAUVbpZsUTN2OCEsJV0nhlvmX3GUzyZx5UXdlM3Dz68PfUWCgfx67Il6sURqWVCnjnU-"
            "_gr3GeDyzedj-lZejnBx-lEy_3j6B98SbcDfkJF6saXnPd7_kgilJT1_g-EVI9ifFB1cxZXHCd2WBeRABSCprAlCglF-YmnU"
            "eeDs5K32z2ckVjadF9BG27CO5UfNq0K8jI9Yj_coOhM9dRNrQ9UVZNdQVG-bAIDhB2y2o3ASGwqchHouIxv5YZNGS0SMJL5t"
            "0edh483q1tSWPqBw-ZeryLztOedBBzSuJk7QDmL1B6B7KKUIrlUYJmVsYzw",
            "p": "6MEg5Di_IFiPGKvMFRjyx2t7YAOQ4KfdIkU_Khny1t1eCG5O07omPe_jLU8I5fPaD5F5HhWExLNureHD4K6LB18JPE3"
            "VE8chQROiRSNPZo1-faUvHu-Dy0pr7I-TS8pl_P3vop1KelIbGwXhzPIRKQMqCEKi3tLJt4R_MQ18Dx0",
            "q": "1cZVPpUbf4p5n4cMv_kERCPh3cieMs4aVojgh3feAiJiLwWWL9Pc43oJUekK44aWMnbs68Y4kqXtc52PMtBDzVp0Gjt"
            "0lCY3M7MYRVI4JhtknqvQynMKQ2nKs3VldvVfY2SxyUmnRyEolQUGRA7rRMUyPb4AXhSR7oroRrJD59s",
            "qi": "50PhyaqbLSczhipWiYy149sLsGlx9cX0tnGMswy1JLam7nBvH4"
            "-MWB2oGwD2hmG-YN66q-xXBS9CVDLZZrj1sonRTQPtWE"
            "-zuZqds6_NVlk2Ge4_IAA3TZ9tvIfM5FZVTOQsExu3_LX8FGCspWC1R"
            "-zDqT45Y9bpaCwxekluO7Q",
            "kid": "sign1",
        },
        {
            "k": b"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
            "kty": "oct",
            "use": "sig",
        },
    ]
}

kb = KeyBundle(JWKS["keys"])
KEYJAR = KeyJar()
KEYJAR.issuer_keys[""] = [kb]


class TestTokenHandler(object):
    @pytest.fixture(autouse=True)
    def create_handler(self):
        self.th = TokenHandler(
            "https://example.com/as",
            {
                "access_token": {
                    "https://example.org/rp": {"client_credentials": 1200}
                },
                "refresh_token": {
                    "https://example.org/rp": {"client_credentials": 86400}
                },
            },
            keyjar=KEYJAR,
        )

    def test_construct_access_token(self):
        token = self.th.get_access_token(
            "https://example.org/rp", "foo bar", "client_credentials"
        )

        assert token

        info = self.th.token_factory.get_info(token)

        assert _eq(
            list(info.keys()),
            ["jti", "scope", "exp", "iss", "aud", "iat", "kid", "azp"],
        )

    def test_construct_access_token_fail(self):
        # Unknown client
        try:
            self.th.get_access_token(
                "https://example.com/rp", "foo bar", "client_credentials"
            )
        except NotAllowed:
            pass
        # wrong grant_type
        try:
            self.th.get_access_token("https://example.org/rp", "foo bar", "implicit")
        except NotAllowed:
            pass

    def test_from_access_to_refresh_token(self):
        token = self.th.get_access_token(
            "https://example.org/rp", "foo bar", "client_credentials"
        )

        refresh_token = self.th.refresh_access_token(
            "https://example.org/rp", token, "client_credentials"
        )

        assert refresh_token

    def test_construct_refresh_token(self):
        sid = "1234"
        rtoken = self.th.get_refresh_token(
            "https://example.org/rp", grant_type="client_credentials", sid=sid
        )

        info = self.th.token_factory.get_info(rtoken)

        assert _eq(list(info.keys()), ["jti", "exp", "iss", "aud", "iat", "kid", "azp"])

        assert self.th.refresh_token_factory.db[info["jti"]] == sid
