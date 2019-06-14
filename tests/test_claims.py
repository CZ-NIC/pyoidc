from oic.oic import claims_match
from oic.utils.claims import ClaimsMode


def test_claims_for_user():
    user = "foobar"
    user2mode = {user: "aggregate"}
    claims_mode = ClaimsMode(user2mode)

    assert claims_mode.aggregate(user)


def test_claims_for_missing_user():
    claims_mode = ClaimsMode({})

    assert not claims_mode.aggregate("nobody")


def test_non_aggregate_claims():
    user = "foobar"
    claims_mode = ClaimsMode({user: "distributed"})

    assert not claims_mode.aggregate(user)


def test_claims_match():
    claims_request = {
        "sub": {"value": "248289761001"},
        "auth_time": {"essential": True},
        "acr": {
            "essential": True,
            "values": ["urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"],
        },
    }

    assert claims_match("248289761001", claims_request["sub"])
    assert claims_match("123456789012", claims_request["sub"]) is False
    assert claims_match("123456789", claims_request["auth_time"])
    assert claims_match("urn:mace:incommon:iap:silver", claims_request["acr"])
    assert claims_match("urn:mace:incommon:iap:gold", claims_request["acr"]) is False
