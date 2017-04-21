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
    assert claims_match("foo", "foo")
    assert claims_match("foo", None)
    assert claims_match("foo", {"a": "foo"})
    assert claims_match("foo", ("foo", "bar"))
