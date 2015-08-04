from oic.utils.http_util import CookieDealer

__author__ = 'roland'


class DummyServer():
    def __init__(self):
        self.symkey = "0123456789012345"


def test_cookie_dealer_1():
    cd = CookieDealer(DummyServer())
    kaka = cd.create_cookie("Something to pass along", "sso", "Foobar")
    #print kaka
    value, _ts, typ = cd.get_cookie_value(kaka[1], "Foobar")
    assert value == "Something to pass along"
    assert typ == "sso"

if __name__ == "__main__":
    test_cookie_dealer_1()
