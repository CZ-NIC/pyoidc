# -*- coding: utf-8 -*-
__author__ = 'rohe0002'

from oic.oic.server import UserInfo
from oic.oic import Claims

DB = {
    "user1": {
        "user_id": "user1",
        "name": "John Doe",
        "given_name": "John",
        "family_name": "Doe",
        #"middle_name":
        "nickname": "jodo",
        #"profile":
        "picture": "http://example.com/person/user1.jpg",
        "website": "http://example.com/person/user1",
        "email": "user1@example.com",
        "verified": True,
        "gender": "male",
        "birthday": "01/01/0000",
        "zoneinfo": "Europe/Stockholm",
        "locale": "se_SW",
        "phone_number": "+46 (90) 7865000",
        #"address":
        "updated_time": "2011-01-03T23:58:42+0000"
    },
    "user2": {
        "user_id": "user2",
        "name": "John Doe",
        "given_name": "John",
        "family_name": "Doe",
        #"middle_name":
        "nickname": "jodo",
        #"profile":
        "picture": "http://example.com/person/user1.jpg",
        "website#se_SV": "http://example.com/person/user1",
        "email": "user1@example.com",
        "verified": True,
        "gender": "male",
        "birthday": "01/01/0000",
        "zoneinfo": "Europe/Stockholm",
        "locale": "se_SW",
        "phone_number": "+46 (90) 7865000",
        #"address":
        "updated_time": "2011-01-03T23:58:42+0000"
    }
}

RULES = {
    "a1b2c3": ["name", "given_name", "family_name", "email", "verified"]
}

def _eq(l1, l2):
    return set(l1) == set(l2)

class TestUserInfo():
    def setup_class(self):
        self.ui = UserInfo(RULES, DB)

    def test_1(self):
        _info = self.ui.pick("user1", "client")

        print _info.keys()
        assert _eq(_info.keys(),['website', 'picture', 'locale', 'birthday',
               'verified', 'nickname', 'family_name', 'user_id', 'name',
               'gender', 'zoneinfo', 'updated_time', 'given_name',
               'phone_number', 'email'])

    def test_2(self):
        claims = Claims(name=None, nickname={"optional": True},
                        email=None, verified=None,
                        picture={"optional": True})

        _info = self.ui.pick("user1", "client", claims)

        print _info.keys()
        assert _eq(_info.keys(),
                    ['picture', 'verified', 'nickname', 'name', 'email'])

    def test_3(self):
        claims = Claims(name=None, nickname={"optional": True},
                        email=None, verified=None,
                        picture={"optional": True})

        _info = self.ui.pick("user1", "a1b2c3", claims)

        print _info.keys()
        assert _eq(_info.keys(), ['verified', 'name', 'email'])