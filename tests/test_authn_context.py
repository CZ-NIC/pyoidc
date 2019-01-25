# pylint: disable=missing-docstring,no-self-use

import socket

import pytest
from mako.lookup import TemplateLookup

from oic.utils.authn.authn_context import PASSWORD
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.authn.user_cas import CasAuthnMethod

__author__ = 'rolandh'

ROOT = './'

LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        input_encoding='utf-8', output_encoding='utf-8')
PASSWD = {
    "diana": "krall",
    "babs": "howes",
    "upper": "crust",
    "rohe0002": "StevieRay",
    "haho0032": "qwerty"
}

try:
    from oic.utils.authn.ldap_member import UserLDAPMemberValidation
    SKIP_LDAP = False
except ImportError:
    SKIP_LDAP = True


class TestAuthnBroker(object):
    @pytest.mark.skipif(SKIP_LDAP, reason="LDAP support missing")
    def test(self):
        ac = AuthnBroker()
        issuer = "https://example.com/op"
        CAS_SERVER = ""
        SERVICE_URL = ""

        LDAP = {
            "uri": "ldaps://ldap.umu.se",
            "base": "dc=umu, dc=se",
            "filter_pattern": "(uid=%s)",
            "user": "",
            "passwd": "",
            "attr": ["eduPersonScopedAffiliation", "eduPersonAffiliation"],
        }

        LDAP_EXTRAVALIDATION = {
            "verify_attr": "eduPersonAffiliation",
            "verify_attr_valid": ['employee', 'staff', 'student']
        }
        LDAP_EXTRAVALIDATION.update(LDAP)

        ac.add(PASSWORD,
               UsernamePasswordMako(None, "login.mako", LOOKUP, PASSWD,
                                    "%s/authorization" % issuer),
               10, "http://%s" % socket.gethostname())

        try:
            ac.add(PASSWORD,
                   CasAuthnMethod(
                       None, CAS_SERVER, SERVICE_URL,
                       "%s/authorization" % issuer,
                       UserLDAPMemberValidation(**LDAP_EXTRAVALIDATION)),
                   20, "http://%s" % socket.gethostname())
        except Exception:
            assert len(ac) == 1
        else:
            assert len(ac) == 2

            res = ac.pick(PASSWORD)

            assert res
            # list of two 2-tuples
            assert len(res) == 2
            assert res[0][0].__class__.__name__ == "CasAuthnMethod"
            assert res[1][0].__class__.__name__ == "UsernamePasswordMako"
