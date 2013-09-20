import socket
from mako.lookup import TemplateLookup
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.authn.authn_context import AuthnBroker, PASSWORD
from oic.utils.authn.user_cas import CasAuthnMethod
from oic.utils.authn.ldap_member import UserLDAPMemberValidation

__author__ = 'rolandh'

ROOT = './'

LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')
PASSWD = {"diana": "krall",
          "babs": "howes",
          "upper": "crust",
          "rohe0002": "StevieRay",
          "haho0032": "qwerty"
}


def test():
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
        "verifyAttr": "eduPersonAffiliation",
        "verifyAttrValid": ['employee', 'staff', 'student']
    }
    LDAP_EXTRAVALIDATION.update(LDAP)

    ac.add(PASSWORD,
           UsernamePasswordMako(None, "login.mako", LOOKUP, PASSWD,
                                "%s/authorization" % issuer),
           10, "http://%s" % socket.gethostname())

    ac.add(PASSWORD,
           CasAuthnMethod(
               None, CAS_SERVER, SERVICE_URL,
               "%s/authorization" % issuer,
               UserLDAPMemberValidation(**LDAP_EXTRAVALIDATION)),
           20, "http://%s" % socket.gethostname())

    assert len(ac) == 2

    res = ac.pick(PASSWORD)

    assert res
    assert len(res) == 3
    assert res[0].__class__.__name__ == "CasAuthnMethod"
    assert res[1].__class__.__name__ == "UsernamePasswordMako"


if __name__ == "__main__":
    test()
