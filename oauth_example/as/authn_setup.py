from oic.utils.authn.authn_context import AuthnBroker

__author__ = "roland"


def ldap_validation(config):
    from oic.utils.authn.ldap_member import UserLDAPMemberValidation

    config["args"].update(config["conf"])
    return UserLDAPMemberValidation(**config["args"])


VALIDATOR = {"LDAP": ldap_validation}


def cas_setup(item):
    from oic.utils.authn.user_cas import CasAuthnMethod

    try:
        v_cnf = item["validator"]
    except KeyError:
        _func = None
    else:
        _func = VALIDATOR[v_cnf["type"].upper()](item)

    _cnf = item["config"]
    return CasAuthnMethod(
        None, _cnf["cas_server"], item["URL"], _cnf["return_to"], _func
    )


def userpwd_setup(item):
    from oic.utils.authn.user import UsernamePasswordMako

    _conf = item["config"]
    return UsernamePasswordMako(
        None, "login.mako", _conf["lookup"], _conf["passwd"], _conf["return_to"]
    )


AUTH_METHOD = {
    "UserPassword": userpwd_setup,
    "CAS": cas_setup,
}


def authn_setup(config):
    broker = AuthnBroker()

    # Which methods to use is defined in the configuration file
    for authkey, method_conf in config.AUTHN_METHOD.items():
        try:
            func = AUTH_METHOD[authkey]
        except KeyError:
            pass
        else:
            broker.add(
                method_conf["ACR"],
                func(method_conf),
                method_conf["WEIGHT"],
                method_conf["URL"],
            )

    return broker
