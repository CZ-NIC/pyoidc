# -*- coding: utf-8 -*-
import base64

import pytest
from future.backports.urllib.parse import quote_plus

from oic.exception import ImproperlyConfigured
from oic.utils.authn.user import BasicAuthn
from oic.utils.authn.user import SymKeyAuthn


def test_symkeyauthn_improperly_configured(provider):
    improper_symkey = ""
    with pytest.raises(ImproperlyConfigured) as err:
        SymKeyAuthn(
            srv=provider,
            ttl=666,
            symkey=improper_symkey
        )
    expected_msg = "SymKeyAuthn.symkey cannot be an empty value"
    assert expected_msg in str(err.value)


def test_basic_authn_authenticate_as():
    pwd_database = {
        'Diana': 'Piano player',
        'NonAscii': '€&+%#@äää'
    }
    ba = BasicAuthn(None, pwd=pwd_database)

    for user, passwd in pwd_database.items():
        credentials = "{}:{}".format(quote_plus(user),
                                     quote_plus(passwd))

        authz = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        authorization_string = "Basic {}".format(authz)

        uid, when = ba.authenticated_as(authorization=authorization_string)
        assert uid == {'uid': user}
