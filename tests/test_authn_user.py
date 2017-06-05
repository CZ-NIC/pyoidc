
import pytest

from oic.exception import ImproperlyConfigured
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
