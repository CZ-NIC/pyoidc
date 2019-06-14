# pylint: disable=redefined-outer-name, missing-docstring

import json
import tempfile

import pytest

from oic.utils.client_management import CDB


@pytest.fixture
def cdb():
    file = tempfile.NamedTemporaryFile()  # just get a unique filename
    file.close()
    return CDB(file.name)


class TestCDB(object):
    def test_create(self, cdb):
        info = self._create_new(cdb)
        assert info == cdb[info["client_id"]]

    def test_dump(self, cdb):
        info = self._create_new(cdb)

        file = tempfile.NamedTemporaryFile(delete=False)
        file.close()
        cdb.dump(file.name)

        with open(file.name) as f:
            from_file = json.load(f)
        assert from_file[0] == info  # serialized to file properly

        client_id = info["client_id"]
        del cdb[client_id]

        with pytest.raises(KeyError):
            cdb[client_id]  # make sure the client is removed
        cdb.load(file.name)
        assert cdb[client_id] == info  # ensure the all info was restored

    def _create_new(self, client_db):
        info = client_db.create(
            ["https://example.com/redirect"],
            "https://example.com/policy",
            "https://example.com/logo",
            "https://example.com/jwks",
        )

        return info
