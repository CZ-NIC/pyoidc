import tempfile
from subprocess import run, STDOUT, PIPE
from sys import executable as python_executable

import pytest

import oic.utils.client_management
from oic.utils.client_management import CDB, pack_redirect_uri

CLI_PATH = oic.utils.client_management.__file__
CLI_INVOCATION = '{} {} '.format(python_executable, CLI_PATH)


@pytest.fixture
def db_file_path():
    db_file = tempfile.NamedTemporaryFile(delete=True)
    db_file.close()
    return db_file.name


class TestClientManagementRun(object):
    def test_help_prints_usage_instructions(self):
        result = run(CLI_INVOCATION + '--help', shell=True,
                     stdout=PIPE, stderr=PIPE)
        assert result.stdout.decode().startswith('usage: ')
        assert result.stderr.decode() == ''

    def test_list_option_with_empty_db_lists_nothing(self, db_file_path):
        for list_option_form in ('-l', '--list'):
            result = run(CLI_INVOCATION + list_option_form + ' ' + db_file_path,
                         shell=True, stdout=PIPE, stderr=STDOUT)
            assert result.stdout.decode() == ''

    def test_list_option_with_1_client_id_in_db(self, db_file_path):
        client_db = CDB(db_file_path)
        client_db.cdb['the_first'] = {
            'client_secret': 'hardToGuess',
            'client_id': 'the_first',
            'client_salt': 'saltedAndReady!',
            'redirect_uris': pack_redirect_uri(['file:///dev/null'])
        }
        client_db.cdb.close()

        for list_option_form in ('-l', '--list'):
            result = run(CLI_INVOCATION + list_option_form + ' ' + db_file_path,
                         shell=True, stdout=PIPE, stderr=STDOUT)
            assert result.stdout.decode().splitlines() == ['the_first']

    def test_list_option_with_2_client_ids_in_db(self, db_file_path):
        client_ids = {'the_first', 'the_2nd'}

        client_db = CDB(db_file_path)
        for client_id in client_ids:
            client_db.cdb[client_id] = {
                'client_secret': 'hardToGuess',
                'client_id': client_id,
                'client_salt': 'saltedAndReady!',
                'redirect_uris': pack_redirect_uri(['file:///dev/null',
                                                   'http://localhost:1337/'])
            }
        client_db.cdb.close()

        for list_option_form in ('-l', '--list'):
            result = run(CLI_INVOCATION + list_option_form + ' ' + db_file_path,
                         shell=True, stdout=PIPE, stderr=STDOUT)
            assert set(result.stdout.decode().splitlines()) == client_ids
