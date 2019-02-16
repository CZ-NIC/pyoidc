import os

BASEDIR = os.path.abspath(os.path.dirname(__file__))

SERVER_CERT = "certs/cert.pem"
SERVER_KEY = "certs/key.pem"
CA_BUNDLE = None

VERIFY_SSL = False

PORT_MIN = 60001
PORT_MAX = 61000

BASE_URL = 'https://op-test'

# The variables below are all passed on to the test tool instance
ENT_PATH = 'entities'
ENT_INFO = 'entity_info'

FLOWDIR = 'flows'

PATH2PORT = 'path2port.csv'
TEST_SCRIPT = './op_test_tool.py'
