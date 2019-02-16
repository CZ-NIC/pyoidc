import os

BASEDIR = os.path.abspath(os.path.dirname(__file__))

SERVER_CERT = "certs/cert.pem"
SERVER_KEY = "certs/key.pem"
CA_BUNDLE = None

VERIFY_SSL = False

# Make sure BASE starts with https if TLS = True
BASE = 'https://op-test'

ENT_PATH = 'entities'
ENT_INFO = 'entity_info'
PRE_HTML = 'html/tt'

KEYS = [
    {"key": "keys/enc.key", "type": "RSA", "use": ["enc"]},
    {"key": "keys/sig.key", "type": "RSA", "use": ["sig"]},
    {"crv": "P-256", "type": "EC", "use": ["sig"]},
    {"crv": "P-256", "type": "EC", "use": ["enc"]}
]
