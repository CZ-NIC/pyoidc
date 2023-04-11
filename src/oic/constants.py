"""Constants used accros the project."""
from jwcrypto.jwe import default_allowed_algs

ALLOWED_ALGS = ['RSA1_5'] + default_allowed_algs
