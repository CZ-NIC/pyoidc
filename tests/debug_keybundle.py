from oic.utils.keyio import KeyBundle, rsa_load

__author__ = 'rolandh'

_key = rsa_load("../oc3/certs/mycert.key")

KC_RSA = KeyBundle([{"key":_key, "kty":"rsa", "use":"ver"},
                    {"key":_key, "kty":"rsa", "use":"sig"}])
