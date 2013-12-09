from mako.lookup import TemplateLookup

PORT = 8666
HOST = "localhost"

BASE = "http://%s:%d/" % (HOST, PORT)

# If BASE is https these has to be specified
SERVER_KEY = ''
SERVER_CERT = ''
CA_BUNDLE = None

SCOPE = []

ROOT = "./"
LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')

AS_CONF = {
    "AuthzServer@DIG": {
        "authorization_endpoint": "https://localhost:8080/authorization",
        "token_endpoint": "https://localhost:8080/token",
        "client_id": "YWwQiwQNWaeI",
        "client_secret": "cdb8c2f40110a5fdefe7e26ea26a0bd51fb3d1b9593d6a054c75abcb"
    }
}

