PORT = 8666
#BASE = "http://lingon.catalogix.se:" + str(PORT) + "/"
BASE = "http://hashog.umdc.umu.se:" + str(PORT) + "/"
#BASE = "http://localhost:" + str(PORT) + "/"

# If BASE is https these has to be specified
SERVER_KEY = ''
SERVER_CERT = ''
CA_BUNDLE = None

ME = {
    "application_type": "web",
    "application_name": "idpproxy",
    "contacts": ["ops@example.com"],
}

SCOPE = ["openid", "profile", "email", "address", "phone"]
