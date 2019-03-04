OP2 Example
===========

Getting Started
---------------

    git clone https://github.com/OpenIDC/pyoidc.git
    cd pyoidc/oidc_example/op2/
    python3 -m venv venv && . venv/bin/activate
    pip install -r requirements.txt -c constraints.txt


### Client Management

To be able to start up the project you have to create a client in the `client_db` file.
This is done by the CLI application `client_management.py`.
The allowed redirect_uris must be provided, then a client_id and client_secret is generated. See some samples below.

Add new client by starting client_management tool with -c and answer the upcoming questions:

    python ../../src/oic/utils/client_management.py -c client_db

List clients in your new `client_db` file:

    python ../../src/oic/utils/client_management.py -l client_db

Show values for a specific client:

    ../../src/oic/utils/client_management.py -s -i <client id> client_db

Should yield something like...

    {
        'client_secret': 'e4d70473ac2db4adbf9fb765ec56d34076720fa52e8edebdbbc368c2',
        'redirect_uris': [['https://myserver.com/callback', None], ['https://eny5ndkgibofe.x.pipedream.net/', None]],
        'client_salt': 'vULdf5Q8',
        'client_id': '9D8nyeoaIfE8'
    }

To show all command-line options:

    ../../src/oic/utils/client_management.py -h client_db


### Running the Server

    ./server.py -p 8040 config_simple.py

To explore options for running the server, invoke it with `--help` to get an overview.
Then dig in and read through the source! :)


### Good to Know

If the `max_age` is not set in the authorization request the `max_age` will be 0 and the authorization cookie will never expire.
