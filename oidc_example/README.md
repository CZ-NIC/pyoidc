# Simple RP and OP examples

These 2 examples can run on the same machine together following these steps.

Both servers "use" up a port, and running them on the same machine means they
need their own ports.  `simple_rp` supports providing a response url with a port
in it, so that will run on a random port (8000 in the example below) and
`simple_op` runs on port 443 - the standard https port.

Run the following:

1. Install oic from source using `python setup.py install`
1. Install `requirements.txt` for `simple_op` using `pip install -r requirements.txt`
1. Install `requirements.txt` for `simple_rp` using `pip install -r requirements.txt`
1. Start the op server on port 443 in `simple_op` using `python src/run.py settings.yaml.example -p 443`
1. Start the rp server on port 8000 in `simple_rp` using `python src/rp.py settings.yaml.example -p 8000`
1. Open the rp server in a browser, <https://localhost:8000/>
1. Enter the uid `localhost` to connect to the simple op server
1. Login using the credentials in `simple_op/passwd.json` (this is referenced in the simple op example settings)
1. Observe the user info is loaded by the RP server
