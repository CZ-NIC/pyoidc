Setup and run simple OP.
========================

Setup:
******
The folder [your path]/pysaml2/oidc_example/op1 contains a file named oc_config.py.example

Take the file named **oc_config.py.example** and rename it **oc_config.py**

Run OP:
********
In order to make th OP work you need to start the claims_provider. If you are running a unix based environment you can use the start.sh script which is located in [your path]/pysaml2/oidc_example/op1.

It's also possible to that the two python application separately:

**Start Claims_provider:**

Open a Terminal::

    cd [your path]/pyoidc/oidc_example/op1
    python claims_provider.py -p 8093 -d cp_config.json


**Start OP:**

Open a Terminal::

    cd [your path]/pyoidc/oidc_example/op1
    python oc_server.py -p 8092 -d oc_config

Note that you should not have the .py extension on the oc_config.py while running the program