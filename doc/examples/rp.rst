Setup and run simple RP.
========================

Setup:
******
The folder [your path]/pysaml2/oidc_example/rp2 contains a file named conf.py.example

Take the file named **conf.py.example** and rename it **conf.py**

Run RP:
********
Open a Terminal::

    cd [your path]/pyoidc/oidc_example/op1
    python rp_server.py conf

Note that you should not have the .py extension on the conf.py while running the program


Test the RP and OP:
*******************

Open a browser and go to localhost:8666 (the url and port specified in [your path]/pyoidc/oidc_example/rp2/conf.py)

As a UID enter username@localhost:8666

Now you should be redirected to the OP and asked to login.

Username:
diana
Password:
krall

It's possible to use any login details specified in the dictionary named PASSWD which is located in oc_server.py