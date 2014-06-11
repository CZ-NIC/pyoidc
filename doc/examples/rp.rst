Setup and run simple RP.
========================

Setup RP2:
**********
The folder [your path]/pysaml2/oidc_example/rp2 contains a file named conf.py.example

#. Take the file named **conf.py.example** and rename it **conf.py**
#. Edit the conf.py
    #. The most important attributes are BASE and PORT

Run RP2:
********
Open a Terminal::

    cd [your path]/pyoidc/oidc_example/rp2
    python rp_server.py conf

Note that you should not have the .py extension on the conf.py while running the program


Setup RP3:
**********
The folder [your path]/pysaml2/oidc_example/rp3 contains a file named conf.py.example

#. Take the file named **conf.py.example** and rename it **conf.py**
#. Edit the conf.py
    #. The most important attributes are BASE and PORT

Note: In the RP configuration file there is a dictionary named CLIENTS which in this quick example only should have one element:
"": {
     "client_info": ME,
     "behaviour": BEHAVIOUR
}
All the other elements should be removed, `read more here <https://github.com/rohe/pyoidc/blob/master/oidc_example/rp3/README>`_

Run RP3:
********
Open a Terminal::

    cd [your path]/pyoidc/oidc_example/rp3
    python rp.py conf

Note that you should not have the .py extension on the conf.py while running the program



Test the RP and OP:
*******************

Open a browser and go to localhost:8666 (the url and port specified in [your path]/pyoidc/oidc_example/rp2/conf.py)

As a UID enter username@localhost:8093

Now you should be redirected to the OP and asked to login.

Username:
diana
Password:
krall

It's possible to use any login details specified in the dictionary named PASSWD which is located in oc_server.py