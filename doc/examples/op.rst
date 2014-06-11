Setup and run simple OP.
========================

Setup OP2:
***********
The folder [your path]/pyoidc/oidc_example/op2 contains a file named oc_config.py.example

#. Take the file named **oc_config.py.example** and copy it to a new file named **oc_config.py**

#. Edit the file **oc_config.py** and update the baseurl to the IP address of you local machine

Run OP2:
********

Open a Terminal::

    cd [your path]/pyoidc/oidc_example/op2
    python server.py -p 8092 -d config

Note that you should not have the .py extension on the config.py while running the program