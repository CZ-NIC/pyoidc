Run Example with Docker
=======================

So, you just want to see how it works?

In order to get started, you'll need to install Docker_. Once installed, please
run the `runOpRp.sh`_ script in the root of the repository.

.. _Docker: https://docs.docker.com/get-docker/
.. _runOpRp.sh: https://github.com/CZ-NIC/pyoidc/blob/master/runOpRp.sh

This will set up the following:

  * An OP listening at port ``localhost:8088``.
  * An RP listening at port ``localhost:8666``.

You can check this is the case by running:

::

  $ docker ps -a

Go ahead and visit the RP at ``localhost:8666``. You can now login with the
following UID:

  * ``username@localhost:8093``

You will then be re-directed to the OP, where you will be asked to enter your
username and password. Please use the following:

  * ``username: diana``
  * ``password: krall``
