.. _testing:

Testing
#######

Using Pytest
------------

Please make sure you have already reviewed :ref:`install`.

PyOIDC uses Pytest_ for testing. You can install it via Pip_:

.. _Pytest: https://doc.pytest.org/
.. _Pip: pip.pypa.io/en/stable/installing/

::

  $ pip install -U pytest

Then, you'll need to install the test dependencies with:

::

  $ pip install -U -r tests/test_requirements.txt

Now, you can run the tests by simply invoking ``py.test``:

::

  $ py.test

Using Tox
---------

PyOIDC also uses Tox_ for testing. This is to ensure PyOIDC is supported across
many versions of Python. You can install it via Pip_:

.. _Tox: https://tox.readthedocs.io/
.. _Pip: pip.pypa.io/en/stable/installing/

::

  $ pip install -U tox

Then, check the available environments with:

::

  $ tox -l

Then run Tox on your chosen environment:

::

  $ tox -e py35
