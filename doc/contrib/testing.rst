.. _testing:

Testing
#######

Using Pytest
------------

Please make sure you have already reviewed the :ref:`install`.

PyOIDC uses Pytest_ for testing.

.. _Pytest: https://doc.pytest.org/

You can install it along with the rest of the test dependencies via Pip_:

.. _Pip: pip.pypa.io/en/stable/installing/

::

  $ pip install -r requirements/test.txt

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

  $ pip install -r requirements/test.txt

Then, check the available environments with:

::

  $ tox -l

Then run Tox on your chosen environment:

::

  $ tox -e py36
