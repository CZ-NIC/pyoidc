.. _documentation:

Documentation
#############

PyOIDC uses Sphinx_ for documentation. You can install
it via Pip_:

.. _Pip: https://pip.pypa.io/en/stable/installing/
.. _Sphinx: https://www.sphinx-doc.org/

::

  $ pip install -U sphinx sphinx-autobuild

There is a convenient Makefile_ for all documentation commands,
which you can review by running (in the root of the repository):

.. _Makefile: https://github.com/rohe/pyoidc/blob/master/Makefile

::

  $ make help

``make livehtml`` is particularly useful when developing locally.
