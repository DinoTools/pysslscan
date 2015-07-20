Introduction
============

Installation
------------

As a Python egg
~~~~~~~~~~~~~~~

You can install the most recent ``pySSLScan`` version using ``pip``

.. code-block:: console

    $ pip install sslscan

Install Terminal(Stable, since 0.6):

Install pySSLScan and all dependencies to optimize terminal usage.

.. code-block:: console

    $ pip install 'sslscan[terminal]'


From a tarball release
~~~~~~~~~~~~~~~~~~~~~~

Download the most recent tarball from github, unpack it and run the following command on the command-line.

.. code-block:: console

    $ python setup.py install

Install Terminal:

.. code-block:: console

    $ pip install -e '.[terminal]'


Install the development version
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Install git and run the following commands on the command-line.

.. code-block:: console

    $ git clone https://github.com/DinoTools/pysslscan.git
    $ cd pysslscan
    $ python setup.py install

Install Terminal:

.. code-block:: console

    $ git clone https://github.com/DinoTools/pysslscan.git
    $ cd pysslscan
    $ pip install -e '.[terminal]'