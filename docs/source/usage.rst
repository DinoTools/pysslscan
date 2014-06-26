How to use
==========

The pySSLScan framework provides an API to write tests for SSL enabled
services. But it also includes a command-line interface to get you
started in a few steps.

Command-line
------------

Use the ``--help`` parameter to display the main help. This will give
a short overview about all global options available and list all
subcommands.

.. code-block:: console

    $ pysslscan --help

Subcommands are very helpful and extend the command-line interface. To get
help for a subcommand just specify the command and append the ``--help``
option. The result of the following example command will be the help for
the ``scan`` command.

.. code-block:: console

    $ pysslscan scan --help


Performe a basic scan
~~~~~~~~~~~~~~~~~~~~~

First of all get a list of all available scan modules.

.. code-block:: console

    $ pysslscan scan.list
    client.ciphers - List all client ciphers.
    server.preferred_ciphers - Detect preferred server ciphers.
    server.certificate - Extract certificate information.
    ...

After that determine what reporting modules are available.

.. code-block:: console

    $ pysslscan report.list
    term - Print results to the terminal.
    ...

Choose some of the modules and perform a target scan. In the example
below two scan modules are used. The first one is ``server.ciphers``
to detect all supported ciphers available on the server and the second one is
``vuln.heartbleed`` to run test to detect if the server is vulnerable
by the heartbleed bug. To display the scan results on the command-line
the reporting module ``term`` is used. The ``--tls10`` option enables
all TLSv1.0 ciphers.

.. code-block:: console

    $ pysslscan scan --scan=server.ciphers --scan=vuln.heartbleed --report=term --tls10 127.0.0.1


Highlight the result
~~~~~~~~~~~~~~~~~~~~

pySSLScan provides also some rating modules to highlight important facts in
the result.

First of all have a look at the list of available rating modules.

.. code-block:: console

    $ pysslscan rating.list
    ssllabs.2009c - Rating used by SSL Labs 2009c
    ssllabs.2009d - Rating used by SSL Labs 2009d
    ...

Perform the scan from an earlier example but specify a rating module.

.. code-block:: console

    $ pysslscan scan --scan=server.ciphers --scan=vuln.heartbleed --report=term:rating=ssllabs.2009e --tls10 127.0.0.1


Use a protocol handler
~~~~~~~~~~~~~~~~~~~~~~

pySSLScan has support for different protocols which are handled by a special
handler module. By default pySSLScan will perform a basic TCP connect to scan
a target but it supports also protocols like HTTP or SMTP.

The example below will print a list of all available handler modules.

.. code-block:: console

    $ sslscan.py handler.list
    tcp - Handle raw TCP-connections.
    smtp - Handle SMTP-connections.
    http - Handle HTTP-connections.
    ...

To use a handler module it has to be specified as shown in the next example.

.. code-block:: console

    $ pysslscan scan --scan=server.ciphers --report=term:rating=rbsec --tls10 'smtp://127.0.0.1:25?starttls=true'


Python API
----------

ToDo
