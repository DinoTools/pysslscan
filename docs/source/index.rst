Welcome to pySSLScan's documentation!
=====================================

Features
--------

* Query SSL services
* Supported cryptographic protocols:

  * SSLv2, SSLv3, TLS 1.0, TLS 1.1 and TLS 1.2
  * DTLS 1.0 and DTLS 1.2

* Supported Protocols:

  * TCP, HTTP, IMAP, POP3, SMTP, LDAP and RDP
  * UDP

* IPv4 and IPv6
* Scan modules:

  * Supported ciphers
  * Ciphers preferred
  * Supported compression methods
  * Supported elliptic curves
  * Test support for Signaling Cipher Suite Value (SCSV)
  * Extract EC Point Formats
  * Server certificate (requires pyOpenSSL)
  * Test renegotiation (requires pyOpenSSL)
  * Detect vulnerabilities

    * Heartbleed

  * Extract server information: HTTP, IMAP, POP3 and SMTP

* Rule based result highlighting
* Output formats:

  * text/terminal


Installation
------------

You can install ``pySSLScan`` with ``pip``:

.. code-block:: console

    $ pip install sslscan

See :doc:`Introduction <introduction>` for more information.

Contents:

.. toctree::
   :maxdepth: 2

   introduction
   usage
   api
   changelog

Development:

.. toctree::
    :maxdepth: 2

    development/rating


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

