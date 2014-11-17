Changelog
=========

0.5 - `master`_
~~~~~~~~~~~~~~~

.. note:: This version is not yet released and is under active development.

0.4 - 2014-11-17
~~~~~~~~~~~~~~~~

* Use flextls module for scans
  * Most scans have been rewritten to be more flexible
  * Support additional ciphers
  * Minimize OpenSSL dependencies
* New server.compression scan to explicitly scan for supported compression methods
* Minimize number of requests during cipher scans
* Improve detection of preferred ciphers
* Don't perform a full handshake during cipher scans
* Fixes (Thanks to Till Maas)

0.3.1 - 2014-10-20
~~~~~~~~~~~~~~~~~~

* Fix error if cert chain not in kb
* Prevent the vuln_heartbleed scan from attempting to call len on payload when it is None. (Thanks to David Black)

0.3 - 2014-09-28
~~~~~~~~~~~~~~~~

* Set certificate chain in knowledge base
* Support numbers in handler names
* Fix error if port attribute not set
* Add support for POP3 + STARTTLS
* Add support for IMAP + STARTTLS
* Improve SMTP support
* Add support for additional rating rules
* Add delay option for TCP connections

0.2 - 2014-07-28
~~~~~~~~~~~~~~~~

* Add: API documentation and docstrings
* Add: Support for Python 2.x
* Add: Logging
* Change: Improve command-line UI

0.1 - 2014-05-11
~~~~~~~~~~~~~~~~

Proof of concept

* Initial release.

.. _`master`: https://github.com/DinoTools/pysslscan
