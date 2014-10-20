Changelog
=========

0.4 - `master`_
~~~~~~~~~~~~~~~

.. note:: This version is not yet released and is under active development.

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
