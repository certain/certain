===============================
**certain** - Command-line Tool
===============================

.. program:: certain



Synopsis
========

The command-line tool is used to control the daemon on the master, and send and receive certificate requests and signed certificates on the clients:

Syntax
======

**certain --help**

**certain --daemon**

**certain [--get] [--makecert] [--sign]**


Options
=======

.. cmdoption:: -h, --help

   Display basic help.


.. cmdoption:: -c, --config

   Configuration file to use (defaults to ``/etc/certain/certain.cfg``)

.. cmdoption:: -d, --daemon

   Launch the certain daemon.

.. note:: Both the master and clients should run the daemon - the master is also a client.

.. cmdoption:: -p, --pidfile

   PID file to use (defaults to B</var/run/certain.pid>)

.. cmdoption:: -m, --makecert

   Create a CSR and send this to the master.

.. cmdoption:: -g, --get

   Receive all available certificates from the store.

.. cmdoption:: -s, --sign

   (On master) Sign pending requests.


Files
=====

``/etc/certain/certain.cfg``


See Also
========

``certain.cfg(5)``