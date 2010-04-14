==================================================
**Certain** --- X509 Certificate Management System
==================================================

.. toctree::
   :hidden:

   certain-cmd.rst
   certain-py.rst
   certain-cfg.rst

Certain is an X509 Certificate management master-client service.  The master generates its own CA certificates, receives certificate signing requests over the network, and then signs these and pushes the signed certificates to a store.

Different store types are provided, from which clients can fetch their own and other client's certificates.

Certain will continue to re-sign certificates for clients as they expire, based on the trust set up from the initial manual certificate signing.

Certain consists of 2 parts:

:doc:`Command-line Tool <certain-cmd>`

:doc:`Python Module <certain-py>`


Installation
============

A deb package is available.

Certain also comes with a ``setuptools`` based **setup.py** which offers various methods including ``install``, ``bdist_rpm``, and ``bdist_deb``.

The default configuration options provided should work 'out-of-the-box', provided that the hostname (CNAME) of the master is set to ``certain``.  By default the ``web`` store plugin will be used.

.. warning:: The Certain deb package creates a ``certain`` user and group which the service runs as (to limit access to the keys and certificates).  If you are installing Certain by hand, it is advised that you configure it in a similar way.

Configuration
=============

For information on the syntax and options available for configuring Certain, please see: :doc:`certain-cfg`

There are 2 aspects to configuring Certain - configuring a **master**, and configuring the **clients**.

Master
------

The master is a server which holds your CA key and certificate, runs a network service to receive certificate signing requests from clients, and then either signs them automatically, or caches them for manual signing.  Signed certificates are pushed to a *store* where they are made publicly available for any client to retrieve them.

In configuring the master, you should pay close attention to the ``[ca]`` section to ensure your CA is properly created, and the ``[store]`` section to choose which store type you wish to use.

Clients
-------

Your clients will generate their own keys and certificate signing requests, and send the CSRs to the master for signing.

In configuring the clients, you should pay close attention to the ``[cert]`` section to ensure you are properly defining the certificate for each client, and to the ``[global]`` configuration section to ensure that the clients are configured to speak to the master properly.


Running Certain
===============


The certain daemon needs to be running on both the master and the clients: to provide certificate services on the master, and to monitor certificate expiry on the clients.  

The certain daemon can be started via the rc.d script:

``/etc/init.d/certain``

or on the command-line: ``certain -d``

Certain will run in the foreground if the LogLevel is set to ``DEBUG``

The client will generate a key and create a CSR at startup and send the CSR to the master (if it has no valid key or certificate).  To manually cause a CSR to be sent, you can use the command:

    ``certain --makecert``

When a client sends a CSR to the master, it will (if it has an existing certificate) sign the CSR with that certificate to identify itself to the master.

The master will check the signature for the client named in the CSR against that client's certificate in the store.  If it matches, a new certificate will be generated automatically.  If there is no stored certificate, it will cache the CSR for manual signing.

To manually sign certificates in the cache, you can use the command:

   ``certain --sign``

Clients can either poll the certificate store to get new signed certificates, or they can get them when instructed to by an event-driven process.  To cause this to occur, you can use the command:

    ``certain --get``



