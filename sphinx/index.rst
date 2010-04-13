==================================================
**Certain** --- X509 Certificate Management System
==================================================

.. toctree::
   :hidden:

   certain-cmd.rst
   certain-py.rst

Certain is an X509 Certificate management master-client service.  The master generates its own CA certificates, receives certificate signing requests over the network, and then signs these and pushes the signed certificates to a store.

Different store types are provided, from which clients can fetch their own and other client's certificates.

Certain will continue to re-sign certificates for clients as they expire, based on the trust set up from the initial manual certificate signing.

Certain consists of 2 parts:

:doc:`Command-line Tool <certain-cmd>`

:doc:`Python Module <certain-py>`


