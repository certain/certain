:mod:`certain` --- Python Module
***********************************

Classes
=======

StoreHandler
------------

StoreHandler provides a 'template' of methods for various store plugins, all of which offer the same methods to Certain.  The store plugin being used is configured via the ``StoreType`` configuration option.

There are currently 2 plugins available: ``git`` and ``web``.

.. autoclass:: certain.StoreHandler.StoreBase
   :members:


ExpiryHandler
-------------

.. automodule:: certain.ExpiryHandler

StoreServer
-----------

.. automodule:: certain.StoreServer

Methods
=======

.. automodule:: certain 


Certificate Creation Methods
----------------------------

These functions relate to the creation of key and certificate objects.

.. autofunction:: make_ca

.. autofunction:: make_cacert

.. autofunction:: make_cert

.. autofunction:: make_csr

.. autofunction:: make_key



Certificate Handling Methods
----------------------------

These functions relate to the processing of certificates and CSRs, including signing and distribution.


.. autofunction:: check_expiry

.. autofunction:: pending_csrs

.. autofunction:: send_csr

.. autofunction:: sign_csr



File Methods
------------

These functions relate to reading and writing certificate objects to and from the filesystem.

.. autofunction:: key_from_file

.. autofunction:: cert_from_file

.. autofunction:: ca_cert_file

.. autofunction:: ca_key_file

.. autofunction:: ca_csr_file

.. autofunction:: cert_file

.. autofunction:: key_file

.. autofunction:: csr_file

.. autofunction:: csr_cache_file

.. autofunction:: check_cacerts

.. autofunction:: check_paths



General Methods
---------------

These methods relate to the general running of the certmgr service.

.. autofunction:: launch_daemon

.. autofunction:: parse_config

.. autofunction:: pidfile


