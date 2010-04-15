Configuration --- ``certain.cfg``
=================================

The configuration file for Certain is based on the format used by the Python **ConfigParser** module - that is it consists of ``[sections]`` which contain ``key = value`` style configuration options.

A configuration file is by default installed to ``/etc/certain/certain.cfg`` - this contains commented-out versions of the default values used by Certain.  To change any values, simply uncomment that line and change its value.

The default values for Certain are contained in the ``certain.cfg.defaults`` file which is distributed with the Certain Python module.  It is recommended **NOT** to change this file!

This configuration file uses the ConfigParser macro style to define a ``RootPath``, then re-use this value in other paths.

.. The following include is an rst file built from the default config file

.. include:: config.rst
