"""ExpiryHandler provides a number of plugins which can be called
when a CA certificate is due to expire.

There are currently 2 plugins available: ``log`` and ``email``.

All ExpiryHandler plugins have an ``expire`` method which is called
when the plugin is used.

"""


def dispatch(name, certobj):
    """Dispatch a method to handle this type of expiry.

    Pass a certificate object as the only parameter. These methods may
    return anything, but usually None.

    @type name: string
    @param name: Name of ExpiryHandler plugin

    @type certobj: M2Crypto.X509.X509
    @param certobj: Certificate to send expiry notification about

    @return: ExpiryHandler plugin object

    """

    try:
        expire = __import__(__name__ + '.' + name,
            fromlist=name).expire
    except (ImportError, AttributeError):
        return expiryerror(name, certobj)
    return expire(certobj)


def expiryerror(name, certobj):
    """Error method - default to deal with unknown Notify types."""

    # This cannot be imported at initialisation, as this module is loaded
    # before the log object has been created.
    from .. import log
    log.error(
        'Unknown notification type "%s", expiry of "%s" went unnoticed.' %
        (name, certobj.get_subject().CN))
