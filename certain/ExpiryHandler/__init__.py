"""Handle different expiry actions."""


def dispatch(name, certobj):
    """Dispatch a method to handle this type of expiry.

    Pass a certificate object as the only parameter. These methods may
    return anything, but usually None.

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
    # before the log (LazyConfig) object has been created.
    from .. import log
    log.error('Unknown notification type "%s", expiry of "%s" went unnoticed.' %
        (name, certobj.get_subject().CN))
