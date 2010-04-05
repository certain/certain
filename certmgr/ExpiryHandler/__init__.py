"""Handle different expiry actions."""

def dispatch(name, certobj):
    """Dispatch a method to handle this type of expiry.

    Pass a certificate object as the only parameter. These methods may
    return anything, but usually None.

    """

    try:
        return __import__('certmgr.ExpiryHandler.' + name,
            fromlist=name).expire(certobj)
    except (ImportError, AttributeError):
        return expiryerror(name, certobj)

def expiryerror(name, certobj):
    """Error method - default to deal with unknown Notify types."""

    print "Unknown notification type: " + name
