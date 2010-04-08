"""Handle different expiry actions."""


def dispatch(name, certobj):
    """Dispatch a method to handle this type of expiry.

    Pass a certificate object as the only parameter. These methods may
    return anything, but usually None.

    @type name: string
    @param name: NAme of ExpiryHandler Plugin

    @type certobj: M2Crypto.X509.X509
    @param certobj: Certificate to send expiry notification about

    @return: ExpireHandler plugin object

    """

    try:
        expire = __import__(__name__ + '.' + name,
            fromlist=name).expire
    except (ImportError, AttributeError):
        return expiryerror(name)
    return expire(certobj)


def expiryerror(name):
    """Error method - default to deal with unknown Notify types."""

    print "Unknown notification type: " + name
