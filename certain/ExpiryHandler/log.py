"""Log expiry messages using the logging object."""

from .. import log


def expire(certobj):
    """Log cert expiry messages.

    @type certobj: M2Crypto.X509.X509
    @param certobj: Certificate object to send expiry notification about

    """

    log.warn("Certificate is about to expire: %s",
             certobj.get_subject().CN)
