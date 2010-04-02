from ..certmgr import log

def expire(certobj):
    """Log cert expiry messages."""

    log.warn("Certificate is about to expire: %s",
             certobj.get_subject().CN)
