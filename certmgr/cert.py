#!/usr/bin/python

#import sys
from OpenSSL import crypto


def make_key(bits=2048):
    """Create RSA key

    bits: Default bits for RSA key (defaults to 2048)

    Returns the Pkey object

    """

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, bits)

    return key


def make_csr(key, CN,
             OU="CertMgr Dept", O="CertMgr Org",
             L="CertMgr City", ST="CertMgr State", C="UK"):

    """Make a certificate request from an RSA key

    key: String containing key
    CN: Common Name
    CN: Common Name (aka CA hostname)
    cacsrfile: File to write Certificate Request to
    OU: Organisational Unit (CertMgr Dept)
    O: Organisation (CertMgr Org)
    L: Location (CertMgr City)
    ST: State (CertMgr State)
    C: Country (UK)

    Returns an X509 object
    """

    csr = crypto.X509Req()
    name = csr.get_subject()
    name.C = C
    name.ST = ST
    name.L = L
    name.O = O
    name.OU = OU
    name.CN = CN

    csr.set_pubkey(key)
    csr.sign(key, 'md5')

    return csr


def sign_csr(cakeyfile, cacertfile, csr, lifetime=60 * 60 * 24 * 365):

    """Sign certificate request.

    cakeyfile: CA key file
    cacertfile: CA Public Certificate file
    csr: Certificate Request string
    lifetime: Lifetime of signed cert in seconds (60*60*24*365 = 1 year)

    Returns X509 object
    """

    cakey = key_from_file(cakeyfile)
    cacert = cert_from_file(cacertfile)

    cert = crypto.X509()
    cert.set_pubkey(csr.get_pubkey())
    cert.set_subject(csr.get_subject())
    ##FIXME## Serial numbers should increment!
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(lifetime)
    cert.set_issuer(cacert.get_subject())
    cert.sign(cakey, 'md5')

    return cert


def make_ca(CN, OU="CertMgr Dept", O="CertMgr Org", L="CertMgr City",
            ST="CertMgr State", C="UK", lifetime=60 * 60 * 24 * 365 * 10):

    """Generate a certificate authority

    CN: Common Name
    OU: Organisational Unit (CertMgr Dept)
    O: Organisation (CertMgr Org)
    L: Location (CertMgr City)
    ST: State (CertMgr State)
    C: Country (UK)
    lifetime: Certificate lifetime in seconds (60*60*24*365*10 = 10 years)

    """

    key = make_key(4096)
    csr = make_csr(key, CN)

    cacert = crypto.X509()
    cacert.set_issuer(csr.get_subject())
    cacert.set_subject(csr.get_subject())
    cacert.set_pubkey(csr.get_pubkey())

    cacert.set_serial_number(0)
    cacert.gmtime_adj_notBefore(0)
    cacert.gmtime_adj_notAfter(lifetime)
    cacert.sign(key, 'md5')

    return (key, cacert)


def get_cert_info(cert):

    """Return certificate information

    cert: String containing certificate

    Returns:
    (X509Name object for issuer,
    X509Name object for certificate,
    notBefore date,
    notAfter date,
    serial_number)


    """

    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    except crypto.Error:
        raise

    ca = cert.get_issuer()
    certinf = cert.get_subject()

    return (ca, certinf,
            cert.get_notBefore(),
            cert.get_notAfter(),
            cert.get_serial_number())


def get_csr_info(csr):

    """Return certificate information

    csr: String containing certificate

    Returns:
    (X509Name object for issuer,
    X509Name object for certificate,
    notBefore date,
    notAfter date,
    serial_number)


    """

    return (csr.get_subject())


def key_from_file(keyfile):
    """Read a private key from file"""

    with open(keyfile, 'r') as f:
        return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())


def csr_from_file(csrfile):
    """ Read a CSR from file"""

    with open(csrfile, 'r') as f:
        return crypto.load_certificate_request(crypto.FILETYPE_PEM, f.read())


def cert_from_file(certfile):
    """Read a certificate from file"""

    with open(certfile, 'r') as f:
        return crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
