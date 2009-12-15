#!/usr/bin/python

#import sys
from OpenSSL import crypto


def make_key(keyfile=None, bits=2048):
    """Create RSA key

    keyfile: If defined, file to write key to
    bits: Default bits for RSA key (defaults to 2048)

    Returns the Pkey object

    """

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, bits)
    if keyfile:
        with open(keyfile, 'w') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    return key


def make_ca(cakeyfile, cacertfile, CN, cacsrfile=None,
            OU="CertMgr Dept", O="CertMgr Org", L="CertMgr City",
            ST="CertMgr State", C="UK", lifetime=60 * 60 * 24 * 365 * 10):

    """Generate a certificate authority

    cakeyfile: File to write Private Part of cert to
    cacertfile: File to write Public part of cert to
    CN: Common Name
    cacsrfile: File to write Certificate Request to
    OU: Organisational Unit (CertMgr Dept)
    O: Organisation (CertMgr Org)
    L: Location (CertMgr City)
    ST: State (CertMgr State)
    C: Country (UK)
    lifetime: Certificate lifetime in seconds (60*60*24*365*10 = 10 years)

    """

    key = make_key(cakeyfile, 4096)
    csr = make_csr(cakeyfile, CN, cacsrfile)

    cacert = crypto.X509()
    cacert.set_issuer(csr.get_subject())
    cacert.set_subject(csr.get_subject())
    cacert.set_pubkey(csr.get_pubkey())

    cacert.set_serial_number(0)
    cacert.gmtime_adj_notBefore(0)
    cacert.gmtime_adj_notAfter(lifetime)
    cacert.sign(key, 'md5')
    if cacertfile:
        with open(cacertfile, 'w') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cacert))

    return cacert


def sign_csr(cakeyfile, cacertfile, csr,
             signedcertfile=None, lifetime=60 * 60 * 24 * 365):

    """Sign certificate request.

    cakeyfile: CA key file
    cacertfile: CA Public Certificate file
    csrfile: Certificate Request file
    signedcertfile: File to write the signed certificate to
    lifetime: Lifetime of signed cert in seconds (60*60*24*365 = 1 year)

    """

    cakey = key_from_file(cakeyfile)
    cacert = cert_from_file(cacertfile)

    cert = crypto.X509()
    try:
        cert.set_pubkey(csr.get_pubkey())
    except AttributeError, e:
        csr = csr_from_file(csrfile)
        cert.set_pubkey(csr.get_pubkey())

    cert.set_subject(csr.get_subject())
    ##FIXME##
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(lifetime)
    cert.set_issuer(cacert.get_subject())
    cert.sign(cakey, 'md5')
    if signedcertfile:
        with open(signedcertfile, 'w') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    return cert


def make_csr(key, CN, csrfile=None,
             OU="CertMgr Dept", O="CertMgr Org",
             L="CertMgr City", ST="CertMgr State", C="UK"):

    """Make a certificate request from an RSA key

    key: PKey object, OR File to retrieve RSA key from
    CN: Common Name
    csrfile: File to write certificate request to
    CN: Common Name (aka CA hostname)
    cacsrfile: File to write Certificate Request to
    OU: Organisational Unit (CertMgr Dept)
    O: Organisation (CertMgr Org)
    L: Location (CertMgr City)
    ST: State (CertMgr State)
    C: Country (UK)

    """

    csr = crypto.X509Req()
    name = csr.get_subject()
    name.C = C
    name.ST = ST
    name.L = L
    name.O = O
    name.OU = OU
    name.CN = CN
    try:
        csr.set_pubkey(key)
    except:
        key = key_from_file(key)
        csr.set_pubkey(key)

    csr.sign(key, 'md5')
    if csrfile:
        with open(csrfile, 'w') as f:
            f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr))

    return csr


def get_cert_info(cert):

    """Return certificate information

    cert: X509 Object, or path to certificate file

    Returns:
    (X509Name object for issuer,
    X509Name object for certificate,
    notBefore date,
    notAfter date,
    serial_number)


    """

    try:
        ca = cert.get_issuer()
    except:
        cert = cert_from_file(cert)
        ca = cert.get_issuer()

    certinf = cert.get_subject()

    return (ca, certinf,
            cert.get_notBefore(),
            cert.get_notAfter(),
            cert.get_serial_number())


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
