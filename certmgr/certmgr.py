#!/usr/bin/python

"""Certificate Management System"""

import sys
import socket
import time
import select
import ConfigParser
import threading
import cert
from optparse import OptionParser
import os
from OpenSSL import crypto
import logging
from contextlib import closing, nested
import errno

configfile = "certmgr.cfg"

config = ConfigParser.ConfigParser({'CN': socket.getfqdn()})
if not config.read(configfile):
    raise ConfigParser.Error(
        "Unable to read Configuration File: %s" % (configfile, ))

log = logging.getLogger('certmgr')
log.setLevel(getattr(logging, config.get('global', 'LogLevel')))
logformat = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
logconsole = logging.StreamHandler()
logconsole.setFormatter(logformat)
logconsole.setLevel(getattr(logging, config.get('global', 'LogLevel')))
log.addHandler(logconsole)


class MsgHandlerThread(threading.Thread):

    def __init__(self, msg, src, cakey, capub):
        threading.Thread.__init__(self)
        self.msg = msg
        self.src = socket.gethostbyaddr(src[0])[0]
        self.cakey = cakey
        self.capub = capub

    def run(self):

        csr = crypto.load_certificate_request(
            crypto.FILETYPE_PEM, self.msg)
        CN = csr.get_subject().CN

        if CN != self.src:
            if config.get('manager', 'HostVerify') == "true":
                raise HostVerifyError
            elif config.get('manager', 'HostVerify') == "warn":
                log.warn("Hostname: %s doesn't match certificate CN: %s",
                         self.src, CN)
            else:
                pass

        if config.getboolean('manager', 'AutoSign'):
            log.info("Auto-signing enabled, signing certificate")
            try:
                certobj = cert.sign_csr(self.cakey, self.capub, csr,
                              config.getint('cert', 'CertLifetime'))
            except Exception, e:
                log.error("Signing failed. Will save for later signing.")
                log.error(str(e))
            else:
                with open(cert_file(CN), 'w') as f:
                    log.info("Writing certificate: %s", f.name)
                    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                            certobj))
                return

        #Just save the CSR for later signing
        with open(csr_cache_file(self.src), 'w') as f:
            log.info("Writing CSR to cache: %s", f.name)
            f.write(self.msg)


class HostVerifyError(Exception):
    """Errors in Certificate Hostname Verification"""

    def __init__(self, args="Hostname doesn't match certificate CN value"):
        Exception.__init__(self, args)


def ca_cert_file():
    return "%s/%s" % (config.get('global', 'CAPath'),
                      config.get('global', 'CACert'))


def ca_key_file():
    return "%s/%s" % (config.get('global', 'CAPrivatePath'),
                      config.get('global', 'CAKey'))


def cert_file(name):
    return "%s/%s.crt" % (config.get('global', 'CertPath'), name)


def key_file(name):
    return "%s/%s.key" % (config.get('global', 'PrivatePath'), name)


def csr_file(name):
    return "%s/%s.csr" % (config.get('global', 'CertPath'), name)


def csr_cache_file(name):
    return "%s/%s.csr" % (config.get('global', 'CSRCache'), name)


def creat(filename, flag=os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode=0777):
    """A thin wrapper around os.open and os.fdopen to return a file-like
    object.

    With the default arguments, ask for a file to be created only if it
    doesn't already exist. If it does, expect an OSError exception  "e"
    with e.errno == errno.EEXIST.

    """
    return os.fdopen(os.open(filename, flag, mode), 'w')


def make_certs():
    if config.getboolean('manager', 'IsMaster'):
        #Generate a CA if no certs exist

        log.info("Generating CA certificates for master")
        CN = config.get('ca', 'CN')

        try:
            with nested(creat(ca_key_file(), mode=0666),
                        creat(ca_cert_file(), mode=0666)) as (f_key, f_cert):
                key, cacert = cert.make_ca(CN,
                             config.get('ca', 'OU'),
                             config.get('ca', 'O'),
                             config.get('ca', 'L'),
                             config.get('ca', 'ST'),
                             config.get('ca', 'C'),
                             config.getint('ca', 'CALifetime'))
                f_key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
                f_cert.write(
                    crypto.dump_certificate(crypto.FILETYPE_PEM, cacert))
        except OSError, e:
            if e.errno == errno.EEXIST: # File exists
                log.warn("CA certificates already exist: " + str(e))
            else:
                raise


    #Make client key and CSR if needed
    CN = config.get('cert', 'CN')

    log.info("Making key and CSR for %s", CN)

    try:
        with nested(creat(key_file(CN), mode=0666),
                creat(csr_file(CN), mode=0666)) as (f_key, f_csr):
            key = cert.make_key(config.getint('cert', 'Bits'))
            f_key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

            csr = cert.make_csr(key, CN,
                                config.get('cert', 'OU'),
                                config.get('cert', 'O'),
                                config.get('cert', 'L'),
                                config.get('cert', 'ST'),
                                config.get('cert', 'C'))
            f_csr.write(crypto.dump_certificate_request(
                crypto.FILETYPE_PEM, csr))

    except OSError, e:
        if e.errno == errno.EEXIST: # File exists
            log.warn("Certificates already exist: " + str(e))
        else:
            raise

    if not config.getboolean('manager', 'IsMaster'):
        send_csr()


def check_status():

    if config.getboolean('manager', 'IsMaster'):
        #Check CA certs
        try:
            with open(ca_cert_file()) as capubfile:
                cacertinf = crypto.load_certificate(
                    crypto.FILETYPE_PEM, capubfile.read())
        except IOError, e:
            if e.errno != errno.ENOENT:
                raise
            log.error("Public CA file missing: %s", ca_cert_file())
        else:
            #Get cert time without timezone chars
            notafter = cacertinf.get_notAfter()[0:14]
            #If notafter is less than a week away...
            if (time.mktime(time.strptime(notafter, '%Y%m%d%H%M%S'))
                - time.time()) < 604800:
                log.warn("CA certificate %s expires in less than 7 days!",
                        capubfile)

        try:
            with open(ca_key_file()) as cakeyfile:
                pass
        except IOError, e:
            if e.errno != errno.ENOENT:
                raise
            log.error("Private CA file missing: %s", ca_key_file())


    #Check certs status
    CN = config.get('cert', 'CN')

    try:
        with open(cert_file(CN)) as pubfile:
            certinf = crypto.load_certificate(
                crypto.FILETYPE_PEM, pubfile.read())
    except IOError, e:
        if e.errno != errno.ENOENT:
            raise
        log.error("Public certificate file missing: %s", e)
        sys.exit(2)
    else:
        #Get cert time without timezone chars
        notafter = certinf.get_notAfter()[0:14]
        #If notafter is less than a week away...
        if (time.mktime(time.strptime(notafter, '%Y%m%d%H%M%S'))
            - time.time()) < 604800:
            log.warn("Certificate %s expires in less than 7 days!", pubfile)

    try:
        with open(key_file(CN)) as keyfile:
            pass
    except IOError, e:
        if e.errno != errno.ENOENT:
            raise
        log.error("Private key file missing: %s", e)
        sys.exit(2)


def csr_list():

    csrpath = config.get('global', 'CSRCache')
    cakey = cert.key_from_file(ca_key_file())
    cacert = cert.cert_from_file(ca_cert_file())

    for file in os.listdir(csrpath):
        log.info("Processing file %s:", file)
        with open(os.path.join(csrpath, file)) as f:
            csr = crypto.load_certificate_request(
                crypto.FILETYPE_PEM, f.read())

        if (config.get('manager', 'HostVerify').lower() in ("warn", "true") and
            csr.get_subject().CN != os.path.splitext(file)[0]):
            log.warn("Hostname doesn't match CN")

        dosign = raw_input(
            "Sign CSR %s (CN=%s) [N/y/d(elete)]? " % (
                file, csr.get_subject().CN)).strip().lower()

        if dosign == "y":
            log.info("Signing certificate")

            certobj = cert.sign_csr(cakey, cacert, csr,
                                    config.getint('cert', 'CertLifetime'))

            with open(cert_file(csr.get_subject().CN), 'w') as f:
                log.info("Writing certificate: %s", f.name)
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                certobj))
            log.info("Deleting CSR file: %s", file)
            os.remove(os.path.join(csrpath, file))

        elif dosign == "d":
            log.info("Deleting CSR file: %s", file)
            os.remove(os.path.join(csrpath, file))
        else:
            log.info("Skipping CSR file: %s", file)


def send_csr(file=None):
    "Send csr to host"

    sendfile = file or csr_file(config.get('cert', 'CN'))

    log.info("Sending CSR %s for signing", sendfile)
    with nested(
            open(sendfile),
            closing(socket.socket(type=socket.SOCK_DGRAM))) as (f, s):
        s.sendto(f.read(), (config.get('global', 'ManagerAddress'),
                            config.getint('global', 'ManagerPort')))


def Daemon():

    cakey = capub = None # Won't be used if auto-signing is turned off.
    if config.getboolean('manager', 'AutoSign'):
        try:
            cakey = cert.key_from_file(ca_cert_file())
            cacert = cert.cert_from_file(ca_pub_file())
        except IOError, e:
            if e.errno != errno.ENOENT:
                raise
            log.error("CA certificate Missing.  Create this, or call --makecerts.")
            sys.exit(2)

    #Listen for incoming messages
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(0)
    s.bind(('', config.getint('global', 'ManagerPort')))

    while True:
        read, write, error = select.select([s], [], [])
        if s not in read:
            continue
        msg, src = s.recvfrom(65535)
        thread = MsgHandlerThread(msg, src, cakey, capub)
        thread.start()


def check_paths():

    log.debug("Checking and creating paths")
    for path in ['CertPath', 'PrivatePath', 'CAPath',
                 'CAPrivatePath', 'CSRCache']:
        try:
            os.makedirs(config.get('global', path), 0700)
        except OSError, e:
            if e.errno == errno.EEXIST:
                continue
            log.error("Unable to create path: %s: %s",
                config.get('global', path),
                e)


def main():
    check_paths()

    parser = OptionParser()
    parser.add_option("-m", "--makecerts",
                      action="store_true", dest="makecerts",
                      help="Setup certificates on your system.")
    parser.add_option("-d", "--daemon",
                      action="store_true", dest="daemon",
                      help="Start Certificate Manager Daemon.")
    parser.add_option("-c", "--check",
                      action="store_true", dest="check",
                      help="Check status of own CA and Client Certificates.")
    parser.add_option("-x", "--sign",
                      action="store_true", dest="sign",
                      help="View and sign queued CSRs.")
    parser.add_option("-s", "--send",
                      action="store_true", dest="send",
                      help="Send a CSR file to the Certificate Manager.")
    parser.add_option("-f", "--file",
                      dest="file",
                      help="Specifies the CSR file to be sent with --send.")

    parser.set_defaults(makecerts=False, daemon=False, send=False)
    (options, args) = parser.parse_args()

    if options.makecerts:
        make_certs()

    if options.daemon:
        if config.getboolean('manager', 'IsMaster'):
            Daemon()
        else:
            log.error("IsMaster not set in configuration file!")
            sys.exit(2)

    if options.send:
        send_csr(options.file)

    if options.sign:
        csr_list()

    if options.check:
        check_status()


if __name__ == "__main__":
    main()
