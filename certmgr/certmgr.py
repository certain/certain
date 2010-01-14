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
import httplib
from urlparse import urlparse
import logging
from contextlib import closing, nested
import errno
import tempfile

configfile = "certmgr.cfg"

config = ConfigParser.ConfigParser({'CN': socket.getfqdn()})
if not config.read(configfile):
    raise ConfigParser.Error(
        "Unable to read Configuration File: %s" % (configfile, ))

log = logging.getLogger('certmgr')
log.setLevel(getattr(logging, config.get('global', 'LogLevel')))
logformat = logging.Formatter('%(levelname)s %(message)s')
logconsole = logging.StreamHandler()
logconsole.setFormatter(logformat)
logconsole.setLevel(getattr(logging, config.get('global', 'LogLevel')))
log.addHandler(logconsole)


class StoreHandler(object):
    """Class to handle different store types"""

    @staticmethod
    def storeerror(certobj):
        """Error method - default for getattr to deal with unknown StoreType"""

        log.error("Unknown StoreType")

    @staticmethod
    def webdav(certobj):
        """Puts certificate on a webdav server"""

        url = urlparse(config.get('manager', 'StoreUrl'))
        certfile = "%s/%s" % (url.path, certobj.get_subject().CN)

        log.debug("Writing cert: %s to server: %s", certfile, url)

        if url.scheme == "https":
            web = httplib.HTTPSConnection(url.netloc)
        else:
            web = httplib.HTTPConnection(url.netloc)

        web.request('PUT', certfile,
                    (crypto.dump_certificate(crypto.FILETYPE_PEM, certobj)))
        resp = web.getresponse()
        if not 200 <= resp.status < 300:
            log.error("Error writing to webdav server: %s", resp.status)
            return


class MsgHandlerThread(threading.Thread):

    def __init__(self, msg, src, cakey, cacert):
        threading.Thread.__init__(self)
        self.msg = msg
        self.src = socket.gethostbyaddr(src[0])[0]
        self.cakey = cakey
        self.cacert = cacert

    def run(self):

        csr = crypto.load_certificate_request(
            crypto.FILETYPE_PEM, self.msg)
        CN = csr.get_subject().CN

        if CN != self.src:
            if config.getboolean('manager', 'HostVerify'):
                log.error("Hostname: %s doesn't match certificate CN: %s",
                         self.src, CN)
                raise HostVerifyError
            else:
                log.warn("Hostname: %s doesn't match certificate CN: %s",
                         self.src, CN)

        if config.getboolean('manager', 'AutoSign'):
            log.info("Auto-signing enabled, signing certificate")
            try:
                certobj = cert.sign_csr(self.cakey, self.cacert, csr,
                              config.getint('cert', 'CertLifetime'))
            except Exception, e:
                log.error("Signing failed. Will save for later signing.")
                log.error(str(e))
            else:
                with open(cert_file(CN), 'w') as f:
                    log.info("Writing certificate: %s", f.name)
                    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                            certobj))

                store_cert(certobj)
                return

        #Just save the CSR for later signing
        with open(csr_cache_file(self.src), 'w') as f:
            log.info("Writing CSR to cache: %s", f.name)
            f.write(self.msg)


class HostVerifyError(Exception):
    """Errors in Certificate Hostname Verification"""

    def __init__(self, args="Hostname doesn't match certificate CN value"):
        Exception.__init__(self, args)


class CACertError(Exception):
    """Error opening CA Certificates"""

    def __init__(self, args="Errors opening CA Certificates"):
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

        #We never want to overwrite a key file,so do nothing if one exists
        try:
            with creat(ca_key_file(), mode=0666) as f_key:
                key = cert.make_key(config.getint('ca', 'Bits'))
                f_key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        except OSError, e:
            if e.errno != errno.EEXIST: # File exists
                raise
            key = cert.key_from_file(ca_key_file())

        with tempfile.NamedTemporaryFile(
            dir=os.path.dirname(ca_cert_file()), delete=False) as f_cacert:
            cacert = cert.make_ca(key, CN,
                                  config.get('ca', 'OU'),
                                  config.get('ca', 'O'),
                                  config.get('ca', 'L'),
                                  config.get('ca', 'ST'),
                                  config.get('ca', 'C'),
                                  config.getint('ca', 'CALifetime'))
            f_cacert.write(
                crypto.dump_certificate(crypto.FILETYPE_PEM, cacert))
            os.rename(f_cacert.name, ca_cert_file())

    #Make client key and CSR if needed
    CN = config.get('cert', 'CN')

    log.info("Making key and CSR for %s", CN)

    #We never want to overwrite a key file,so do nothing if it already exists
    try:
        with creat(key_file(CN), mode=0666) as f_key:
            key = cert.make_key(config.getint('cert', 'Bits'))
            f_key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    except OSError, e:
        if e.errno != errno.EEXIST: # File exists
            raise
        key = cert.key_from_file(key_file(CN))

        csrcache = config.get('global', 'CSRCache')
    with tempfile.NamedTemporaryFile(
        dir=os.path.dirname(csr_file(CN)), delete=False) as f_csr:
        csr = cert.make_csr(key, CN,
                            config.get('cert', 'OU'),
                            config.get('cert', 'O'),
                            config.get('cert', 'L'),
                            config.get('cert', 'ST'),
                            config.get('cert', 'C'))
        f_csr.write(
            crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr))

        os.rename(f_csr.name, csr_file(CN))

    if config.getboolean('client', 'AutoSend'):
        send_csr()


def check_status():

    if config.getboolean('manager', 'IsMaster'):
        #Check CA certs
        try:
            with open(ca_cert_file()) as cacertfile:
                cacertinf = crypto.load_certificate(
                    crypto.FILETYPE_PEM, cacertfile.read())
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
                        cacertfile)

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
        with open(cert_file(CN)) as certfile:
            certinf = crypto.load_certificate(
                crypto.FILETYPE_PEM, certfile.read())
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
            log.warn("Certificate %s expires in less than 7 days!", certfile)

    try:
        with open(key_file(CN)) as keyfile:
            pass
    except IOError, e:
        if e.errno != errno.ENOENT:
            raise
        log.error("Private key file missing: %s", e)
        sys.exit(2)


def csr_sign():

    if not config.getboolean('manager', 'IsMaster'):
        log.error("Not running as a Certificate Master")
        sys.exit(2)

    cakey = cacert = None
    try:
        cakey, cacert = check_cacerts()
    except CACertError:
        log.error("Can't sign CSR without CA Certs")
        sys.exit(2)

    csrpath = config.get('global', 'CSRCache')

    for file in os.listdir(csrpath):
        log.info("Processing file %s:", file)
        with open(os.path.join(csrpath, file)) as f:
            csr = crypto.load_certificate_request(
                crypto.FILETYPE_PEM, f.read())

        if csr.get_subject().CN != os.path.splitext(file)[0]:
            if config.getboolean('manager', 'HostVerify'):
                log.error("Hostname doesn't match CN and HostVerify is set")
                raise HostVerifyError
            else:
                log.warn("Hostname doesn't match CN - continuing anyway")

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

            store = config.get("manager", "StoreType")
            if store.lower() != "none":
                log.info("Storing Signed Cert")
                getattr(StoreHandler, store, StoreHandler.storeerror)(certobj)
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

    cakey = cacert = None # Won't be used if auto-signing is turned off.
    if config.getboolean('manager', 'AutoSign'):
        try:
            cakey, cacert = check_cacerts()
        except CACertError:
            log.error("Can't perform auto-signing without CA Certs")
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
        thread = MsgHandlerThread(msg, src, cakey, cacert)
        thread.start()


def check_cacerts():
    try:
        cakey = cert.key_from_file(ca_key_file())
        cacert = cert.cert_from_file(ca_cert_file())
        return cakey, cacert
    except IOError, e:
        if e.errno != errno.ENOENT:
            raise
        log.error("CA certificate Missing.  Create this, or call --makecerts.")
        raise CACertError


def check_paths():

    log.debug("Checking (and creating) paths")

    for path, mode in [('RootPath', 0777),
                 ('CertPath', 0777),
                 ('CSRCache', 0777),
                 ('PrivatePath', 0700),
                 ('CAPath', 0700),
                 ('CAPrivatePath', 0700)]:
        try:
            os.makedirs(config.get('global', path), mode)
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
                      help="Specifies the CSR file to be sent with --send.  \
                      If unset, defaults to client CSR.")

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
        csr_sign()

    if options.check:
        check_status()


if __name__ == "__main__":
    main()
