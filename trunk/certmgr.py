#!/usr/bin/python

"""Certificate Management System"""

import sys
import socket
import time
import select
import ConfigParser
import threading
import cert
import os
from OpenSSL import crypto
import httplib
from urlparse import urlparse
import logging
from contextlib import closing, nested
import errno
import tempfile
import pysvn
import abc


class LazyConfig(object):
    """Class which calls parse_config the first time it is referenced.

    Allows user to override the default configfile value before it is used

    """

    def __getattr__(self, s):
        parse_config()
        return getattr(config, s)


class StoreBase(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def setup(self):
        """Setup this specific store object."""
        return

    @abc.abstractmethod
    def fetch(self):
        """Retrieve certificates from the store."""
        return

    @abc.abstractmethod
    def write(self, certobj):
        """Write certificate to the central store."""
        return

    @abc.abstractmethod
    def finalise(self):
        """Finalise any pending actions on the store."""
        return


class StoreHandler(object):
    """Class to handle different store types"""

    @staticmethod
    def storeerror(certobj):
        """Error method - default for getattr to deal with unknown StoreType"""

        log.warn("Unknown StoreType")

    class none(StoreBase):

        def setup(self):
            pass

        def finalise(self):
            pass

        def fetch(self):
            pass

        def write(self, certobj):
            pass

    class webdav(StoreBase):

        def setup(self):
            pass

        def finalise(self):
            pass

        def fetch(self):
            pass

        def write(self, certobj):
            """Puts certificate on a webdav server"""

            url = urlparse(config.get('global', 'StoreUrl'))
            certfile = "%s/%s.pem" % (url.path, certobj.get_subject().CN)

            log.debug("Writing cert: %s to server: %s", certfile, url)

            if url.scheme == "https":
                web = httplib.HTTPSConnection(url.netloc)
            else:
                web = httplib.HTTPConnection(url.netloc)

            web.request('PUT', certfile,
                        (crypto.dump_certificate(
                            crypto.FILETYPE_PEM, certobj)))
            resp = web.getresponse()
            if not 200 <= resp.status < 300:
                log.error("Error writing to webdav server: %s", resp.status)
                return

    class svn(StoreBase):

        def __init__(self):
            self.client = pysvn.Client()
            self.lock = threading.Lock()

        def setup(self):
            log.debug("Setting up svn repository (co/update)")
            self.storedir = config.get('global', 'StoreDir')
            if not os.path.exists(self.storedir):
                with self.lock:
                    self.client.checkout(config.get('global', 'StoreUrl'),
                                    self.storedir)
            else:
                with self.lock:
                    self.client.update(self.storedir)

        def finalise(self):
            log.debug("Doing checkin of store")
            with self.lock:
                self.client.checkin(self.storedir, "Adding certificates")

        def fetch(self):
            with self.lock:
                self.client.update(self.storedir)

        def write(self, certobj):
            certfile = "%s/%s.pem" % (self.storedir, certobj.get_subject().CN)
            log.debug("Storing cert: %s", certfile)

            with nested(self.lock,
                        open(certfile, 'w')) as (locked, f_crt):
                self.client.update(self.storedir)
                f_crt.write(
                    crypto.dump_certificate(crypto.FILETYPE_PEM, certobj))

            try:
                with self.lock:
                    self.client.add(certfile)
            except Exception:
                #If add fails, its because its already under VC
                pass


class MsgHandlerThread(threading.Thread):

    def __init__(self, store, msg, src, cakey, cacert):
        threading.Thread.__init__(self)
        self.store = store
        self.msg = msg
        self.src = socket.gethostbyaddr(src[0])[0]
        self.cakey = cakey
        self.cacert = cacert

    def run(self):

        csr = crypto.load_certificate_request(
            crypto.FILETYPE_PEM, self.msg)
        CN = csr.get_subject().CN

        if CN != self.src:
            if config.getboolean('global', 'HostVerify'):
                log.error("Hostname: %s doesn't match certificate CN: %s",
                         self.src, CN)
                raise HostVerifyError
            else:
                log.warn("Hostname: %s doesn't match certificate CN: %s",
                         self.src, CN)

        if config.getboolean('global', 'AutoSign'):
            log.info("Auto-signing enabled, signing certificate")
            try:
                certobj = cert.sign_csr(self.cakey, self.cacert, csr,
                              config.getint('cert', 'CertLifetime'))
            except Exception, e:
                log.warn("Signing failed. Will save for later signing.")
                log.warn(str(e))

            with tempfile.NamedTemporaryFile(
                dir=os.path.dirname(cert_file(CN)), delete=False) as f_crt:
                log.info("Writing certificate: %s", cert_file(CN))
                f_crt.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                            certobj))

                os.rename(f_crt.name, cert_file(CN))

                log.info("Storing Signed Cert")
                self.store.write(certobj)

        else:
            #Just save the CSR for later signing
            with tempfile.NamedTemporaryFile(
                dir=os.path.dirname(csr_cache_file(self.src)),
                delete=False) as f_csr:
                log.info("Writing CSR to cache: %s", csr_cache_file(self.src))
                f_csr.write(self.msg)

                os.rename(f_csr.name, csr_cache_file(self.src))

        self.store.finalise()


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


def parse_config(configfile="/etc/certmgr/certmgr.cfg"):
    global config
    config = ConfigParser.ConfigParser({'CN': socket.getfqdn()})
    if not config.read(configfile):
        raise ConfigParser.Error(
            "Unable to read Configuration File: %s" % (configfile, ))
    log.setLevel(getattr(logging, config.get('global', 'LogLevel')))
    logconsole.setLevel(getattr(logging, config.get('global', 'LogLevel')))


def make_certs(caoverwrite=False):
    if config.getboolean('global', 'IsMaster'):
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

        if caoverwrite:
            #We want to overwrite the CA
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
        else:
            #Only create if it doesn't already exist
            try:
                with creat(ca_cert_file(), mode=0666) as f_cacert:
                    cacert = cert.make_ca(key, CN,
                                          config.get('ca', 'OU'),
                                          config.get('ca', 'O'),
                                          config.get('ca', 'L'),
                                          config.get('ca', 'ST'),
                                          config.get('ca', 'C'),
                                          config.getint('ca', 'CALifetime'))
                    f_cacert.write(
                        crypto.dump_certificate(crypto.FILETYPE_PEM, cacert))
            except OSError, e:
                if e.errno != errno.EEXIST: # File exists
                    raise

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


def check_expiry(certobj):
    """Return expiry time in seconds

    certobj: OpenSSL X509 Object

    """

    return int(time.mktime(time.strptime(
        certobj.get_notAfter()[0:14],
        '%Y%m%d%H%M%S')) - time.time())


def check_status():
    if config.getboolean('global', 'IsMaster'):
        #Check CA certs
        try:
            with open(ca_cert_file()) as cacertfile:
                cacert = crypto.load_certificate(
                    crypto.FILETYPE_PEM, cacertfile.read())
        except IOError, e:
            if e.errno != errno.ENOENT:
                raise
            log.error("Public CA file missing: %s", ca_cert_file())
            sys.exit(2)
        else:
            if check_expiry(cacert) < config.get('ca', 'ExpiryDeadline'):
                log.warn("CA certificate %s expires in less than 7 days!",
                        cacertfile)

        try:
            with open(ca_key_file()) as cakeyfile:
                pass
        except IOError, e:
            if e.errno != errno.ENOENT:
                raise
            log.error("Private CA file missing: %s", ca_key_file())
            sys.exit(2)


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
    if not config.getboolean('global', 'IsMaster'):
        log.error("Not running as a Certificate Master")
        sys.exit(2)

    cakey = cacert = None
    try:
        cakey, cacert = check_cacerts()
    except CACertError:
        log.error("Can't sign CSR without CA Certs")
        sys.exit(2)

    csrpath = config.get('global', 'CSRCache')

    store = getattr(StoreHandler, config.get('global', 'StoreType'),
                    StoreHandler.storeerror)()
    store.setup()

    for file in os.listdir(csrpath):
        log.info("Processing file %s:", file)
        with open(os.path.join(csrpath, file)) as f:
            csr = crypto.load_certificate_request(
                crypto.FILETYPE_PEM, f.read())

        if csr.get_subject().CN != os.path.splitext(file)[0]:
            if config.getboolean('global', 'HostVerify'):
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

            with tempfile.NamedTemporaryFile(
                dir=os.path.dirname(cert_file(csr.get_subject().CN)),
                delete=False) as f_crt:
                log.info("Writing certificate: %s",
                         cert_file(csr.get_subject().CN))
                f_crt.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                certobj))

            os.rename(f_crt.name, cert_file(csr.get_subject().CN))

            log.info("Deleting CSR file: %s", file)
            os.remove(os.path.join(csrpath, file))

            log.info("Storing Signed Cert")
            store.write(certobj)

        elif dosign == "d":
            log.info("Deleting CSR file: %s", file)
            os.remove(os.path.join(csrpath, file))
        else:
            log.info("Skipping CSR file: %s", file)

        store.finalise()


def send_csr(file=None):
    "Send csr to host"

    sendfile = file or csr_file(config.get('cert', 'CN'))

    log.info("Sending CSR %s for signing", sendfile)
    with nested(
            open(sendfile),
            closing(socket.socket(type=socket.SOCK_DGRAM))) as (f, s):
        s.sendto(f.read(), (config.get('global', 'MasterAddress'),
                            config.getint('global', 'MasterPort')))


class CertExpiry(object):

    def __init__(self, cakey, cacert, store):
        self.cacert = cacert
        self.cakey = cakey
        self.store = store

    def expiry_timer(self):
        try:
            crt = cert.cert_from_file(cert_file(config.get('cert', 'CN')))
        except IOError, e:
            if e.errno != errno.ENOENT:
                raise
            log.warn("Certificate missing. Call --makecerts.")
        else:
            log.debug("Cert expiry timer waiting for %s seconds",
                      check_expiry(crt) - config.getint(
                          'cert', 'ExpiryDeadline'))
            self.tcrt = threading.Timer(
                check_expiry(crt) - config.getint('cert', 'ExpiryDeadline'),
                self.expiry_action, [crt])
            self.tcrt.daemon = True
            self.tcrt.start()

        if self.cacert is not None:
            log.debug("CA expiry timer waiting for %s seconds",
                      check_expiry(self.cacert) - config.getint(
                          'ca', 'ExpiryDeadline'))
            self.tca = threading.Timer(
                check_expiry(self.cacert) - config.getint(
                    'ca', 'ExpiryDeadline'),
                self.expiry_action, [self.cacert], {'caoverwrite': 'True'})
            self.tca.daemon = True
            self.tca.start()

    def expiry_action(self, cert, caoverwrite=False):
        """Launched when expired cert timer completes"""

        #Need to allow overwriting of CA
        #Re-sending of CSR will happen for free
        make_certs(caoverwrite)

        #Update the local cert store
        self.store.fetch()

        self.expiry_timer()


def launch_daemon():
    cakey = cacert = None # Won't be used if auto-signing is turned off.
    if config.getboolean('global', 'AutoSign'):
        try:
            cakey, cacert = check_cacerts()
        except CACertError:
            log.error("Can't perform auto-signing without CA Certs")
            sys.exit(2)

    store = getattr(StoreHandler, config.get('global', 'StoreType'),
                    StoreHandler.storeerror)()
    store.setup()

    certexpiry = CertExpiry(cakey, cacert, store)
    certexpiry.expiry_timer()

    #Listen for incoming messages
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(0)
    s.bind((config.get('global', 'MasterAddress'),
            config.getint('global', 'MasterPort')))

    while True:
        read, write, error = select.select([s], [], [])
        if s not in read:
            continue
        msg, src = s.recvfrom(65535)
        thread = MsgHandlerThread(store, msg, src, cakey, cacert)
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


log = logging.getLogger('certmgr')
log.setLevel(logging.CRITICAL)
logformat = logging.Formatter('%(levelname)s %(message)s')
logconsole = logging.StreamHandler()
logconsole.setFormatter(logformat)
logconsole.setLevel(logging.CRITICAL)
log.addHandler(logconsole)

#Calling config.* methods will call parse_config, reading the default
#config file if the importing app hasn't previously
#done certmgr.parse_config(configfile="...")
config = LazyConfig()
